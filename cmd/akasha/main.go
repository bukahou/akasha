// akasha — 第一方身份联邦中枢 (OIDC IdP)。
//
// 本文件是**装配蓝图**: 只负责"把零件按依赖顺序拼起来", 不含任何业务逻辑。
// 想知道某个行为在哪实现, 看下面的路由表定位到 feature 包即可。
//
// # 启动顺序 (每步 fail-fast, 起不来就退出 — 半残状态的 IdP 比不可用更危险)
//
//	① 日志: JSON handler (对齐集群日志采集; msg 中文给人读, key 英文给机器解析)
//	② 配置: 全量 env → Config struct (缺关键项在这一步就炸)
//	③ 存储: GORM/MySQL 连接池
//	④ 密钥: 加载 RSA 私钥并把公钥登记进 signing_keys (JWKS 数据源)
//	⑤ 装配: 各 feature 组件按依赖方向 new 出来
//	⑥ 路由: 各 feature 自治 Register(mux)
//	⑦ 运行: 阻塞直到信号, 10s 优雅关停
//
// # 无状态设计 (2026-08-16 定案)
//
// akasha 【不保留任何登录态】—— 没有 sessions 表, 没有登录 cookie, 没有登出。
// 每一次 /authorize 都意味着重新走一遍上游认证。
//
// 放弃的是 SSO (从 geass 登录后进 atlhyper 不会免登录); 换来的是: 应用之间
// 彻底无关联 (与 pairwise sub 的隔离立场一致)、用户随时能换上游账号 (中枢会话
// 会把人静默钉死在第一次登录的账号上)、以及一个真正无状态的服务。
// 体验损失有限 —— 上游自己有会话, 重走一遍通常只是几百毫秒的静默重定向。
//
// # 依赖方向 (架构红线, 不允许反向)
//
//	op         → keys / client / account   (协议层调所有下层)
//	federation → account                   (上游 broker)
//	login      → 无                        (纯渲染器; op 的判据经注入送达)
//	account    → 无                        (身份权威在最底层, 不知道任何人)
//
// op 与 federation 是同一套 OIDC 概念的镜像两侧: op 发 code 给下游 (akasha 当
// Provider), federation 拿 code 找上游换 (akasha 当 Relying Party), 中间同为
// account 裁决身份。两者的衔接靠 main 注入 op.CompleteAuthorize, 而非直接依赖。
//
// # 一次登录的完整路径
//
//	下游 → /authorize (校验后停车, 原请求塞进 next)
//	     → /login?next=... (选上游)
//	     → /federation/{p}/start (state/nonce/next 进签名 cookie; prompt 透传) → 上游
//	     → /federation/{p}/callback (验 state → 换身份 → 裁决账号)
//	     → op.CompleteAuthorize (就地签 code, 不回跳 /authorize —— 无会话下会死循环)
//	     → 302 回下游 redirect_uri?code=...
//
// # 路由表 (这个进程对外的全部表面)
//
//	op 包 (协议, 机器读):
//	  GET  /.well-known/openid-configuration  发现文档 (RP 自动配置的入口)
//	  GET  /jwks                              公钥集 (下游验签的数据源)
//	  GET  /authorize                         前信道: 校验后一律送去登录页
//	  POST /token                             后信道: code/refresh → 三 token
//	  GET  /userinfo                          Bearer 换用户资料 (实时状态)
//	  GET  /end_session                       RP 发起登出 (无状态可清, 只管送回)
//	server 包 (探针, K8s 读):
//	  GET  /healthz                           存活: 不查任何依赖 (查了会导致误重启)
//	  GET  /readyz                            就绪: DB 可达 + 密钥已加载
//	  GET  /health                            /healthz 的别名 (旧配置兼容)
//	login 包 (柜台, 人读):
//	  GET  /       说明页 (这是中枢, 请从应用发起登录)
//	  GET  /login  上游登录入口 (无密码表单, 无注册, 无登出)
//	federation 包 (上游往返):
//	  GET  /federation/{provider}/start     生成 state/nonce → 跳去上游
//	  GET  /federation/{provider}/callback  验 state → 换身份 → 交给 op 签 code
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/bukahou/akasha/internal/account"
	"github.com/bukahou/akasha/internal/client"
	"github.com/bukahou/akasha/internal/config"
	"github.com/bukahou/akasha/internal/federation"
	"github.com/bukahou/akasha/internal/keys"
	"github.com/bukahou/akasha/internal/login"
	"github.com/bukahou/akasha/internal/op"
	"github.com/bukahou/akasha/internal/server"
	"github.com/bukahou/akasha/internal/storage"
)

func main() {
	// ① 结构化日志
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// ② 配置
	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("加载配置失败", "err", err)
		os.Exit(1)
	}

	// ③ 存储 — 七张表的唯一连接池, 后面所有 repository 共用这一个 *gorm.DB
	//    连接参数与日志策略见 storage 包 (装配蓝图不管那些细节)
	db, err := storage.OpenMySQL(cfg.DBDSN)
	if err != nil {
		slog.Error("连接数据库失败", "err", err)
		os.Exit(1)
	}

	// ④ 签名密钥 — 整个信任链的锚点: 下游凭什么信 akasha 签的 token, 就凭这把私钥。
	//    构造时顺带把公钥 upsert 进 signing_keys, 所以必须在 op 之前 (JWKS 要读这张表)。
	//    私钥只活在内存与挂载文件里, 永不入库、不打日志 — 只打 kid 指纹便于排查验签问题。
	km, err := keys.NewManager(cfg.SigningKeyPath, db)
	if err != nil {
		slog.Error("初始化签名密钥失败", "err", err)
		os.Exit(1)
	}
	slog.Info("签名密钥就绪", "kid", km.Kid())

	// ⑤ 装配 — 从最底层往上, 顺序即依赖方向

	// account: 身份权威。repo 给 op 直连 (签 token 时取用户 claims),
	// svc 给 federation 用 (上游身份裁决 + 建号) — 两个消费者要的粒度不同, 故都暴露。
	accountRepo := account.NewRepository(db)
	accountSvc := account.NewService(accountRepo)

	// client: RP 注册表。谁能来要身份、能回跳到哪, 由它说了算 (开放重定向的唯一防线)。
	clientReg := client.NewRegistry(db)

	// op: 协议核心。issuer 是写进每张 JWT 的 iss (协议层身份, 定了不改);
	// 四个 TTL 决定 code 与三种 token 的生命周期 (无会话, 故无会话 TTL)。
	opSvc := op.NewService(op.NewRepository(db), km, accountRepo, cfg.Issuer, cfg.PairwiseSalt, op.TTLConfig{
		IDToken:     cfg.IDTokenTTL,
		AccessToken: cfg.AccessTokenTTL,
		Refresh:     cfg.RefreshTTL,
		AuthCode:    cfg.AuthCodeTTL,
	})

	// federation: 上游 broker (akasha 当 RP 的那一侧, 与 op 镜像)。
	// 构造 Google provider 时会拉取其 discovery 文档 — 网络请求失败即退出:
	// 无密码定案后联邦是唯一认证入口, "能启动但登不进去"比起不来更糟。
	googleProvider, err := federation.NewGoogleProvider(context.Background(),
		cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.Issuer+"/federation/google/callback")
	if err != nil {
		slog.Error("初始化 Google 上游失败", "err", err)
		os.Exit(1)
	}
	providerRegistry := federation.NewRegistry(googleProvider)
	// 联邦往返状态用签名 cookie 保管, 密钥由 pairwise salt 派生 (不新增配置项)
	stateKeeper, err := federation.NewStateKeeper(cfg.PairwiseSalt, cfg.FederationTTL, cfg.CookieSecure)
	if err != nil {
		slog.Error("初始化联邦状态保管失败", "err", err)
		os.Exit(1)
	}

	// handler 层: 只做 HTTP 编解码 + 调 service, 不含业务判断
	opHandler := op.NewHandler(opSvc, clientReg, km, cfg.Issuer)
	// login 的构造会解析 embed 模板 — 模板语法错误在启动时暴露, 而不是等用户点登录才 500。
	// safeNext 与 federation 那边注入的是同一个函数: 判据属于 op, 但两个消费者
	// 都不该为一个谓词去 import 整个协议核心。
	loginHandler, err := login.NewHandler(providerRegistry.Names(), op.SafeLocalNext)
	if err != nil {
		slog.Error("初始化登录页失败", "err", err)
		os.Exit(1)
	}
	// op 的四项能力经 bridge 注入, 让 federation 不必依赖 op
	// (login 包为复用其中一个函数直接 import 了 op, 造成计划外的依赖方向; 这里避开)
	fedHandler := federation.NewHandler(providerRegistry, accountSvc, stateKeeper, federation.OPBridge{
		Complete: opHandler.CompleteAuthorize,
		Deny:     opHandler.DenyAuthorize,
		SafeNext: op.SafeLocalNext,
		Prompt:   op.PromptFromNext,
	})

	// 健康探针: liveness 不查任何依赖 (DB 挂掉时正确的反应是摘出负载均衡,
	// 而不是把所有 Pod 重启一遍); readiness 才查 DB 与密钥。
	// 检查项以函数注入, server 包因此不认识数据库也不认识密钥。
	healthHandler := server.NewHealth(
		server.Check{Name: "database", Probe: func(ctx context.Context) error {
			return storage.PingContext(ctx, db)
		}},
		server.Check{Name: "signing-key", Probe: func(context.Context) error {
			if km.Kid() == "" {
				return errors.New("签名密钥未加载")
			}
			return nil
		}},
	)

	// ⑥ 路由 — 各 feature 自治注册自己的端点 (加端点只改对应包, main 不动)
	mux := http.NewServeMux()
	opHandler.Register(mux)
	loginHandler.Register(mux)
	fedHandler.Register(mux)
	healthHandler.Register(mux)

	// 全局 middleware: 安全头 (点击劫持/嗅探/Referer 泄漏防护) + CORS + 请求体上限。
	// 包在最外层 —— 每一条响应都该带上, 包括 404 与各类错误页。
	// CORS 只对不依赖 cookie 的端点放行 (见 server.corsAllowedPaths)。
	handler := server.SecurityHeaders(cfg.Issuer, server.CORS(server.LimitBody(mux)))

	// ⑦ 运行 — 阻塞直到 SIGINT/SIGTERM, 然后 10s 窗口优雅关停 (让在途的 token 兑换跑完)
	if err := server.Run(cfg.Addr, handler); err != nil {
		slog.Error("服务退出", "err", err)
		os.Exit(1)
	}
}
