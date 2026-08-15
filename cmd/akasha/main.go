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
// # 依赖方向 (架构红线, 不允许反向)
//
//	op    → keys / client / session / account   (协议层调所有下层)
//	login → session / account                   (柜台页只碰会话与用户)
//	account → 无                                (身份权威在最底层, 不知道任何人)
//
// # 路由表 (这个进程对外的全部表面)
//
//	op 包 (协议, 机器读):
//	  GET  /.well-known/openid-configuration  发现文档 (RP 自动配置的入口)
//	  GET  /jwks                              公钥集 (下游验签的数据源)
//	  GET  /authorize                         前信道: 有会话发 code, 无会话去登录页
//	  POST /token                             后信道: code/refresh → 三 token
//	  GET  /health                            存活探针
//	login 包 (柜台, 人读):
//	  GET  /login    展示登录页
//	  POST /login    验密码 → 建中枢会话 (SSO cookie) → 回跳 authorize
//	  POST /logout   吊销会话
package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/bukahou/akasha/internal/account"
	"github.com/bukahou/akasha/internal/client"
	"github.com/bukahou/akasha/internal/config"
	"github.com/bukahou/akasha/internal/keys"
	"github.com/bukahou/akasha/internal/login"
	"github.com/bukahou/akasha/internal/op"
	"github.com/bukahou/akasha/internal/server"
	"github.com/bukahou/akasha/internal/session"
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
	// svc 给 login 用 (密码校验/认亲建号) — 两个消费者要的粒度不同, 故都暴露。
	accountRepo := account.NewRepository(db)
	accountSvc := account.NewService(accountRepo)

	// client: RP 注册表。谁能来要身份、能回跳到哪, 由它说了算 (开放重定向的唯一防线)。
	clientReg := client.NewRegistry(db)

	// session: 中枢会话 = SSO 的物理载体。cookie 种在 akasha 域下,
	// 之后任何应用跳来 /authorize 都能命中 → 免登录。
	sessionStore := session.NewStore(db, cfg.SessionTTL, cfg.CookieSecure)

	// op: 协议核心。issuer 是写进每张 JWT 的 iss (协议层身份, 定了不改);
	// 四个 TTL 决定 code/token/会话的生命周期。
	opSvc := op.NewService(op.NewRepository(db), km, accountRepo, cfg.Issuer, cfg.PairwiseSalt, op.TTLConfig{
		IDToken:     cfg.IDTokenTTL,
		AccessToken: cfg.AccessTokenTTL,
		Refresh:     cfg.RefreshTTL,
		AuthCode:    cfg.AuthCodeTTL,
	})

	// handler 层: 只做 HTTP 编解码 + 调 service, 不含业务判断
	opHandler := op.NewHandler(opSvc, clientReg, sessionStore, km, cfg.Issuer)
	// login 的构造会解析 embed 模板 — 模板语法错误在启动时暴露, 而不是等用户点登录才 500
	loginHandler, err := login.NewHandler(accountSvc, sessionStore)
	if err != nil {
		slog.Error("初始化登录页失败", "err", err)
		os.Exit(1)
	}

	// ⑥ 路由 — 各 feature 自治注册自己的端点 (加端点只改对应包, main 不动)
	mux := http.NewServeMux()
	opHandler.Register(mux)
	loginHandler.Register(mux)

	// ⑦ 运行 — 阻塞直到 SIGINT/SIGTERM, 然后 10s 窗口优雅关停 (让在途的 token 兑换跑完)
	if err := server.Run(cfg.Addr, mux); err != nil {
		slog.Error("服务退出", "err", err)
		os.Exit(1)
	}
}
