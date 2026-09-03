package oidcrp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// OnAuthenticated 身份验证成功后, 由调用方决定接下来怎么办。
//
// 这是本包与应用之间【唯一】的接缝: 上游身份是通用的, "这个身份对应我系统里
// 的谁、要不要建号、发什么 token"则完全是应用自己的事。
//
// 签名与 http.Handler 同形 (w, r) 是有意的: 调用方几乎一定需要请求里的东西 ——
// 种 cookie 要 w, 取 X-Forwarded-For / User-Agent 要 r, ctx 也从 r 里拿。
//
// 返回的 redirectTo 是最终要把浏览器送去的地方 —— 调用方【不要】自己调
// http.Redirect, 由本包统一处理, 免得出现"跳了两次"。
//
// 返回 error 时本包会渲染失败页, 且【不会】泄漏 error 的内容给用户。
type OnAuthenticated func(w http.ResponseWriter, r *http.Request, res Result) (redirectTo string, err error)

// OnError 登录失败时的展示方式。可选 —— 不设则回一个极简的纯文本页。
//
// reason 是稳定的原因码 (见 Reason* 常量), 不是给人看的文案 ——
// 直接把它显示给用户等于让攻击者能构造 /callback?...&error=<任意文案>
// 借可信域名伪造提示。文案由调用方按白名单映射。
// next 是本次流程的回跳目标 (已过 SafeNext 校验); 上下文丢失时为空串。
//
// 带上它, 调用方才能把【失败】也送回原生客户端。否则原生登录一旦失败,
// 系统认证会话会停在一个网页上等用户手动关 —— App 侧收不到任何回调。
type OnError func(w http.ResponseWriter, r *http.Request, reason, next string)

// 失败原因码。
const (
	// ReasonCancelled 用户在 provider 那边点了取消 / 拒绝授权。
	ReasonCancelled = "cancelled"
	// ReasonState state 校验失败: cookie 缺失、签名不符、超时。
	// 上下文已经丢了 —— 连"用户原本要去哪"都不知道。
	ReasonState = "state"
	// ReasonUpstream 与 provider 通信失败, 或它返回的东西不合法。可重试。
	ReasonUpstream = "upstream"
	// ReasonApplication 调用方的 OnAuthenticated 返回了错误。
	ReasonApplication = "application"
)

// Config 构造 Flow 所需的全部配置。
type Config struct {
	// IssuerURL provider 的 issuer, 例如 https://akasha.bukahou.com。
	// 构造时会去拉它的 /.well-known/openid-configuration。
	IssuerURL string
	// ClientID / ClientSecret 在 provider 处注册得到。
	//
	// 本应用是 confidential client: 换票发生在服务端, secret 不经过浏览器。
	ClientID     string
	ClientSecret string
	// RedirectURL 必须与在 provider 处登记的回调地址【逐字一致】——
	// 差一个字符就会被对方的白名单拒绝 (那道白名单正是防开放重定向的关键)。
	RedirectURL string
	// Scopes 留空则用 openid email profile。
	//
	// ⚠️ 只写 openid 会拿到一个除了 sub 什么都没有的 id_token ——
	// 遵守规范的 provider 按 scope 分发 claims, 不申请就不给。
	Scopes []string

	// CookieSecret 状态 cookie 的签名密钥 (会经 HKDF 派生, 不直接使用)。
	// 必填, 建议 32 字节以上随机串。
	CookieSecret string
	// CookiePrefix 状态 cookie 名的前缀, 例如 "myapp_oidc_"。
	CookiePrefix string
	// CookiePath 状态 cookie 的作用域, 例如 "/api/auth/oidc/"。
	// 限定它可以让这个 cookie 不出现在其他请求上。
	CookiePath string
	// CookieSecure 生产必须 true。false 时 cookie 允许走明文 HTTP,
	// 中间人读到 state 即可发起登录 CSRF。
	CookieSecure bool
	// FlowTTL 一次往返的有效期 (含用户在 provider 输密码、过 MFA 的时间)。
	// 留空则 10 分钟。太短会让慢吞吞的用户白跑一趟, 太长则拉大 CSRF 窗口。
	FlowTTL time.Duration

	// OnAuthenticated 必填。见该类型的说明。
	OnAuthenticated OnAuthenticated
	// OnError 可选。
	OnError OnError
	// SafeNext 校验回跳目标。留空则只放行本站绝对路径 (见 defaultSafeNext)。
	SafeNext func(next string) bool
	// Logger 留空则用 slog.Default()。
	Logger *slog.Logger
}

// Flow 是本包对外的唯一入口: 两个 HTTP handler。
type Flow struct {
	provider *provider
	keeper   *stateKeeper
	cfg      Config
	log      *slog.Logger
}

// New 构造一次登录流程的处理器。
//
// 会立即拉取 provider 的 discovery 文档 —— 配置写错或对方不可达时在这里就失败,
// 而不是等第一个用户来点登录。调用方应当把这个错误当作启动失败处理。
func New(ctx context.Context, cfg Config) (*Flow, error) {
	if cfg.OnAuthenticated == nil {
		return nil, errors.New("必须提供 OnAuthenticated —— 本包不知道身份该落到哪")
	}
	applyDefaults(&cfg)

	keeper, err := newStateKeeper(cfg.CookieSecret, cfg.FlowTTL,
		cfg.CookiePrefix, cfg.CookiePath, cfg.CookieSecure)
	if err != nil {
		return nil, err
	}
	p, err := newProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Flow{provider: p, keeper: keeper, cfg: cfg, log: cfg.Logger}, nil
}

// applyDefaults 给留空的配置项补上安全的默认值。
//
// 单独成函数是为了能直接断言 —— "忘了补某一项"既不会编译失败也不会运行报错,
// 只会让行为悄悄劣化 (例如 Scopes 空着 → id_token 里没有任何用户资料)。
func applyDefaults(cfg *Config) {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	if cfg.FlowTTL <= 0 {
		cfg.FlowTTL = 10 * time.Minute
	}
	if cfg.SafeNext == nil {
		cfg.SafeNext = DefaultSafeNext
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.CookiePrefix == "" {
		cfg.CookiePrefix = "oidc_state_"
	}
	if cfg.CookiePath == "" {
		cfg.CookiePath = "/"
	}
}

// Start 发起登录: 生成状态、种 cookie、跳去 provider。
//
// 读取 query 参数 next 作为登录成功后的应用内目标; 不合法或缺失时置空。
func (f *Flow) Start(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !f.cfg.SafeNext(next) {
		// 不合法就丢弃而非报错: 它只是个"回哪去"的建议, 不该让登录失败。
		// 但绝不能原样带上 —— 那是开放重定向。
		next = ""
	}

	fs, err := f.keeper.begin(w, next)
	if err != nil {
		f.log.Error("生成登录流程状态失败", "err", err)
		f.fail(w, r, ReasonUpstream, next)
		return
	}
	http.Redirect(w, r, f.provider.authCodeURL(fs), http.StatusFound)
}

// Callback provider 把用户送回来: 验 state → 换票验签 → 交给调用方。
func (f *Flow) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// 用户在 provider 那边点了取消, 或对方拒绝授权
	if e := q.Get("error"); e != "" {
		f.log.Info("用户在上游取消或被拒绝", "reason", e)
		// 这条路径【不消费 state】—— 状态 cookie 留着自然过期即可。
		// 用户很可能只是想换个方式再试一次, 没必要现在就把上下文清掉。
		//
		// 但仍要把回跳目标读出来 (peek 只验签不清除): 取消也是一种结局,
		// 得把用户送回他来的地方 —— 原生客户端尤其如此, 送错地方就等于
		// 让 App 的登录会话悬在那儿。读不出来就退化成空串。
		var next string
		if fs, err := f.keeper.peek(r, q.Get("state")); err == nil {
			next = fs.Next
		}
		f.fail(w, r, ReasonCancelled, next)
		return
	}

	// ⭐ 先验 state 再碰 code: state 校验是 CSRF 防线, 必须发生在任何
	// 有副作用的操作之前 (否则攻击者的 code 会先被拿去跟 provider 兑换)
	fs, err := f.keeper.finish(w, r, q.Get("state"))
	if err != nil {
		f.log.Warn("登录状态校验失败", "err", err)
		// 这里【拿不到】next —— 它本来就存在那个校验失败的 cookie 里。
		// 调用方只能落回默认目标; 原生客户端因此收不到回调 (已知降级)。
		f.fail(w, r, ReasonState, "")
		return
	}

	code := q.Get("code")
	if code == "" {
		f.log.Warn("provider 未返回授权码")
		f.fail(w, r, ReasonUpstream, fs.Next)
		return
	}

	identity, err := f.provider.exchange(r.Context(), code, fs)
	if err != nil {
		f.log.Error("换取上游身份失败", "err", err)
		f.fail(w, r, ReasonUpstream, fs.Next)
		return
	}

	// 到这里身份已经可信。接下来是应用自己的事。
	redirectTo, err := f.cfg.OnAuthenticated(w, r, Result{Identity: identity, Next: fs.Next})
	if err != nil {
		f.log.Error("应用侧处理登录身份失败", "err", err)
		f.fail(w, r, ReasonApplication, fs.Next)
		return
	}
	if redirectTo == "" {
		redirectTo = "/"
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (f *Flow) fail(w http.ResponseWriter, r *http.Request, reason, next string) {
	if f.cfg.OnError != nil {
		f.cfg.OnError(w, r, reason, next)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, "登录未完成 (%s)", reason)
}

// DefaultSafeNext 只放行本站绝对路径, 是 Config.SafeNext 留空时的策略。
//
// 【导出】它是为了让调用方能在其之上扩展而不是重写 —— 例如原生客户端需要额外
// 放行一个自定义 scheme 回调。把下面这几条开放重定向的判定复制一份出去,
// 两份迟早会有一份忘了跟进, 而那种失效不会有任何外部症状。
//
// ⚠️ "//evil.com" 必须拦掉: 它以 / 开头, 看着像本站路径, 但浏览器会把它当作
// 【协议相对 URL】解析成 https://evil.com —— 这是开放重定向最经典的绕过手法。
// 同理 "/\evil.com" 在部分浏览器上等价于 "//evil.com"。
func DefaultSafeNext(next string) bool {
	if next == "" {
		return false
	}
	if !strings.HasPrefix(next, "/") {
		return false
	}
	if strings.HasPrefix(next, "//") || strings.HasPrefix(next, `/\`) {
		return false
	}
	return true
}
