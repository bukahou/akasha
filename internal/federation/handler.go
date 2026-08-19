package federation

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/bukahou/akasha/internal/account"
)

// OPBridge op 侧提供给联邦流程的能力, 由 main 注入 —— 本包因此不必依赖 op。
//
// 用结构体而非四个位置参数: 它们都是函数值, 位置传参写错顺序编译器拦不住
// (把 Complete 和 Deny 传反 = 封禁用户照样拿到 code)。
type OPBridge struct {
	// Complete 认证成功: 就地签 code 并回跳 RP
	Complete func(w http.ResponseWriter, r *http.Request, next string, userID int64)
	// Deny 认证失败且【下游有权知道】: 按规范把 error 回投给 RP
	Deny func(w http.ResponseWriter, r *http.Request, next, errCode, desc string)
	// SafeNext 校验回跳目标是否为本站合法断点 (防开放重定向)
	SafeNext func(next string) bool
	// Prompt 取出停车请求里的 prompt, 用于透传给上游
	Prompt func(next string) string
}

// Handler 联邦端点: 送用户去上游, 把回来的人交给 op 换成授权码。
//
// akasha 无会话 (2026-08-16 定案), 所以这里【不建立任何登录态】——
// 认证结果直接用于完成本次 authorize, 用完即弃。下一次登录重走一遍上游。
type Handler struct {
	registry *Registry
	accounts *account.Service
	keeper   *StateKeeper
	// op 侧的能力全部由装配方注入, 本包不 import op。
	// login 包同样如此 (2026-08-18 起) —— 两个消费者一种机制。
	op OPBridge
}

func NewHandler(registry *Registry, accounts *account.Service, keeper *StateKeeper, bridge OPBridge) *Handler {
	return &Handler{registry: registry, accounts: accounts, keeper: keeper, op: bridge}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /federation/{provider}/start", h.start)
	mux.HandleFunc("GET /federation/{provider}/callback", h.callback)
}

// start 前信道出发: 生成并保管 state/nonce/next, 然后把用户送去上游。
func (h *Handler) start(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	provider, err := h.registry.Lookup(name)
	if err != nil {
		http.Error(w, "不支持的登录方式", http.StatusNotFound)
		return
	}

	// next 是停车的 authorize 断点。只放行本站合法断点 —— 否则攻击者可构造
	// /federation/google/start?next=https://evil.com, 用户在 akasha 正常登录后
	// 被送去钓鱼站, 而地址栏全程显示的是可信域名 (开放重定向)。
	next := r.URL.Query().Get("next")
	if !h.op.SafeNext(next) {
		next = ""
	}

	fs, err := h.keeper.Begin(w, next)
	if err != nil {
		slog.Error("生成联邦流程状态失败", "err", err, "provider", name)
		http.Error(w, "服务器内部错误", http.StatusInternalServerError)
		return
	}
	prompt := upstreamPrompt(h.op.Prompt(next))
	slog.Info("联邦登录开始", "provider", name, "prompt", prompt)
	http.Redirect(w, r, provider.AuthCodeURL(AuthRequest{
		State:    fs.State,
		Nonce:    fs.Nonce,
		Prompt:   prompt,
		Verifier: fs.Verifier,
	}), http.StatusFound)
}

// upstreamPrompt 决定往上游发什么 prompt。
//
// # 为什么默认就带 select_account
//
// 无会话定案宣称的好处之一是"用户随时能换上游账号"(中枢会话会把人静默钉死在
// 第一次登录的那个账号上)。但 akasha 拆掉【自己的】会话, 拆不掉【上游的】——
// Google 那边登着一个账号时, 不带 prompt 的跳转会静默返回它, 用户连选的机会
// 都没有。好处只兑现了一半。带上 select_account 才真正把选择权还给用户。
//
// 这与"登录页必须保留、必须表明是第三方身份"是同一个立场在上游侧的延伸:
// 身份的选择不该被藏起来。代价是多一次点击。
//
// # 为什么 RP 要求 login 时要升级
//
// prompt=login 比 select_account 更强: 前者要求用户【重新证明身份】(敏感操作前
// 的 step-up), 后者只要求选一个账号。RP 显式要更强的, 就给它更强的。
func upstreamPrompt(requested string) string {
	for _, p := range strings.Fields(requested) {
		if p == "login" {
			return "login"
		}
	}
	return "select_account"
}

// callback 上游回来: 校验 state → 换身份断言 → 裁决账号 → 就地续跑停车的 authorize。
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	provider, err := h.registry.Lookup(name)
	if err != nil {
		http.Error(w, "不支持的登录方式", http.StatusNotFound)
		return
	}

	q := r.URL.Query()
	// 用户在上游点了"取消", 或上游拒绝授权
	if e := q.Get("error"); e != "" {
		slog.Info("用户在上游取消或被拒绝", "provider", name, "reason", e)
		// ⭐ next 此刻还在签名 cookie 里, 必须取出来带回登录页。
		// 不取的话: 用户误点一次"取消"→ 回到无 next 的登录页 → 再登成功也只能
		// 落到"请从应用发起登录"的说明页, 必须回下游整个重来。这是很难自查的死路。
		next := ""
		if fs, ferr := h.keeper.Finish(w, r, q.Get("state")); ferr == nil {
			next = fs.Next
		}
		failBack(w, r, "cancelled", next)
		return
	}

	// ⭐ 先验 state 再碰 code: state 校验是 CSRF 防线, 必须发生在任何
	// 有副作用的操作之前 (否则攻击者的 code 会先被拿去跟 Google 兑换)
	fs, err := h.keeper.Finish(w, r, q.Get("state"))
	if err != nil {
		slog.Warn("联邦回调状态校验失败", "err", err, "provider", name)
		// 这一类【确实无处可回】—— 上下文本身就丢了, 不知道用户原本要去哪个 RP
		failBack(w, r, "state", "")
		return
	}

	code := q.Get("code")
	if code == "" {
		slog.Warn("上游未返回授权码", "provider", name)
		failBack(w, r, "upstream", fs.Next)
		return
	}

	upstream, err := provider.Exchange(r.Context(), ExchangeRequest{
		Code:     code,
		Nonce:    fs.Nonce,
		Verifier: fs.Verifier,
	})
	if err != nil {
		slog.Error("上游身份换取失败", "err", err, "provider", name)
		failBack(w, r, "upstream", fs.Next)
		return
	}

	// 身份权威裁决: 命中已关联身份即登录, 否则建号。account 不认亲、无 provider 分支
	user, err := h.accounts.ResolveUpstreamIdentity(r.Context(), upstream)
	if err != nil {
		if errors.Is(err, account.ErrUserBanned) {
			// 封禁是【下游有权知道】的结论: 重试没有意义, 换个 provider 也进不去。
			// 按规范回投 access_denied, 让 geass 用自己的页面向用户解释 ——
			// 把人留在 akasha 的裸页面上, RP 永远不知道发生了什么。
			if fs.Next != "" {
				h.op.Deny(w, r, fs.Next, "access_denied", "账号已封禁")
				return
			}
			failBack(w, r, "banned", "")
			return
		}
		slog.Error("裁决上游身份失败", "err", err, "provider", name)
		failBack(w, r, "internal", fs.Next)
		return
	}

	slog.Info("上游认证成功", "provider", name, "user_id", user.ID)

	// 无 next = 用户直接访问登录页点了上游按钮, 没有任何应用在等这次认证。
	// 无会话设计下这种认证没有归宿 (它不产生登录态), 只能告知用户从应用发起。
	if fs.Next == "" {
		http.Redirect(w, r, "/?authenticated=1", http.StatusFound)
		return
	}
	// 就地完成停车的 authorize: 签 code 并回跳 RP。
	// 【不回跳 /authorize】—— 无会话下那里查不到人, 会再次弹去登录页形成死循环。
	h.op.Complete(w, r, fs.Next, user.ID)
}

// failBack 联邦失败时回到登录页, 而不是甩一个白底黑字的错误页给用户。
//
// 只传【原因码】不传文案: 文案由 login 包按白名单映射。若把 message 直接放进
// query, 攻击者就能构造 /login?error=<任意文案> 借可信域名伪造提示
// (例如"账号异常, 请致电 XXX 解锁")。
// next 一并带回 (若还拿得到): 用户重试或改选另一个上游后仍能回到原应用。
func failBack(w http.ResponseWriter, r *http.Request, reason, next string) {
	target := "/login?error=" + url.QueryEscape(reason)
	if next != "" {
		target += "&next=" + url.QueryEscape(next)
	}
	http.Redirect(w, r, target, http.StatusFound)
}
