package federation

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/bukahou/akasha/internal/account"
)

// CompleteAuthorize 认证成功后完成停车的 authorize 事务 (签 code 并回跳 RP)。
// 由 op 包实现、经 main 注入 —— 本包因此不必依赖 op。
type CompleteAuthorize func(w http.ResponseWriter, r *http.Request, next string, userID int64)

// Handler 联邦端点: 送用户去上游, 把回来的人交给 op 换成授权码。
//
// akasha 无会话 (2026-08-16 定案), 所以这里【不建立任何登录态】——
// 认证结果直接用于完成本次 authorize, 用完即弃。下一次登录重走一遍上游。
type Handler struct {
	registry *Registry
	accounts *account.Service
	keeper   *StateKeeper
	complete CompleteAuthorize
	// safeNext 校验回跳目标是否为本站合法断点。与 complete 同样由装配方注入,
	// 避免本包依赖 op —— login 包为复用同一个函数直接 import 了 op, 造成了
	// 计划外的依赖方向, 这里不重蹈覆辙。
	safeNext func(string) bool
}

func NewHandler(registry *Registry, accounts *account.Service, keeper *StateKeeper,
	complete CompleteAuthorize, safeNext func(string) bool) *Handler {
	return &Handler{registry: registry, accounts: accounts, keeper: keeper, complete: complete, safeNext: safeNext}
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
	if !h.safeNext(next) {
		next = ""
	}

	state, nonce, err := h.keeper.Begin(w, next)
	if err != nil {
		slog.Error("生成联邦流程状态失败", "err", err, "provider", name)
		http.Error(w, "服务器内部错误", http.StatusInternalServerError)
		return
	}
	slog.Info("联邦登录开始", "provider", name)
	http.Redirect(w, r, provider.AuthCodeURL(state, nonce), http.StatusFound)
}

// callback 上游回来: 校验 state → 换身份断言 → 裁决账号 → 建会话 → 回到断点。
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
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// ⭐ 先验 state 再碰 code: state 校验是 CSRF 防线, 必须发生在任何
	// 有副作用的操作之前 (否则攻击者的 code 会先被拿去跟 Google 兑换)
	fs, err := h.keeper.Finish(w, r, q.Get("state"))
	if err != nil {
		slog.Warn("联邦回调状态校验失败", "err", err, "provider", name)
		failBack(w, r, "state")
		return
	}

	code := q.Get("code")
	if code == "" {
		slog.Warn("上游未返回授权码", "provider", name)
		failBack(w, r, "upstream")
		return
	}

	upstream, err := provider.Exchange(r.Context(), code, fs.Nonce)
	if err != nil {
		slog.Error("上游身份换取失败", "err", err, "provider", name)
		failBack(w, r, "upstream")
		return
	}

	// 身份权威裁决: 命中已关联身份即登录, 否则建号。account 不认亲、无 provider 分支
	user, err := h.accounts.ResolveUpstreamIdentity(r.Context(), upstream)
	if err != nil {
		if errors.Is(err, account.ErrUserBanned) {
			failBack(w, r, "banned")
			return
		}
		slog.Error("裁决上游身份失败", "err", err, "provider", name)
		failBack(w, r, "internal")
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
	h.complete(w, r, fs.Next, user.ID)
}

// failBack 联邦失败时回到登录页, 而不是甩一个白底黑字的错误页给用户。
//
// 只传【原因码】不传文案: 文案由 login 包按白名单映射。若把 message 直接放进
// query, 攻击者就能构造 /login?error=<任意文案> 借可信域名伪造提示
// (例如"账号异常, 请致电 XXX 解锁")。
func failBack(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(reason), http.StatusFound)
}
