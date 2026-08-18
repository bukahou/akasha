package op

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/bukahou/akasha/internal/client"
	"github.com/bukahou/akasha/internal/keys"
)

// Handler OIDC 协议端点的 HTTP 层。
type Handler struct {
	svc     *Service
	clients *client.Registry
	km      *keys.Manager
	issuer  string
}

func NewHandler(svc *Service, clients *client.Registry, km *keys.Manager, issuer string) *Handler {
	return &Handler{svc: svc, clients: clients, km: km, issuer: issuer}
}

// Register 挂载协议端点。
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("GET /jwks", h.jwks)
	mux.HandleFunc("GET /authorize", h.authorize)
	mux.HandleFunc("POST /token", h.token)
	// 规范要求至少支持 GET; POST 一并支持 (部分 RP 用表单提交以避免 URL 过长)
	mux.HandleFunc("GET /end_session", h.endSession)
	mux.HandleFunc("POST /end_session", h.endSession)
	mux.HandleFunc("GET /userinfo", h.userinfo)
	mux.HandleFunc("POST /userinfo", h.userinfo)
	// 健康探针【不在这里】—— 它不是协议端点, 归 server.Health (见 main 的装配)
}

// discovery RFC 8414 / OIDC Discovery 发现文档。
func (h *Handler) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                   h.issuer,
		"authorization_endpoint":   h.issuer + "/authorize",
		"token_endpoint":           h.issuer + "/token",
		"jwks_uri":                 h.issuer + "/jwks",
		"userinfo_endpoint":        h.issuer + "/userinfo",
		"end_session_endpoint":     h.issuer + "/end_session",
		"response_types_supported": []string{"code"},
		"grant_types_supported":    []string{"authorization_code", "refresh_token"},
		// pairwise: 每个 client 拿到不同的 sub, 下游之间无法比对出"这是同一个人"。
		// 三个下游面向完全不同的人群, 身份隔离是刻意的 (见 CLAUDE.md 身份标识策略)。
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"response_modes_supported":              []string{"query"},
		// 声明 none 是有意义的: 它告诉 RP "静默认证这条路存在但会失败",
		// RP 据此知道该拿到 login_required 而不是超时
		"prompt_values_supported": []string{"none", "login", "select_account"},
		// claims_supported 让 RP 知道能拿到哪些字段, 不必靠试。
		// 后半段那些【按 scope 分发】(见 identityClaims): 只申请 openid 的 RP
		// 一个都拿不到 —— 这里声明的是"能拿到什么", 不是"一定会拿到什么"
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time", "azp", "at_hash", "nonce",
			"email", "email_verified", // scope=email
			"name", "preferred_username", "picture", // scope=profile
		},
	})
}

// jwksMaxAge 公钥集的缓存时长。
//
// 不发缓存头时 RP 每次验签都可能回源, akasha 就成了验签路径上的实时依赖。
// 1 小时是主流 OP 的量级 (Google 同级)。轮换安全性不受影响: 新旧公钥并存于
// JWKS 中, 旧 token 在自然过期前始终验得过, 缓存过期后新公钥自然被取到。
const jwksMaxAge = 3600

func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	set, err := h.km.JWKS(r.Context())
	if err != nil {
		slog.Error("JWKS 序列化失败", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", jwksMaxAge))
	writeJSON(w, http.StatusOK, set)
}

// authorize 前信道入口。
//
// # 为什么这里【永远】跳登录页, 从不直接发 code
//
// akasha 不保留登录态 (2026-08-16 定案: 完全无会话)。每一次 authorize 都意味着
// 重新走一遍上游认证 —— 没有"已登录用户"这种状态可查, 自然也就没有"直接发 code"
// 这条分支。
//
// 代价是放弃 SSO (从 geass 登录后再进 atlhyper 不会免登录), 换来的是:
//   - 应用之间彻底无关联, 与 pairwise sub 的隔离立场一致
//   - 用户随时能换上游账号 —— 中枢会话会把人静默钉死在第一次登录的那个账号上
//   - akasha 无状态, 无需登出机制, 也没有"30 天窗口"这种攻击面
//
// 实际体验损失有限: 上游 (Google) 自己有会话, 重新走一遍通常只是几百毫秒的
// 静默重定向, 不需要重新输密码。
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	req, err := h.validateAuthorizeRequest(r.Context(), r.URL.Query())
	if err != nil {
		h.failAuthorize(w, r, r.URL.Query(), err)
		return
	}

	// prompt=none 要求"绝不与用户交互"。akasha 不保留登录态, 静默认证永远无法满足 ——
	// 但必须按规范回 error=login_required 给 RP, 而不是把登录页显示出来:
	// SPA 常用隐藏 iframe + prompt=none 探测登录态, 显示登录页会让探测永远无结论。
	if req.RequiresSilentAuth() {
		ae := &AuthorizeError{Code: ErrCodeLoginRequired, Desc: "需要用户交互完成认证 (本服务不保留登录态)"}
		if err := RedirectWithError(w, r, req.RedirectURI, ae, req.State); err != nil {
			slog.Error("回投 authorize 错误失败", "err", err, "client_id", req.ClientID)
			http.Error(w, "服务器内部错误", http.StatusInternalServerError)
		}
		return
	}

	// 停车: 原始请求整体作为 next 穿过登录页与上游往返, 认证完成后由
	// CompleteAuthorize 就地续跑 (不再回跳本端点 —— 无会话下那会死循环)
	next := url.QueryEscape("/authorize?" + r.URL.RawQuery)
	http.Redirect(w, r, "/login?next="+next, http.StatusFound)
}

// failAuthorize 决定一个 authorize 错误是【回投给 RP】还是【直接显示】。
//
// 这个判断本身就是防开放重定向的关键: 只有当 client 确实存在、且 redirect_uri
// 确实在它的白名单里时, 才可以往那个地址跳。否则任何人都能构造一个指向自己
// 站点的 redirect_uri, 让 akasha 把用户送过去, 而地址栏全程显示可信域名。
//
// 所以次序是固定的: 先独立地把 client 与 redirect_uri 验一遍, 通过了才回投;
// 没通过就只能在本站显示 —— 那时我们无法确认目标地址属于谁。
func (h *Handler) failAuthorize(w http.ResponseWriter, r *http.Request, q url.Values, err error) {
	var ae *AuthorizeError
	if !errors.As(err, &ae) {
		ae = &AuthorizeError{Code: ErrCodeServerError, Desc: err.Error()}
	}

	clientID, redirectURI := q.Get("client_id"), q.Get("redirect_uri")
	if clientID != "" && redirectURI != "" {
		if c, cerr := h.clients.FindByClientID(r.Context(), clientID); cerr == nil {
			if h.clients.ValidateRedirectURI(c, redirectURI) == nil {
				// 目标可信, 按规范回投
				if rerr := RedirectWithError(w, r, redirectURI, ae, q.Get("state")); rerr == nil {
					slog.Info("回投 authorize 错误", "error", ae.Code, "client_id", clientID)
					return
				}
			}
		}
	}
	// 目标不可信或不可用 —— 只能在本站显示
	slog.Warn("authorize 请求不合法且无法回投", "error", ae.Code, "desc", ae.Desc)
	http.Error(w, "authorize 请求不合法: "+ae.Desc, http.StatusBadRequest)
}

// CompleteAuthorize 用刚认证到的身份完成一次停车的 authorize 事务: 签 code 并回跳 RP。
//
// 由 federation 在上游回调成功后调用 (经 main 注入, 避免 federation 依赖 op)。
// next 是停车时保存的原始 "/authorize?..." 请求, 全程受签名 cookie 保护。
//
// 这里【重新校验一遍】client 与 redirect_uri: next 虽有签名保护不可篡改, 但
// 从停车到回来中间隔着整个上游往返, 期间 client 可能已被删除或改了白名单。
// 签发 code 前的最后一道关必须自己把住。
func (h *Handler) CompleteAuthorize(w http.ResponseWriter, r *http.Request, next string, userID int64) {
	u, err := url.Parse(next)
	if err != nil {
		slog.Error("停车的 authorize 请求解析失败", "err", err)
		http.Redirect(w, r, "/login?error=internal", http.StatusFound)
		return
	}
	req, err := h.validateAuthorizeRequest(r.Context(), u.Query())
	if err != nil {
		// 停车期间 client 被删或白名单变了 —— 此时用户已完成认证, 回投比白页友好
		slog.Warn("停车的 authorize 请求已失效", "err", err)
		h.failAuthorize(w, r, u.Query(), err)
		return
	}

	code, err := h.svc.IssueCode(r.Context(), req, userID)
	if err != nil {
		slog.Error("签发授权码失败", "err", err, "client_id", req.ClientID)
		http.Redirect(w, r, "/login?error=internal", http.StatusFound)
		return
	}
	slog.Info("签发授权码", "client_id", req.ClientID, "user_id", userID)
	if err := RedirectWithCode(w, r, req.RedirectURI, code, req.State); err != nil {
		// code 已签发但送不回去 —— 它 60 秒后自然过期, 无需额外清理
		slog.Error("回跳 RP 失败", "err", err, "client_id", req.ClientID)
		http.Error(w, "服务器内部错误", http.StatusInternalServerError)
		return
	}
}

// DenyAuthorize 把"认证没成功"的结论按规范回投给 RP (RFC 6749 §4.1.2.1)。
//
// 由 federation 在【下游有权知道】的失败上调用 (经 main 注入)。
// 典型场景是账号被封禁: 重试没有意义, 换一个上游 provider 也照样进不去,
// 把人留在 akasha 的裸页面上只会让 RP 永远不知道发生了什么 ——
// 而 geass 用自己的页面告诉用户"该账号无法登录"显然更合适。
//
// 与 CompleteAuthorize 同样【重新校验】client 与白名单: 回投的前提永远是
// "这个地址确实属于这个 client"。验不过就退回本站显示, 绝不盲跳。
func (h *Handler) DenyAuthorize(w http.ResponseWriter, r *http.Request, next, errCode, desc string) {
	u, err := url.Parse(next)
	if err != nil {
		slog.Error("停车的 authorize 请求解析失败", "err", err)
		http.Redirect(w, r, "/login?error=internal", http.StatusFound)
		return
	}
	q := u.Query()
	req, verr := h.validateAuthorizeRequest(r.Context(), q)
	if verr != nil {
		// 连 client 都验不过 —— 交给 failAuthorize 自己判断能不能回投
		h.failAuthorize(w, r, q, verr)
		return
	}
	ae := &AuthorizeError{Code: errCode, Desc: desc}
	if rerr := RedirectWithError(w, r, req.RedirectURI, ae, req.State); rerr != nil {
		slog.Error("回投 authorize 拒绝失败", "err", rerr, "client_id", req.ClientID)
		http.Error(w, "服务器内部错误", http.StatusInternalServerError)
		return
	}
	slog.Info("回投 authorize 拒绝", "error", errCode, "client_id", req.ClientID)
}

// ClientNameFromNext 由停车的 authorize 请求取出该 client 的展示名。
//
// 登录页拿它渲染"继续前往 xx"。这【不只是 UX】—— 让用户看见自己正在登录到
// 哪个应用是反钓鱼的一环: 攻击者诱导你点一个看似 atlhyper 的链接, 页面上却
// 写着 geass, 那一刻是唯一能察觉的机会。
//
// 由 op 提供并经 main 注入, 因为查 clients 表是它的事 ——
// login 是个不依赖任何内部包的渲染器, 不该为此认识数据库。
//
// 任何失败都返回空串: 名字缺了页面少一行字而已, 绝不能让登录失败。
func (h *Handler) ClientNameFromNext(ctx context.Context, next string) string {
	u, err := url.Parse(next)
	if err != nil {
		return ""
	}
	clientID := u.Query().Get("client_id")
	if clientID == "" {
		return ""
	}
	c, err := h.clients.FindByClientID(ctx, clientID)
	if err != nil {
		return ""
	}
	return c.Name
}

// validateAuthorizeRequest 解析并校验 authorize 参数 + client 注册状态 + 回调白名单。
// authorize 入口与 CompleteAuthorize 共用它, 保证"进来时"和"发 code 前"用的是同一套判据。
func (h *Handler) validateAuthorizeRequest(ctx context.Context, q url.Values) (*AuthorizeRequest, error) {
	req, err := ParseAuthorizeRequest(q)
	if err != nil {
		return nil, err
	}
	c, err := h.clients.FindByClientID(ctx, req.ClientID)
	if err != nil {
		// client 都不存在, 更谈不上信任它给的 redirect_uri —— 这个错误注定无法回投
		return nil, authErr(ErrCodeUnauthorizedClient, "client 未注册")
	}
	if err := h.clients.ValidateRedirectURI(c, req.RedirectURI); err != nil {
		return nil, authErr(ErrCodeInvalidRequest, "redirect_uri 不在白名单")
	}
	return req, nil
}

// token 后信道: client 认证 → code 兑换 / refresh 滚动。
func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "表单解析失败")
		return
	}

	clientID, clientSecret := r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	if u, p, ok := r.BasicAuth(); ok { // client_secret_basic 优先
		clientID, clientSecret = u, p
	}
	c, err := h.clients.Authenticate(r.Context(), clientID, clientSecret)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client 认证失败")
		return
	}

	var ts *TokenSet
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		ts, err = h.svc.ExchangeCode(r.Context(),
			c.ClientID,
			r.PostFormValue("code"),
			r.PostFormValue("code_verifier"),
			r.PostFormValue("redirect_uri"),
		)
	case "refresh_token":
		ts, err = h.svc.RefreshTokens(r.Context(), c.ClientID, r.PostFormValue("refresh_token"))
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "仅支持 authorization_code / refresh_token")
		return
	}

	if err != nil {
		// 请求方的错 → 400 invalid_grant (RFC 6749 §5.2)。
		// 只有真正的服务端故障才配 500 —— 分错了会让 RP 把"用户被封禁"当成
		// akasha 宕机去重试, 而不是引导用户重新登录。
		switch {
		// 重放已在 repository 层触发连坐撤销并记了安全事件日志。
		// 对外仍回统一的 invalid_grant, 不透露"我们识别出了重放"——
		// 那等于给攻击者反馈, 帮他判断哪张票是真的。
		case errors.Is(err, ErrCodeReplayed), errors.Is(err, ErrRefreshReplayed):
			writeTokenError(w, http.StatusBadRequest, "invalid_grant", "凭证无效")
			return
		case errors.Is(err, ErrCodeInvalid), errors.Is(err, ErrRefreshInvalid),
			errors.Is(err, ErrPKCEMismatch), errors.Is(err, ErrPKCEMalformed),
			errors.Is(err, ErrUserUnavailable):
			writeTokenError(w, http.StatusBadRequest, "invalid_grant", err.Error())
			return
		}
		slog.Error("token 签发失败", "err", err, "client_id", c.ClientID)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "服务器内部错误")
		return
	}
	slog.Info("签发 token", "client_id", c.ClientID)
	// RFC 6749 §5.1 REQUIRED: token 响应装着凭证, 绝不能被任何中间层缓存。
	// (对比 /jwks 那边发的是 public max-age —— 公钥本就该被缓存, 两者刚好相反)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, ts)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeTokenError RFC 6749 错误响应格式。
func writeTokenError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}
