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
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// discovery RFC 8414 / OIDC Discovery 发现文档。
func (h *Handler) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                   h.issuer,
		"authorization_endpoint":   h.issuer + "/authorize",
		"token_endpoint":           h.issuer + "/token",
		"jwks_uri":                 h.issuer + "/jwks",
		"response_types_supported": []string{"code"},
		"grant_types_supported":    []string{"authorization_code", "refresh_token"},
		// pairwise: 每个 client 拿到不同的 sub, 下游之间无法比对出"这是同一个人"。
		// 三个下游面向完全不同的人群, 身份隔离是刻意的 (见 CLAUDE.md 身份标识策略)。
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
	})
}

func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	set, err := h.km.JWKS(r.Context())
	if err != nil {
		slog.Error("JWKS 序列化失败", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
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
	if _, err := h.validateAuthorizeRequest(r.Context(), r.URL.Query()); err != nil {
		// 请求不合法时不能盲目 302 回 redirect_uri (它本身可能就是伪造的), 直接展示错误
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// 停车: 原始请求整体作为 next 穿过登录页与上游往返, 认证完成后由
	// CompleteAuthorize 就地续跑 (不再回跳本端点 —— 无会话下那会死循环)
	next := url.QueryEscape("/authorize?" + r.URL.RawQuery)
	http.Redirect(w, r, "/login?next="+next, http.StatusFound)
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
		slog.Warn("停车的 authorize 请求已失效", "err", err)
		http.Redirect(w, r, "/login?error=internal", http.StatusFound)
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

// validateAuthorizeRequest 解析并校验 authorize 参数 + client 注册状态 + 回调白名单。
// authorize 入口与 CompleteAuthorize 共用它, 保证"进来时"和"发 code 前"用的是同一套判据。
func (h *Handler) validateAuthorizeRequest(ctx context.Context, q url.Values) (*AuthorizeRequest, error) {
	req, err := ParseAuthorizeRequest(q)
	if err != nil {
		return nil, fmt.Errorf("authorize 请求不合法: %w", err)
	}
	c, err := h.clients.FindByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errors.New("client 未注册")
	}
	if err := h.clients.ValidateRedirectURI(c, req.RedirectURI); err != nil {
		return nil, errors.New("redirect_uri 不在白名单")
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
