package op

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/bukahou/akasha/internal/client"
	"github.com/bukahou/akasha/internal/keys"
	"github.com/bukahou/akasha/internal/session"
)

// Handler OIDC 协议端点的 HTTP 层。
type Handler struct {
	svc      *Service
	clients  *client.Registry
	sessions *session.Store
	km       *keys.Manager
	issuer   string
}

func NewHandler(svc *Service, clients *client.Registry, sessions *session.Store, km *keys.Manager, issuer string) *Handler {
	return &Handler{svc: svc, clients: clients, sessions: sessions, km: km, issuer: issuer}
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
		"issuer":                                h.issuer,
		"authorization_endpoint":                h.issuer + "/authorize",
		"token_endpoint":                        h.issuer + "/token",
		"jwks_uri":                              h.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
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

// authorize 前信道入口: 校验请求与 client → 有会话直发 code / 无会话把断点塞进 next 送去 /login。
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	req, err := ParseAuthorizeRequest(r.URL.Query())
	if err != nil {
		// 请求结构不合法: 不能盲目 302 回 redirect_uri (它本身可能就是伪造的), 直接展示错误
		http.Error(w, "authorize 请求不合法: "+err.Error(), http.StatusBadRequest)
		return
	}
	c, err := h.clients.FindByClientID(r.Context(), req.ClientID)
	if err != nil {
		http.Error(w, "client 未注册", http.StatusBadRequest)
		return
	}
	if err := h.clients.ValidateRedirectURI(c, req.RedirectURI); err != nil {
		http.Error(w, "redirect_uri 不在白名单", http.StatusBadRequest)
		return
	}

	sess, err := h.sessions.Resolve(r.Context(), r)
	if err != nil {
		slog.Error("会话解析失败", "err", err)
		http.Error(w, "服务器内部错误", http.StatusInternalServerError)
		return
	}
	if sess == nil {
		// 停车: 原始请求整体作为 next 穿过登录页, 登录完成后 302 回来续跑
		next := url.QueryEscape("/authorize?" + r.URL.RawQuery)
		http.Redirect(w, r, "/login?next="+next, http.StatusFound)
		return
	}

	code, err := h.svc.IssueCode(r.Context(), req, sess.UserID)
	if err != nil {
		slog.Error("签发授权码失败", "err", err, "client_id", req.ClientID)
		http.Error(w, "服务器内部错误", http.StatusInternalServerError)
		return
	}
	slog.Info("签发授权码", "client_id", req.ClientID, "user_id", sess.UserID)
	RedirectWithCode(w, r, req.RedirectURI, code, req.State)
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
		if errors.Is(err, ErrCodeInvalid) || errors.Is(err, ErrPKCEMismatch) {
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
