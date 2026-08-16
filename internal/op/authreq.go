package op

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// AuthorizeRequest /authorize 的已解析参数。
// "停车"机制: 整个原始 query 以 next= 形式穿过登录页与上游往返,
// 认证完成后由 CompleteAuthorize 就地续跑 — 无需停车表, 断点在 URL 里。
type AuthorizeRequest struct {
	ClientID      string
	RedirectURI   string
	Scope         string
	State         string
	Nonce         string
	CodeChallenge string
	// Prompt 空 / "none" / "login" / "consent" / "select_account" (可空格分隔多值)
	Prompt string
	// LoginHint 用户名提示, 透传给上游预填账号
	LoginHint string
}

// AuthorizeError 可回投给 RP 的 authorize 错误 (RFC 6749 §4.1.2.1)。
//
// 规范要求: 只要 client_id 与 redirect_uri 【已验证有效】, 错误就必须 302 回
// redirect_uri 并带 error 与原样 state, 而不是在 OP 上直接显示 —— 否则 RP 永远
// 不知道发生了什么, 用户停在一个陌生域名的白页上。
type AuthorizeError struct {
	Code string // RFC 定义的错误码, 会作为 error 参数回投
	Desc string // 给人看的补充说明
}

func (e *AuthorizeError) Error() string { return e.Desc }

// RFC 6749 §4.1.2.1 / OIDC Core §3.1.2.6 的错误码。
const (
	ErrCodeInvalidRequest      = "invalid_request"
	ErrCodeUnsupportedRespType = "unsupported_response_type"
	ErrCodeInvalidScope        = "invalid_scope"
	ErrCodeLoginRequired       = "login_required"
	ErrCodeInteractionRequired = "interaction_required"
	ErrCodeServerError         = "server_error"
	ErrCodeUnauthorizedClient  = "unauthorized_client"
	ErrCodeAccessDenied        = "access_denied"
	promptNone                 = "none"
	promptLogin                = "login"
	promptSelectAccount        = "select_account"
)

func authErr(code, desc string) error { return &AuthorizeError{Code: code, Desc: desc} }

// ParseAuthorizeRequest 解析并做与 client 无关的结构校验。
//
// 返回的 error 若为 *AuthorizeError, 调用方应在确认 redirect_uri 可信后回投给 RP。
func ParseAuthorizeRequest(q url.Values) (*AuthorizeRequest, error) {
	if q.Get("response_type") != "code" {
		return nil, authErr(ErrCodeUnsupportedRespType, "response_type 仅支持 code")
	}
	// 第一方策略: PKCE 一律强制 (机密客户端也带, 防前信道 code 截获)
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		return nil, authErr(ErrCodeInvalidRequest, "必须携带 PKCE (code_challenge + code_challenge_method=S256)")
	}
	req := &AuthorizeRequest{
		ClientID:      q.Get("client_id"),
		RedirectURI:   q.Get("redirect_uri"),
		Scope:         q.Get("scope"),
		State:         q.Get("state"),
		Nonce:         q.Get("nonce"),
		CodeChallenge: q.Get("code_challenge"),
		Prompt:        q.Get("prompt"),
		LoginHint:     q.Get("login_hint"),
	}
	if req.ClientID == "" || req.RedirectURI == "" {
		return nil, authErr(ErrCodeInvalidRequest, "缺少 client_id 或 redirect_uri")
	}
	if req.Scope == "" {
		req.Scope = "openid email profile"
	}
	// OIDC 请求必须含 openid scope; 没有它这就不是一个 OIDC 请求
	if !hasScope(req.Scope, "openid") {
		return nil, authErr(ErrCodeInvalidScope, "scope 必须包含 openid")
	}
	return req, nil
}

// RequiresSilentAuth 请求方要求"不得与用户交互"(prompt=none)。
//
// akasha 无会话, 因此静默认证【永远无法满足】—— 但规范要求此时回
// error=login_required 给 RP, 而不是把登录页展示出来。SPA 常用隐藏 iframe +
// prompt=none 探测登录态, 展示登录页会让探测永远等不到结论。
func (r *AuthorizeRequest) RequiresSilentAuth() bool {
	return hasPrompt(r.Prompt, promptNone)
}

// ForcesAccountSelection 请求方要求重新选择账号 (prompt=login / select_account)。
// 无会话下每次本就重新认证, 此处用于把意图透传给上游。
func (r *AuthorizeRequest) ForcesAccountSelection() bool {
	return hasPrompt(r.Prompt, promptLogin) || hasPrompt(r.Prompt, promptSelectAccount)
}

// hasPrompt prompt 是空格分隔的多值列表 (OIDC Core §3.1.2.1)。
func hasPrompt(prompt, want string) bool {
	for _, p := range strings.Fields(prompt) {
		if p == want {
			return true
		}
	}
	return false
}

func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// RedirectWithError 把错误回投给 RP (RFC 6749 §4.1.2.1)。
//
// ⚠️ 调用前【必须】已经确认 redirect_uri 属于该 client 的白名单。
// 次序反了就是开放重定向漏洞: 任何人都能构造一个指向自己站点的 redirect_uri,
// 让 akasha 把用户送过去 —— 而地址栏全程显示的是可信域名。
func RedirectWithError(w http.ResponseWriter, r *http.Request, redirectURI string, ae *AuthorizeError, state string) error {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("redirect_uri 解析失败: %w", err)
	}
	q := u.Query()
	q.Set("error", ae.Code)
	if ae.Desc != "" {
		q.Set("error_description", ae.Desc)
	}
	// state 必须原样回传 —— RP 靠它把这次响应和自己发起的请求对上
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
	return nil
}

// SafeLocalNext 校验登录后的回跳目标必须是本站 /authorize 路径 (防开放重定向)。
func SafeLocalNext(next string) bool {
	return strings.HasPrefix(next, "/authorize?")
}

// RedirectWithCode 把 code(+state) 送回 RP 回调 (前信道, 只带非机密)。
//
// redirectURI 已过白名单精确匹配, 值来自管理员写进 clients 表的配置 ——
// 但"可信来源"不等于"格式合法": 一个手滑写坏的白名单值会让 url.Parse 返回 nil,
// 紧接着的 u.Query() 就是 nil 解引用 panic, 整个 IdP 随之崩溃。
// 触发概率低而代价是全线不可用, 所以这里必须把 error 收上来。
func RedirectWithCode(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) error {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("redirect_uri 解析失败: %w", err)
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
	return nil
}
