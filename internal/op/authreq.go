package op

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// AuthorizeRequest /authorize 的已解析参数。
// "停车"机制: 无会话时整个原始 query 以 next= 形式穿过 /login,
// 登录完成后 302 回 /authorize?原参数 续跑 — 无需停车表, 断点在 URL 里。
type AuthorizeRequest struct {
	ClientID      string
	RedirectURI   string
	Scope         string
	State         string
	Nonce         string
	CodeChallenge string
}

var (
	errUnsupportedResponseType = errors.New("response_type 仅支持 code")
	errPKCERequired            = errors.New("必须携带 PKCE (code_challenge, S256)")
)

// ParseAuthorizeRequest 解析并做与 client 无关的结构校验。
func ParseAuthorizeRequest(q url.Values) (*AuthorizeRequest, error) {
	if q.Get("response_type") != "code" {
		return nil, errUnsupportedResponseType
	}
	// 第一方策略: PKCE 一律强制 (机密客户端也带, 防前信道 code 截获)
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		return nil, errPKCERequired
	}
	req := &AuthorizeRequest{
		ClientID:      q.Get("client_id"),
		RedirectURI:   q.Get("redirect_uri"),
		Scope:         q.Get("scope"),
		State:         q.Get("state"),
		Nonce:         q.Get("nonce"),
		CodeChallenge: q.Get("code_challenge"),
	}
	if req.ClientID == "" || req.RedirectURI == "" {
		return nil, errors.New("缺少 client_id 或 redirect_uri")
	}
	if req.Scope == "" {
		req.Scope = "openid email profile"
	}
	return req, nil
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
