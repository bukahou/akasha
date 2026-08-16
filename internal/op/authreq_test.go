package op

import (
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"
)

func baseQuery() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"geass"},
		"redirect_uri":          {"https://geass.test/cb"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
}

func TestParseAuthorizeRequest_Valid(t *testing.T) {
	q := baseQuery()
	q.Set("state", "s1")
	q.Set("nonce", "n1")

	req, err := ParseAuthorizeRequest(q)
	if err != nil {
		t.Fatalf("合法请求被拒: %v", err)
	}
	if req.ClientID != "geass" || req.State != "s1" || req.Nonce != "n1" {
		t.Errorf("解析结果不符: %+v", req)
	}
	// 未指定 scope 时补默认值, 且默认值必须含 openid (否则不是 OIDC 请求)
	if req.Scope != "openid email profile" {
		t.Errorf("默认 scope = %q", req.Scope)
	}
}

// TestParseAuthorizeRequest_Rejects 每一条拒绝都对应一个具体的安全或规范要求。
func TestParseAuthorizeRequest_Rejects(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(url.Values)
		wantCode string
		why      string
	}{
		{
			name:     "response_type 非 code",
			mutate:   func(q url.Values) { q.Set("response_type", "token") },
			wantCode: ErrCodeUnsupportedRespType,
			why:      "implicit flow 会把 token 直接暴露在 URL 里, 本服务只做授权码流",
		},
		{
			name:     "缺 code_challenge",
			mutate:   func(q url.Values) { q.Del("code_challenge") },
			wantCode: ErrCodeInvalidRequest,
			why:      "PKCE 对所有客户端强制 —— public client 的安全性完全依赖它",
		},
		{
			name:     "code_challenge_method 非 S256",
			mutate:   func(q url.Values) { q.Set("code_challenge_method", "plain") },
			wantCode: ErrCodeInvalidRequest,
			why:      "plain 方式下 challenge 就是 verifier 本身, 截获即可重放",
		},
		{
			name:     "缺 client_id",
			mutate:   func(q url.Values) { q.Del("client_id") },
			wantCode: ErrCodeInvalidRequest,
		},
		{
			name:     "缺 redirect_uri",
			mutate:   func(q url.Values) { q.Del("redirect_uri") },
			wantCode: ErrCodeInvalidRequest,
		},
		{
			name:     "scope 不含 openid",
			mutate:   func(q url.Values) { q.Set("scope", "email profile") },
			wantCode: ErrCodeInvalidScope,
			why:      "没有 openid 就不是 OIDC 请求, 不该签发 id_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := baseQuery()
			tt.mutate(q)

			_, err := ParseAuthorizeRequest(q)
			if err == nil {
				t.Fatalf("应当被拒绝但通过了。原因: %s", tt.why)
			}
			var ae *AuthorizeError
			if !errors.As(err, &ae) {
				t.Fatalf("错误类型不是 *AuthorizeError, 无法回投给 RP: %T", err)
			}
			if ae.Code != tt.wantCode {
				t.Errorf("error = %q, 期望 %q", ae.Code, tt.wantCode)
			}
		})
	}
}

// TestPromptParsing prompt 是【空格分隔的多值】(OIDC Core §3.1.2.1)。
// 按单值处理会漏掉 "none login" 这类组合 —— 而含 none 时必须按 none 处理。
func TestPromptParsing(t *testing.T) {
	tests := []struct {
		prompt       string
		wantSilent   bool
		wantReselect bool
	}{
		{"", false, false},
		{"none", true, false},
		{"login", false, true},
		{"select_account", false, true},
		{"none login", true, true}, // 多值: 两者都命中
		{"consent", false, false},  // 未支持的值不误判
		{"nonexistent", false, false},
		{"NONE", false, false}, // 区分大小写, 规范定义的是小写
	}

	for _, tt := range tests {
		t.Run("prompt="+tt.prompt, func(t *testing.T) {
			q := baseQuery()
			q.Set("prompt", tt.prompt)
			req, err := ParseAuthorizeRequest(q)
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if got := req.RequiresSilentAuth(); got != tt.wantSilent {
				t.Errorf("RequiresSilentAuth() = %v, 期望 %v", got, tt.wantSilent)
			}
			if got := req.ForcesAccountSelection(); got != tt.wantReselect {
				t.Errorf("ForcesAccountSelection() = %v, 期望 %v", got, tt.wantReselect)
			}
		})
	}
}

// TestSafeLocalNext 防开放重定向的第一道闸。
//
// next 会被原样用作登录后的跳转目标。放行任何外部 URL, 攻击者就能构造
// /login?next=https://evil.com —— 用户在【真实的】akasha 完成登录后被送去钓鱼站,
// 而地址栏全程显示可信域名。
func TestSafeLocalNext(t *testing.T) {
	allowed := []string{
		"/authorize?response_type=code&client_id=geass",
		"/authorize?a=1",
	}
	for _, s := range allowed {
		if !SafeLocalNext(s) {
			t.Errorf("合法断点被拒: %q", s)
		}
	}

	denied := []string{
		"https://evil.com/steal",
		"//evil.com/steal",                    // 协议相对 URL —— 浏览器会当成外部地址
		"http://localhost:9100/authorize?x=1", // 绝对 URL 即便同源也不放行
		"/login?next=/authorize?x=1",          // 其他本站路径
		"/",
		"",
		"javascript:alert(1)",
		"/authorize",      // 无 query 说明不是一个真实断点
		" /authorize?x=1", // 前导空格
	}
	for _, s := range denied {
		if SafeLocalNext(s) {
			t.Errorf("危险的 next 被放行: %q", s)
		}
	}
}

// TestRedirectWithError 错误回投必须带上 error 与【原样的】state。
// state 是 RP 用来把响应和自己发起的请求对上的凭据, 丢了 RP 无法处理这次失败。
func TestRedirectWithError(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)
	ae := &AuthorizeError{Code: ErrCodeLoginRequired, Desc: "需要交互"}

	if err := RedirectWithError(w, r, "https://geass.test/cb?keep=1", ae, "state-xyz"); err != nil {
		t.Fatalf("回投失败: %v", err)
	}
	if w.Code != 302 {
		t.Errorf("状态码 = %d, 期望 302", w.Code)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location 解析失败: %v", err)
	}
	q := loc.Query()
	if q.Get("error") != ErrCodeLoginRequired {
		t.Errorf("error = %q", q.Get("error"))
	}
	if q.Get("state") != "state-xyz" {
		t.Errorf("state = %q, 必须原样回传", q.Get("state"))
	}
	// 原 URL 上已有的查询参数不能被冲掉
	if q.Get("keep") != "1" {
		t.Error("redirect_uri 原有的查询参数丢失了")
	}
}

func TestRedirectWithError_MalformedURI(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)
	ae := &AuthorizeError{Code: ErrCodeServerError, Desc: "x"}

	// 畸形地址必须返回 error 而不是 panic —— 这是 2026-08-10 修过的缺陷
	if err := RedirectWithError(w, r, "http://a b.com/cb", ae, ""); err == nil {
		t.Fatal("畸形 redirect_uri 应当返回 error")
	}
}

func TestRedirectWithCode(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)

	if err := RedirectWithCode(w, r, "https://geass.test/cb", "the-code", "st"); err != nil {
		t.Fatalf("回跳失败: %v", err)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("code") != "the-code" {
		t.Errorf("code = %q", loc.Query().Get("code"))
	}
	if loc.Query().Get("state") != "st" {
		t.Errorf("state = %q", loc.Query().Get("state"))
	}
}
