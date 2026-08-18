package federation

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"

	"golang.org/x/oauth2"
)

// newTestGoogleProvider 不走 NewGoogleProvider —— 那个构造函数会去拉 Google 的
// discovery 文档 (需要网络)。这里只测 URL 组装, 直接填 oauth 配置即可。
func newTestGoogleProvider() *googleProvider {
	return &googleProvider{
		oauth: &oauth2.Config{
			ClientID:    "test-client-id",
			RedirectURL: "https://akasha.test/federation/google/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/v2/auth"},
			Scopes:      []string{"openid", "email", "profile"},
		},
	}
}

// TestGoogleAuthCodeURL_CarriesPrompt ⭐ prompt 必须真的进到给 Google 的 URL 里。
//
// # 这条测试补得晚了
//
// 2026-08-18 提交 prompt 透传后做变异测试, 把 AuthCodeURL 里的 prompt 分支
// 改成永不执行 —— 全部测试照样通过。upstreamPrompt 有测试, 但没有任何断言
// 检查它的返回值是否真的到达了上游 URL。
//
// 而整个改动的目的 (让用户看到账号选择器) 恰恰依赖这最后一步。
// 中间函数算得再对, 值没传出去就等于没做。
func TestGoogleAuthCodeURL_CarriesPrompt(t *testing.T) {
	g := newTestGoogleProvider()

	cases := []string{"select_account", "login"}
	for _, prompt := range cases {
		raw := g.AuthCodeURL(AuthRequest{State: "st4te", Nonce: "n0nce", Prompt: prompt})
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("生成的授权地址不是合法 URL: %q", raw)
		}
		q := u.Query()

		if got := q.Get("prompt"); got != prompt {
			t.Errorf("prompt = %q, 期望 %q\n"+
				"  没传到上游 = 用户看不到账号选择器, 整个透传改动等于没做\n"+
				"  完整地址: %s", got, prompt, raw)
		}
		// 同一趟必须带上的另外两个: 少哪个都会让流程在回调时失败
		if q.Get("state") != "st4te" {
			t.Errorf("state = %q, 期望原样带上 (CSRF 防线)", q.Get("state"))
		}
		if q.Get("nonce") != "n0nce" {
			t.Errorf("nonce = %q, 期望原样带上 (防 id_token 重放)", q.Get("nonce"))
		}
	}
}

// TestGoogleAuthCodeURL_OmitsEmptyPrompt 没有 prompt 时不该发一个空参数。
//
// prompt= (空值) 与不发这个参数在上游看来未必等价, 别给它机会。
func TestGoogleAuthCodeURL_OmitsEmptyPrompt(t *testing.T) {
	raw := newTestGoogleProvider().AuthCodeURL(AuthRequest{State: "s", Nonce: "n"})
	u, _ := url.Parse(raw)
	if u.Query().Has("prompt") {
		t.Errorf("Prompt 为空时仍写了 prompt= 参数: %s", raw)
	}
}

// TestGoogleAuthCodeURL_EndToEndDefault 从 upstreamPrompt 到最终 URL 的整条链。
//
// 分开测两截各自正确, 不代表接起来是通的 —— 上面那次变异漏检就是断在接缝处。
func TestGoogleAuthCodeURL_EndToEndDefault(t *testing.T) {
	// RP 没有要求 prompt 时, 默认也必须让用户看到账号选择器
	raw := newTestGoogleProvider().AuthCodeURL(AuthRequest{
		State: "s", Nonce: "n", Prompt: upstreamPrompt(""),
	})
	u, _ := url.Parse(raw)
	if got := u.Query().Get("prompt"); got != "select_account" {
		t.Errorf("默认链路上的 prompt = %q, 期望 select_account\n"+
			"  这是无会话定案「用户随时能换上游账号」真正落地的那一步", got)
	}
}

// TestGoogleAuthCodeURL_CarriesPKCE ⭐ akasha 当 RP 时也要用 PKCE。
//
// # 为什么这里也需要
//
// akasha 对下游【强制】PKCE S256, 自己向上游却一直不带 —— 一个把"亲手实现
// 协议两侧"写进定位的项目, 这处不对称格外显眼。RFC 9700 建议所有 client
// (含能保管 secret 的 confidential) 都用: 它防的是回调阶段 code 被截获,
// 而那与 client 能不能保管 secret 无关。
//
// verifier 本身留在签名 cookie 里, 发出去的只有 S256(verifier)。
func TestGoogleAuthCodeURL_CarriesPKCE(t *testing.T) {
	const verifier = "test-verifier-0123456789012345678901234567890123456789"

	raw := newTestGoogleProvider().AuthCodeURL(AuthRequest{
		State: "s", Nonce: "n", Prompt: "select_account", Verifier: verifier,
	})
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("授权地址不是合法 URL: %q", raw)
	}
	q := u.Query()

	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, 期望 S256（plain 等于没有防护）", q.Get("code_challenge_method"))
	}
	challenge := q.Get("code_challenge")
	if challenge == "" {
		t.Fatal("没有发送 code_challenge —— 上游侧 PKCE 没生效")
	}

	// challenge 必须是 verifier 的 S256, 且【不等于 verifier 本身】——
	// 后者是最典型的实现错误: 把原文当挑战发出去, PKCE 直接失效
	want := base64.RawURLEncoding.EncodeToString(func() []byte {
		sum := sha256.Sum256([]byte(verifier))
		return sum[:]
	}())
	if challenge != want {
		t.Errorf("code_challenge = %q, 期望 S256(verifier) = %q", challenge, want)
	}
	if challenge == verifier {
		t.Error("把 verifier 原文当作 challenge 发出去了 —— 截获它的人可直接兑换")
	}
}

// TestGoogleAuthCodeURL_OmitsEmptyVerifier 没有 verifier 时不发 challenge。
// 留给将来不支持 PKCE 的上游 —— 发一个空 challenge 会让它直接报错。
func TestGoogleAuthCodeURL_OmitsEmptyVerifier(t *testing.T) {
	raw := newTestGoogleProvider().AuthCodeURL(AuthRequest{State: "s", Nonce: "n"})
	u, _ := url.Parse(raw)
	if u.Query().Has("code_challenge") {
		t.Errorf("Verifier 为空时仍发了 code_challenge: %s", raw)
	}
}
