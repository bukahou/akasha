package federation

import (
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
