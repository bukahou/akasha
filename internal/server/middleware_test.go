package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 安全头与 CORS 白名单属于"配错了不会报错, 只会静默失去防护"的一类 ——
// 服务照常返回 200, 日志干干净净, 只有攻击者知道防线没了。
// 这类东西必须由测试守着, 靠人工审查看不出来。
//
// 2026-08-16 审计发现本项目当时【一个安全头都没有】; 补上之后, 这里防的是
// "以后某次重构把它们弄丢了"。

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
}

func serve(h http.Handler, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

// TestSecurityHeaders_AlwaysPresent 这四个头与请求是什么无关, 必须恒定发送。
func TestSecurityHeaders_AlwaysPresent(t *testing.T) {
	// 覆盖登录页 / 协议端点 / 静态路径三类, 确认没有"某些路径漏发"
	paths := []string{"/", "/login", "/authorize", "/token", "/.well-known/openid-configuration"}

	want := map[string]string{
		"X-Frame-Options":        "DENY",        // 点击劫持: IdP 登录页是首选目标
		"X-Content-Type-Options": "nosniff",     // 防 JSON 响应被当 HTML 执行
		"Referrer-Policy":        "no-referrer", // URL 里带 code/state, 不能外泄
	}

	h := SecurityHeaders("https://akasha.test", okHandler())
	for _, p := range paths {
		w := serve(h, http.MethodGet, p)
		for k, v := range want {
			if got := w.Header().Get(k); got != v {
				t.Errorf("%s: %s = %q, 期望 %q", p, k, got, v)
			}
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("%s: 缺少 Content-Security-Policy", p)
		}
	}
}

// TestSecurityHeaders_CSPDirectives CSP 是一串字符串, 少一条指令不会报错。
// 这里逐条钉住有实际防护意义的指令。
func TestSecurityHeaders_CSPDirectives(t *testing.T) {
	csp := serve(SecurityHeaders("https://akasha.test", okHandler()),
		http.MethodGet, "/login").Header().Get("Content-Security-Policy")

	required := map[string]string{
		"default-src 'none'":     "基线全拒, 少了它下面的开口就失去意义",
		"frame-ancestors 'none'": "点击劫持防线 (X-Frame-Options 的现代版)",
		"form-action 'self'":     "挡住注入一个指向外部站点的 form",
		"base-uri 'none'":        "禁 <base> 改写相对 URL",
	}
	for directive, why := range required {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP 缺少 %q —— %s\n  实际: %s", directive, why, csp)
		}
	}

	// script-src 不该被放开: 登录页没有任何 JS, 开了等于白留一个 XSS 落点
	if strings.Contains(csp, "script-src") {
		t.Errorf("CSP 出现了 script-src —— 登录页不需要 JS, 放开它等于白留 XSS 落点\n  实际: %s", csp)
	}
}

// TestSecurityHeaders_HSTSFollowsIssuer HSTS 的开关看 issuer 协议, 不看 r.TLS。
//
// 生产在反向代理 (cloudflared → Gateway) 后面, 到达进程时永远是明文 HTTP,
// r.TLS 恒为 nil —— 靠它判断会导致生产【永远不发】HSTS, 而且没人会注意到。
func TestSecurityHeaders_HSTSFollowsIssuer(t *testing.T) {
	cases := []struct {
		issuer string
		want   bool
		why    string
	}{
		{"https://akasha.example.com", true, "生产形态的 issuer 是 https, 必须发"},
		{"http://localhost:9100", false, "本地明文, 发了浏览器也忽略, 只是噪音"},
	}

	for _, c := range cases {
		// 请求本身是明文 (httptest 不带 TLS), 模拟反向代理后的真实情形
		w := serve(SecurityHeaders(c.issuer, okHandler()), http.MethodGet, "/login")
		got := w.Header().Get("Strict-Transport-Security") != ""
		if got != c.want {
			t.Errorf("issuer=%s: 发送 HSTS = %v, 期望 %v (%s)", c.issuer, got, c.want, c.why)
		}
	}
}

// TestCORS_OnlyNonCookieEndpoints CORS 白名单的判据是"这个端点靠什么认证"。
//
// 靠 cookie 认证的端点一旦开放跨源, 等于让任意站点借用用户的 cookie
// 发起请求 —— CSRF 防线自毁。
func TestCORS_OnlyNonCookieEndpoints(t *testing.T) {
	h := CORS(okHandler())

	allowed := []string{"/token", "/userinfo", "/jwks", "/.well-known/openid-configuration"}
	for _, p := range allowed {
		if got := serve(h, http.MethodPost, p).Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("%s 应放行跨源 (靠参数/Bearer 认证, 不靠 cookie), 实际 Allow-Origin=%q", p, got)
		}
	}

	// 这些依赖联邦状态 cookie 或属于顶级导航, 绝不能开跨源
	denied := map[string]string{
		"/authorize":                  "依赖联邦状态 cookie",
		"/federation/google/start":    "依赖联邦状态 cookie",
		"/federation/google/callback": "依赖联邦状态 cookie",
		"/login":                      "登录页是顶级导航, 不是 XHR",
		"/end_session":                "顶级导航",
	}
	for p, why := range denied {
		if got := serve(h, http.MethodGet, p).Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("%s 不该放行跨源 (%s), 实际 Allow-Origin=%q", p, why, got)
		}
	}
}

// TestCORS_NeverAllowCredentials 放行任意来源的前提就是【不带 credentials】。
//
// 两者同时开在规范上就是非法的, 浏览器会拒绝; 更要紧的是一旦有人"顺手"补上
// 这个头并把 Allow-Origin 改成回显来源, 联邦 cookie 就对全网开放了。
func TestCORS_NeverAllowCredentials(t *testing.T) {
	for _, p := range []string{"/token", "/userinfo", "/jwks"} {
		if got := serve(CORS(okHandler()), http.MethodPost, p).
			Header().Get("Access-Control-Allow-Credentials"); got != "" {
			t.Errorf("%s 回了 Access-Control-Allow-Credentials=%q —— "+
				"与 Allow-Origin:* 并存时 cookie 会对全网开放", p, got)
		}
	}
}

// TestCORS_PreflightShortCircuits 预检请求不应进入业务 handler。
func TestCORS_PreflightShortCircuits(t *testing.T) {
	reached := false
	h := CORS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	w := serve(h, http.MethodOptions, "/token")
	if reached {
		t.Error("OPTIONS 预检进入了业务 handler —— 应在中间件层就结束")
	}
	if w.Code != http.StatusNoContent {
		t.Errorf("预检返回 %d, 期望 204", w.Code)
	}

	// 非白名单路径的 OPTIONS 不该被截胡, 要照常往下走 (交给 mux 判 405)
	reached = false
	serve(h, http.MethodOptions, "/authorize")
	if !reached {
		t.Error("非白名单路径的 OPTIONS 被中间件截胡了 —— 它不归 CORS 管")
	}
}

// TestLimitBody_Threshold 上限值本身钉死。
//
// 下面那条测试用的是 maxRequestBody 常量, 于是常量改成多大它都照样通过 ——
// 它只能证明 MaxBytesReader 接上了, 证明不了限额还是个合理的数。
// 把 64KB 写死在这里, 谁调大它谁就得先回答"为什么"。
//
// 参考: 本服务最大的请求是 /token 的表单, 实际几百字节; 64KB 已是数量级的余量。
func TestLimitBody_Threshold(t *testing.T) {
	const want = 64 << 10
	if maxRequestBody != want {
		t.Errorf("请求体上限 = %d, 期望 %d (64KB)\n"+
			"  调大它意味着扩大内存耗尽面。若确有需要, 请连同理由一起改这条测试", maxRequestBody, want)
	}
}

// TestLimitBody 超限的请求体读取时必须报错, 而不是被默默读完。
func TestLimitBody(t *testing.T) {
	var readErr error
	h := LimitBody(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	}))

	// 恰好在限内: 正常读完
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(strings.Repeat("a", maxRequestBody))))
	if readErr != nil {
		t.Errorf("限内请求体读取失败: %v", readErr)
	}

	// 超一个字节: 必须报错, 否则 ParseForm 会把整个 body 吞进内存
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(strings.Repeat("a", maxRequestBody+1))))
	if readErr == nil {
		t.Error("超限请求体被完整读入 —— MaxBytesReader 没有生效")
	}
}
