package oidcrp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestKeeper(t *testing.T, ttl time.Duration) *stateKeeper {
	t.Helper()
	k, err := newStateKeeper("test-secret-not-a-real-key", ttl, "test_", "/cb/", false)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	return k
}

// begin 走一遍并把 cookie 装进新请求, 模拟浏览器往返。
func roundTrip(t *testing.T, k *stateKeeper, next string) (*flowState, *http.Request) {
	t.Helper()
	w := httptest.NewRecorder()
	fs, err := k.begin(w, next)
	if err != nil {
		t.Fatalf("begin 失败: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/cb/callback", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	return fs, r
}

func TestStateKeeper_RoundTrip(t *testing.T) {
	k := newTestKeeper(t, 10*time.Minute)
	fs, r := roundTrip(t, k, "/anime/123")

	got, err := k.finish(httptest.NewRecorder(), r, fs.State)
	if err != nil {
		t.Fatalf("正常往返失败: %v", err)
	}
	if got.Next != "/anime/123" {
		t.Errorf("next = %q, 期望原样带回", got.Next)
	}
	if got.Nonce != fs.Nonce || got.Verifier != fs.Verifier {
		t.Error("nonce / verifier 没有原样带回 —— 后续的重放校验与 PKCE 都会失效")
	}
}

// TestStateKeeper_RequiresCookie ⭐ 光有合法 state 不够, 必须是【这个浏览器】的。
//
// 这条守的是登录 CSRF: 攻击者手里的 state 也是本应用签发的、签名也合法,
// 唯一能区分的就是"有没有对应的 cookie"。
func TestStateKeeper_RequiresCookie(t *testing.T) {
	k := newTestKeeper(t, 10*time.Minute)
	fs, _ := roundTrip(t, k, "/x")

	// 有合法 state, 但请求不带 cookie（= 另一个浏览器）
	bare := httptest.NewRequest(http.MethodGet, "/cb/callback", nil)
	if _, err := k.finish(httptest.NewRecorder(), bare, fs.State); err == nil {
		t.Error("没有 cookie 也放行了 —— 登录 CSRF 防线失效")
	}
}

// TestStateKeeper_TamperedPayload 篡改 payload 后签名必须失效。
func TestStateKeeper_TamperedPayload(t *testing.T) {
	k := newTestKeeper(t, 10*time.Minute)
	w := httptest.NewRecorder()
	fs, err := k.begin(w, "/safe")
	if err != nil {
		t.Fatalf("begin 失败: %v", err)
	}
	orig := w.Result().Cookies()[0]

	// 把 next 改成钓鱼站, 签名照抄
	payload, sig, _ := strings.Cut(orig.Value, ".")
	tampered := payload[:len(payload)-4] + "AAAA" + "." + sig

	r := httptest.NewRequest(http.MethodGet, "/cb/callback", nil)
	r.AddCookie(&http.Cookie{Name: orig.Name, Value: tampered})
	if _, err := k.finish(httptest.NewRecorder(), r, fs.State); err == nil {
		t.Error("篡改 payload 后仍然通过 —— HMAC 没起作用")
	}
}

// TestStateKeeper_ForeignKey 别的密钥签的 cookie 必须拒。
func TestStateKeeper_ForeignKey(t *testing.T) {
	mine := newTestKeeper(t, 10*time.Minute)
	other, _ := newStateKeeper("a-completely-different-secret", 10*time.Minute, "test_", "/cb/", false)

	fs, r := roundTrip(t, other, "/x")
	if _, err := mine.finish(httptest.NewRecorder(), r, fs.State); err == nil {
		t.Error("接受了用别的密钥签的状态 cookie")
	}
}

// TestStateKeeper_Expired 服务端必须自己判过期, 不能信 cookie 的 MaxAge。
func TestStateKeeper_Expired(t *testing.T) {
	k := newTestKeeper(t, -time.Second) // 一出生就过期
	fs, r := roundTrip(t, k, "/x")
	if _, err := k.finish(httptest.NewRecorder(), r, fs.State); err == nil {
		t.Error("过期的状态仍然通过 —— MaxAge 由浏览器执行, 服务端必须自己判")
	}
}

// TestStateKeeper_MultiTab 两个标签页同时登录, 各自的状态不能互相覆盖。
func TestStateKeeper_MultiTab(t *testing.T) {
	k := newTestKeeper(t, 10*time.Minute)

	w1, w2 := httptest.NewRecorder(), httptest.NewRecorder()
	fs1, err := k.begin(w1, "/anime/1")
	if err != nil {
		t.Fatal(err)
	}
	fs2, err := k.begin(w2, "/drama/2")
	if err != nil {
		t.Fatal(err)
	}

	// 浏览器会同时持有两个 cookie
	r := httptest.NewRequest(http.MethodGet, "/cb/callback", nil)
	for _, c := range append(w1.Result().Cookies(), w2.Result().Cookies()...) {
		r.AddCookie(c)
	}

	got1, err1 := k.finish(httptest.NewRecorder(), r, fs1.State)
	got2, err2 := k.finish(httptest.NewRecorder(), r, fs2.State)
	if err1 != nil || err2 != nil {
		t.Fatalf("多标签页回调失败: %v / %v", err1, err2)
	}
	if got1.Next != "/anime/1" || got2.Next != "/drama/2" {
		t.Errorf("两个标签页的状态串了: %q / %q\n"+
			"  cookie 名必须按 state 区分, 否则后发起的会覆盖先发起的", got1.Next, got2.Next)
	}
}

// TestStateKeeper_CookieAttributes cookie 属性直接决定几条防线成不成立。
func TestStateKeeper_CookieAttributes(t *testing.T) {
	k, _ := newStateKeeper("s", time.Minute, "test_", "/cb/", true)
	w := httptest.NewRecorder()
	if _, err := k.begin(w, "/x"); err != nil {
		t.Fatal(err)
	}
	c := w.Result().Cookies()[0]

	if !c.HttpOnly {
		t.Error("缺 HttpOnly —— XSS 可以直接读走 state 与 PKCE verifier")
	}
	if !c.Secure {
		t.Error("CookieSecure=true 时必须带 Secure —— 否则中间人能在明文 HTTP 上读到")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, 必须是 Lax", c.SameSite)
	}
	if c.Path != "/cb/" {
		t.Errorf("Path = %q, 应限定作用域", c.Path)
	}
}
