package federation

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testSalt = "test-salt-not-for-production"

func newKeeper(t *testing.T, ttl time.Duration) *StateKeeper {
	t.Helper()
	k, err := NewStateKeeper(testSalt, ttl, false)
	if err != nil {
		t.Fatalf("构造 StateKeeper 失败: %v", err)
	}
	return k
}

// begin 走一遍 Begin 并把产生的 cookie 装进一个新请求, 模拟浏览器的往返。
func begin(t *testing.T, k *StateKeeper, next string) (state string, r *http.Request) {
	t.Helper()
	w := httptest.NewRecorder()
	fs, err := k.Begin(w, next)
	if err != nil {
		t.Fatalf("Begin 失败: %v", err)
	}
	state = fs.State
	r = httptest.NewRequest("GET", "/federation/google/callback", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	return state, r
}

func TestStateKeeper_RoundTrip(t *testing.T) {
	k := newKeeper(t, 10*time.Minute)
	const next = "/authorize?client_id=geass&state=x"

	state, r := begin(t, k, next)
	fs, err := k.Finish(httptest.NewRecorder(), r, state)
	if err != nil {
		t.Fatalf("正常往返失败: %v", err)
	}
	if fs.Next != next {
		t.Errorf("next = %q, 期望 %q", fs.Next, next)
	}
	if fs.Nonce == "" {
		t.Error("nonce 为空 —— 上游 id_token 的重放校验会失去依据")
	}
	if len(state) != 64 {
		t.Errorf("state 长度 = %d, 期望 64 (32 字节 hex)", len(state))
	}
}

// TestStateKeeper_RejectsMissingCookie 这是登录 CSRF 的核心防线。
//
// 攻击者用自己的账号走完上游授权, 拿到回调 URL 但不访问, 转而诱导受害者点击。
// 受害者的浏览器里【没有】对应的 cookie —— 若此处放行, 受害者就会被登入
// 攻击者的账号, 此后上传的内容全进了攻击者账号。
//
// 关键: 光验"这个 state 是我发过的"没用, 攻击者的 state 也是本服务发的、
// 签名也合法。必须验"这个 state 是【这个浏览器】发起时拿到的"。
func TestStateKeeper_RejectsMissingCookie(t *testing.T) {
	k := newKeeper(t, 10*time.Minute)

	w := httptest.NewRecorder()
	fs, err := k.Begin(w, "/authorize?x=1")
	if err != nil {
		t.Fatalf("Begin 失败: %v", err)
	}
	state := fs.State

	// 受害者浏览器: 有攻击者给的 state, 但没有任何 cookie
	victim := httptest.NewRequest("GET", "/federation/google/callback", nil)
	if _, err := k.Finish(httptest.NewRecorder(), victim, state); err == nil {
		t.Fatal("无 cookie 时放行 —— 登录 CSRF 防线失效, 用户可被塞进攻击者账号")
	}
}

func TestStateKeeper_RejectsTampering(t *testing.T) {
	k := newKeeper(t, 10*time.Minute)

	t.Run("篡改 payload 后签名失效", func(t *testing.T) {
		w := httptest.NewRecorder()
		begun, err := k.Begin(w, "/authorize?x=1")
		if err != nil {
			t.Fatalf("Begin 失败: %v", err)
		}
		state := begun.State
		orig := w.Result().Cookies()[0]

		// 把 next 改成钓鱼站, 签名照抄
		payload, sig, _ := strings.Cut(orig.Value, ".")
		raw, err := base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			t.Fatalf("解码失败: %v", err)
		}
		var fs flowState
		if err := json.Unmarshal(raw, &fs); err != nil {
			t.Fatalf("反序列化失败: %v", err)
		}
		fs.Next = "https://evil.test/steal"
		mutated, _ := json.Marshal(fs)
		tampered := base64.RawURLEncoding.EncodeToString(mutated) + "." + sig

		r := httptest.NewRequest("GET", "/federation/google/callback", nil)
		r.AddCookie(&http.Cookie{Name: orig.Name, Value: tampered})
		if _, err := k.Finish(httptest.NewRecorder(), r, state); err == nil {
			t.Fatal("篡改 next 后仍被接受 —— 用户会被送去钓鱼站")
		}
	})

	t.Run("state 与 cookie 不匹配", func(t *testing.T) {
		_, r1 := begin(t, k, "/authorize?a=1")
		state2, _ := begin(t, k, "/authorize?b=2")
		// 用流程①的 cookie 配流程②的 state
		if _, err := k.Finish(httptest.NewRecorder(), r1, state2); err == nil {
			t.Fatal("state 与 cookie 不匹配却被接受")
		}
	})

	t.Run("另一把密钥签的 cookie 被拒", func(t *testing.T) {
		other := newKeeper(t, 10*time.Minute)
		w := httptest.NewRecorder()
		fs, err := other.Begin(w, "/authorize?x=1")
		if err != nil {
			t.Fatalf("Begin 失败: %v", err)
		}
		state := fs.State
		_ = state
		// 换个 salt 派生出的密钥
		k2, err := NewStateKeeper("completely-different-salt", 10*time.Minute, false)
		if err != nil {
			t.Fatalf("构造失败: %v", err)
		}
		r := httptest.NewRequest("GET", "/federation/google/callback", nil)
		for _, c := range w.Result().Cookies() {
			r.AddCookie(c)
		}
		if _, err := k2.Finish(httptest.NewRecorder(), r, state); err == nil {
			t.Fatal("其他密钥签的 cookie 被接受 —— HMAC 未真正生效")
		}
	})
}

// TestStateKeeper_RejectsExpired cookie 的 Max-Age 由浏览器执行, 服务端不能信 ——
// 攻击者可以自己保留一份过期的 cookie 继续发送。
func TestStateKeeper_RejectsExpired(t *testing.T) {
	k := newKeeper(t, -time.Second) // 构造出立即过期的状态

	state, r := begin(t, k, "/authorize?x=1")
	if _, err := k.Finish(httptest.NewRecorder(), r, state); err == nil {
		t.Fatal("过期状态被接受 —— 服务端未独立校验 exp, 只依赖浏览器的 Max-Age")
	}
}

// TestStateKeeper_MultiTab 用户同时在两个标签页登录不同应用。
//
// cookie 名若固定, 后发起的会覆盖先发起的, 先那个回调时就找不到自己的状态。
// 名字带 state 前缀才能让多个流程并存。
func TestStateKeeper_MultiTab(t *testing.T) {
	k := newKeeper(t, 10*time.Minute)

	w1, w2 := httptest.NewRecorder(), httptest.NewRecorder()
	beginFS1, err := k.Begin(w1, "/authorize?client_id=geass")
	if err != nil {
		t.Fatalf("Begin 失败: %v", err)
	}
	state1 := beginFS1.State
	beginFS2, err := k.Begin(w2, "/authorize?client_id=atlhyper")
	if err != nil {
		t.Fatalf("Begin 失败: %v", err)
	}
	state2 := beginFS2.State

	c1, c2 := w1.Result().Cookies()[0], w2.Result().Cookies()[0]
	if c1.Name == c2.Name {
		t.Fatalf("两个流程用了同名 cookie (%s) —— 后者会覆盖前者", c1.Name)
	}

	// 浏览器会同时持有两个 cookie, 两个回调都应各自成功
	r := httptest.NewRequest("GET", "/federation/google/callback", nil)
	r.AddCookie(c1)
	r.AddCookie(c2)

	fs1, err := k.Finish(httptest.NewRecorder(), r, state1)
	if err != nil {
		t.Fatalf("标签页①的回调失败: %v", err)
	}
	fs2, err := k.Finish(httptest.NewRecorder(), r, state2)
	if err != nil {
		t.Fatalf("标签页②的回调失败: %v", err)
	}
	if !strings.Contains(fs1.Next, "geass") || !strings.Contains(fs2.Next, "atlhyper") {
		t.Errorf("两个流程的 next 串了: %q / %q", fs1.Next, fs2.Next)
	}
}

// TestStateKeeper_CookieAttributes cookie 属性本身就是防护的一部分。
func TestStateKeeper_CookieAttributes(t *testing.T) {
	k := newKeeper(t, 10*time.Minute)
	w := httptest.NewRecorder()
	if _, err := k.Begin(w, "/authorize?x=1"); err != nil {
		t.Fatalf("Begin 失败: %v", err)
	}
	c := w.Result().Cookies()[0]

	if !c.HttpOnly {
		t.Error("缺 HttpOnly —— XSS 可读走联邦状态")
	}
	if c.SameSite != http.SameSiteLaxMode {
		// Strict 会掐掉从上游跳回时的 cookie, 联邦登录直接失效;
		// None 则放宽到任意跨站请求
		t.Errorf("SameSite = %v, 必须是 Lax", c.SameSite)
	}
	if c.Path != "/federation/" {
		t.Errorf("Path = %q, 应限定在 /federation/ 以免污染其他请求", c.Path)
	}
	if c.MaxAge <= 0 {
		t.Error("未设置 MaxAge —— 废弃的状态 cookie 会一直堆在浏览器里")
	}
}

// TestNewStateKeeper_DerivesKey 密钥由 pairwise salt 派生, 而非直接复用。
// 派生后两个用途的密钥数学上独立: 即便 cookie 密钥泄漏也反推不回 salt。
func TestNewStateKeeper_DerivesKey(t *testing.T) {
	k, err := NewStateKeeper(testSalt, time.Minute, false)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if string(k.key) == testSalt {
		t.Fatal("直接使用了 salt 作为 HMAC 密钥, 未经派生")
	}
	if len(k.key) != 32 {
		t.Errorf("派生密钥长度 = %d, 期望 32", len(k.key))
	}

	// 同一个 salt 必须派生出同一把密钥, 否则重启后进行中的登录全部失效
	k2, _ := NewStateKeeper(testSalt, time.Minute, false)
	if string(k.key) != string(k2.key) {
		t.Error("同一 salt 派生出不同密钥 —— 派生不是确定性的")
	}
}
