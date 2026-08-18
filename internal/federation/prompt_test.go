package federation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/bukahou/akasha/internal/account"
)

// TestUpstreamPrompt 往上游发什么 prompt (2026-08-18 定案 B)。
//
// 这个函数的行为直接决定用户【能不能换 Google 账号】——
// 返回空串或不带 prompt 时, 浏览器里登着单个 Google 账号会被静默返回,
// 用户连选择器都看不到。无会话定案宣称的"随时能换上游账号"就落不了地。
func TestUpstreamPrompt(t *testing.T) {
	cases := []struct {
		requested string
		want      string
		why       string
	}{
		{"", "select_account", "RP 没要求时也要给选择器 —— 这是默认带上的理由"},
		{"select_account", "select_account", "RP 要的就是它"},
		{"login", "login", "step-up: 要求重新证明身份, 比选账号更强"},
		{"login select_account", "login", "多值时取更强的那个"},
		{"consent", "select_account", "未识别的值不改变默认行为"},
		{"none", "select_account", "prompt=none 在 /authorize 就已被拒, 走不到这里"},
	}
	for _, c := range cases {
		if got := upstreamPrompt(c.requested); got != c.want {
			t.Errorf("upstreamPrompt(%q) = %q, 期望 %q —— %s", c.requested, got, c.want, c.why)
		}
	}

	// 绝不返回空串: 空串意味着不带 prompt 参数, 即静默返回上次那个账号
	for _, in := range []string{"", "consent", "garbage", "  "} {
		if upstreamPrompt(in) == "" {
			t.Errorf("upstreamPrompt(%q) 返回空串 —— 不带 prompt 会让上游静默返回单一账号", in)
		}
	}
}

// TestFailBack_PreservesNext 失败回登录页时必须把 next 带上。
//
// 不带的话: 用户在 Google 误点一次"取消" → 回到无 next 的登录页 → 再登成功
// 也只能落到"请从应用发起登录"的说明页, 必须回下游整个重来。
// 这条路径用户自己查不出问题在哪。
func TestFailBack_PreservesNext(t *testing.T) {
	const next = "/authorize?client_id=geass&response_type=code"

	w := httptest.NewRecorder()
	failBack(w, httptest.NewRequest(http.MethodGet, "/federation/google/callback", nil), "cancelled", next)

	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("回跳地址不是合法 URL: %q", loc)
	}
	if got := u.Query().Get("next"); got != next {
		t.Errorf("回跳丢了 next: 得到 %q, 期望 %q\n  用户重试成功后将无法回到原应用", got, next)
	}
	if got := u.Query().Get("error"); got != "cancelled" {
		t.Errorf("原因码 = %q, 期望 cancelled", got)
	}

	// 拿不到 next 时不应留下空参数
	w2 := httptest.NewRecorder()
	failBack(w2, httptest.NewRequest(http.MethodGet, "/x", nil), "state", "")
	if u2, _ := url.Parse(w2.Header().Get("Location")); u2.Query().Has("next") {
		t.Error("next 为空时仍写了 next= 参数")
	}
}

// TestRegistryNames_Sorted map 迭代顺序随机, 不排序则登录页按钮位置会随重启变化。
func TestRegistryNames_Sorted(t *testing.T) {
	reg := NewRegistry(stubProvider("google"), stubProvider("github"), stubProvider("apple"))
	got := reg.Names()
	want := []string{"apple", "github", "google"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names() = %v, 期望按字典序 %v —— 否则按钮顺序每次重启都可能变", got, want)
		}
	}
}

// stubProvider 只为测注册表, 不实现真实交互。
type stubProvider string

func (s stubProvider) Name() string                   { return string(s) }
func (s stubProvider) AuthCodeURL(AuthRequest) string { return "" }
func (s stubProvider) Exchange(context.Context, ExchangeRequest) (account.UpstreamIdentity, error) {
	return account.UpstreamIdentity{}, nil
}
