package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/bukahou/akasha/internal/account"
)

// 复用 state.go 里同款的解码方式, 免得测试自己再引一遍 encoding 包。
func b64Decode(s string) ([]byte, error)  { return base64.RawURLEncoding.DecodeString(s) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// callback 是整个登录流程里分支最多的一处: 上游取消 / state 失效 / 缺 code /
// 换票失败 / 账号被封 / 正常完成, 六条路各有各的归宿。此前完全没有测试 ——
// 而"归宿对不对"正是 2026-08-18 走查里问题最集中的地方 (取消丢 next、
// 封禁不回投都在这里)。
//
// 好消息是: 六条里有五条【走不到 account】, 因此不需要数据库。
// 只有"正常完成"与"账号被封"要真实用户, 那两条走 opt-in。

// fakeProvider 可控的上游: 想让它成功就给 identity, 想让它失败就给 err。
type fakeProvider struct {
	identity account.UpstreamIdentity
	err      error
	lastReq  ExchangeRequest // 记下收到了什么, 用于断言 verifier/nonce 确实传下去了
}

func (f *fakeProvider) Name() string                   { return "fake" }
func (f *fakeProvider) AuthCodeURL(AuthRequest) string { return "https://upstream.test/auth" }
func (f *fakeProvider) Exchange(_ context.Context, req ExchangeRequest) (account.UpstreamIdentity, error) {
	f.lastReq = req
	if f.err != nil {
		return account.UpstreamIdentity{}, f.err
	}
	return f.identity, nil
}

// spyBridge 记录 op 侧被怎么调用 —— 认证的最终归宿就体现在这两个回调上。
type spyBridge struct {
	completed []int64  // Complete 拿到的 userID
	denied    []string // Deny 拿到的 errCode
	lastNext  string
}

func (s *spyBridge) bridge() OPBridge {
	return OPBridge{
		Complete: func(_ http.ResponseWriter, _ *http.Request, next string, userID int64) {
			s.completed = append(s.completed, userID)
			s.lastNext = next
		},
		Deny: func(_ http.ResponseWriter, _ *http.Request, next, errCode, _ string) {
			s.denied = append(s.denied, errCode)
			s.lastNext = next
		},
		SafeNext: func(n string) bool { return strings.HasPrefix(n, "/authorize?") },
		Prompt:   func(string) string { return "" },
	}
}

// fedFixture 一套可用的 handler + 走完 start 拿到的 state/cookie。
type fedFixture struct {
	mux      *http.ServeMux
	provider *fakeProvider
	spy      *spyBridge
	state    string
	cookies  []*http.Cookie
}

func newFedFixture(t *testing.T, accounts *account.Service) *fedFixture {
	t.Helper()
	provider := &fakeProvider{}
	spy := &spyBridge{}
	keeper, err := NewStateKeeper("test-salt-not-a-real-secret", 10*time.Minute, false)
	if err != nil {
		t.Fatalf("构造 StateKeeper 失败: %v", err)
	}
	mux := http.NewServeMux()
	NewHandler(NewRegistry(provider), accounts, keeper, spy.bridge()).Register(mux)

	// 走一遍 start, 拿到 state 与 cookie —— 与真实浏览器同样的往返
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/federation/fake/start?next="+url.QueryEscape("/authorize?client_id=geass"), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("start 返回 %d, 期望 302", w.Code)
	}
	f := &fedFixture{mux: mux, provider: provider, spy: spy, cookies: w.Result().Cookies()}
	if len(f.cookies) == 0 {
		t.Fatal("start 没有设置联邦状态 cookie")
	}
	// cookie 名是 akasha_fed_ + state 前 8 位; state 本身要从 Location 之外拿 ——
	// 这里直接解出保存在 cookie 里的那个
	f.state = f.stateFromCookie(t)
	return f
}

func (f *fedFixture) stateFromCookie(t *testing.T) string {
	t.Helper()
	// cookie 值是 base64(payload).sig, payload 里就有 state
	for _, c := range f.cookies {
		payload, _, ok := strings.Cut(c.Value, ".")
		if !ok {
			continue
		}
		raw, err := b64Decode(payload)
		if err != nil {
			continue
		}
		var fs flowState
		if err := jsonUnmarshal(raw, &fs); err == nil && fs.State != "" {
			return fs.State
		}
	}
	t.Fatal("无法从 cookie 中取出 state")
	return ""
}

// callback 发起一次回调请求, 带上 start 阶段拿到的 cookie。
func (f *fedFixture) callback(query string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/federation/fake/callback?"+query, nil)
	for _, c := range f.cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

func locationOf(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("回跳地址不是合法 URL: %q", w.Header().Get("Location"))
	}
	return u
}

// TestCallback_UpstreamCancel ⭐ 用户取消 → 回登录页且【保住 next】。
func TestCallback_UpstreamCancel(t *testing.T) {
	f := newFedFixture(t, nil)

	w := f.callback("error=access_denied&state=" + f.state)
	u := locationOf(t, w)

	if u.Path != "/login" {
		t.Errorf("回跳到 %s, 期望 /login", u.Path)
	}
	if u.Query().Get("error") != "cancelled" {
		t.Errorf("原因码 = %q, 期望 cancelled", u.Query().Get("error"))
	}
	if next := u.Query().Get("next"); !strings.Contains(next, "client_id=geass") {
		t.Errorf("next = %q, 期望保住停车的授权请求\n"+
			"  丢了它, 用户重试成功后也回不到原应用", next)
	}
	if len(f.spy.completed) != 0 {
		t.Error("取消却调用了 Complete —— 未认证的人拿到了授权码")
	}
}

// TestCallback_StateFailure state 校验失败无处可回, 留在本站是对的。
func TestCallback_StateFailure(t *testing.T) {
	f := newFedFixture(t, nil)

	// 用一个对不上的 state (cookie 里那个是另一个值)
	w := f.callback("code=xyz&state=totally-different-state")
	u := locationOf(t, w)

	if u.Query().Get("error") != "state" {
		t.Errorf("原因码 = %q, 期望 state", u.Query().Get("error"))
	}
	if u.Query().Has("next") {
		t.Error("state 失效时不该带 next —— 上下文本身就丢了, 那个值不可信")
	}
	if len(f.spy.completed) != 0 {
		t.Error("state 校验失败却调用了 Complete —— CSRF 防线失效")
	}
}

// TestCallback_MissingCode 上游没给 code。
func TestCallback_MissingCode(t *testing.T) {
	f := newFedFixture(t, nil)

	u := locationOf(t, f.callback("state="+f.state))
	if u.Query().Get("error") != "upstream" {
		t.Errorf("原因码 = %q, 期望 upstream", u.Query().Get("error"))
	}
	if !strings.Contains(u.Query().Get("next"), "client_id=geass") {
		t.Error("缺 code 时应保住 next —— 这是可重试的失败")
	}
}

// TestCallback_ExchangeFailure 换票失败同样可重试, next 要留着。
func TestCallback_ExchangeFailure(t *testing.T) {
	f := newFedFixture(t, nil)
	f.provider.err = errors.New("上游 500")

	u := locationOf(t, f.callback("code=xyz&state="+f.state))
	if u.Query().Get("error") != "upstream" {
		t.Errorf("原因码 = %q, 期望 upstream", u.Query().Get("error"))
	}
	if !strings.Contains(u.Query().Get("next"), "client_id=geass") {
		t.Error("换票失败时应保住 next")
	}
}

// TestCallback_PassesPKCEAndNonce ⭐ verifier 与 nonce 必须真的传给 provider。
//
// 它们生成在 start、保管在签名 cookie、使用在 callback —— 中间隔着一整个
// 上游往返。传丢了不会报错: 上游照样返回 token, 只是 PKCE 与重放校验双双失效。
func TestCallback_PassesPKCEAndNonce(t *testing.T) {
	f := newFedFixture(t, nil)
	f.provider.err = errors.New("到此为止即可, 我们只看它收到了什么")

	f.callback("code=xyz&state=" + f.state)

	if f.provider.lastReq.Code != "xyz" {
		t.Errorf("provider 收到的 code = %q", f.provider.lastReq.Code)
	}
	if f.provider.lastReq.Verifier == "" {
		t.Error("provider 没收到 verifier —— 上游侧 PKCE 静默失效")
	}
	if f.provider.lastReq.Nonce == "" {
		t.Error("provider 没收到 nonce —— id_token 重放校验静默失效")
	}
}

// TestCallback_UnknownProvider 未注册的上游返回 404, 不进任何后续逻辑。
func TestCallback_UnknownProvider(t *testing.T) {
	f := newFedFixture(t, nil)

	r := httptest.NewRequest(http.MethodGet, "/federation/nonexistent/callback?code=x", nil)
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("未注册的 provider 返回 %d, 期望 404", w.Code)
	}
}

// ---- 以下两条需要真实用户, 因此需要数据库 (opt-in, 同 account/op 两包的模式) ----
//
//	AKASHA_TEST_DB_DSN="$AKASHA_DB_DSN" go test ./internal/federation/ -run Callback

func accountsForTest(t *testing.T) (*account.Service, *gorm.DB) {
	t.Helper()
	dsn := os.Getenv("AKASHA_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("未设置 AKASHA_TEST_DB_DSN, 跳过需要数据库的测试")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("连接测试数据库失败: %v", err)
	}
	return account.NewService(account.NewRepository(db)), db
}

// upstreamFor 造一个本次运行独有的上游身份, 并登记清理。
func upstreamFor(t *testing.T, db *gorm.DB) account.UpstreamIdentity {
	t.Helper()
	subject := fmt.Sprintf("fed-cb-%d", time.Now().UnixNano())
	id := account.UpstreamIdentity{
		Provider: "fake", Subject: subject,
		Email: subject + "@example.test", EmailVerified: true, Name: "Callback Test",
	}
	internalID := account.DeriveInternalID(id.Provider, id.Subject)
	t.Cleanup(func() {
		db.Exec("DELETE fi FROM federated_identities fi JOIN users u ON fi.user_id = u.id WHERE u.internal_id = ?", internalID)
		db.Exec("DELETE FROM users WHERE internal_id = ?", internalID)
	})
	return id
}

// TestCallback_Success ⭐ 认证成功 → 调 Complete, 并把停车的 next 原样交回去。
func TestCallback_Success(t *testing.T) {
	accounts, db := accountsForTest(t)
	f := newFedFixture(t, accounts)
	f.provider.identity = upstreamFor(t, db)

	f.callback("code=xyz&state=" + f.state)

	if len(f.spy.completed) != 1 {
		t.Fatalf("Complete 被调用 %d 次, 期望 1 次", len(f.spy.completed))
	}
	if f.spy.completed[0] == 0 {
		t.Error("Complete 拿到的 user_id 是 0 —— 身份裁决没落实")
	}
	if !strings.Contains(f.spy.lastNext, "client_id=geass") {
		t.Errorf("Complete 拿到的 next = %q, 期望是停车的那个授权请求", f.spy.lastNext)
	}
	if len(f.spy.denied) != 0 {
		t.Error("成功路径却调用了 Deny")
	}
}

// TestCallback_BannedGoesBackToRP ⭐ 账号被封 → 按规范回投 access_denied 给 RP。
//
// 重试没有意义, 换个 provider 也进不去 —— 把人留在 akasha 的裸页面上,
// RP 永远不知道发生了什么。
func TestCallback_BannedGoesBackToRP(t *testing.T) {
	accounts, db := accountsForTest(t)
	f := newFedFixture(t, accounts)
	id := upstreamFor(t, db)
	f.provider.identity = id

	// 先建号, 再封禁
	u, err := accounts.ResolveUpstreamIdentity(context.Background(), id)
	if err != nil {
		t.Fatalf("预置用户失败: %v", err)
	}
	if err := db.Table("users").Where("id = ?", u.ID).
		Update("status", account.StatusBanned).Error; err != nil {
		t.Fatalf("封禁失败: %v", err)
	}

	f.callback("code=xyz&state=" + f.state)

	if len(f.spy.denied) != 1 || f.spy.denied[0] != "access_denied" {
		t.Errorf("Deny 调用情况 = %v, 期望恰好一次 access_denied\n"+
			"  留在 akasha 的裸页面上, RP 永远不知道发生了什么", f.spy.denied)
	}
	if len(f.spy.completed) != 0 {
		t.Error("⚠️ 被封禁的账号仍然拿到了授权码")
	}
	if !strings.Contains(f.spy.lastNext, "client_id=geass") {
		t.Errorf("Deny 拿到的 next = %q, 回投需要它才知道往哪送", f.spy.lastNext)
	}
}
