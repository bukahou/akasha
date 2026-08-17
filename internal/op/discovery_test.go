package op

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bukahou/akasha/internal/account"
	"github.com/golang-jwt/jwt/v5"
)

// discovery 文档是 RP 自动配置的唯一入口 —— 它声明什么, 对方就按什么行事。
//
// # 为什么这些断言值得写死
//
// 2026-08-17 的审计复盘发现: 首轮审计判「协议完整性」时靠的是人工通读,
// 结果漏掉了 userinfo / end_session 两个端点的缺失。人通读会漏,
// 而"声明了什么"与"实现了什么"这两件事本来就可以机器比对。
//
// 这里的三类断言分别防三种事故:
//
//	① 缺 REQUIRED 字段     → 守规范的 RP 直接拒绝配置
//	② 声明了但没实现       → RP 调到 404, 在真实用户面前暴露
//	③ 实现了但没声明       → 白做, 守规范的 RP 根本不会来调
const testIssuer = "https://akasha.test"

func fetchDiscovery(t *testing.T) map[string]any {
	t.Helper()

	h := &Handler{issuer: testIssuer}
	w := httptest.NewRecorder()
	h.discovery(w, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("discovery 返回 %d, 期望 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("discovery Content-Type = %q, 期望 application/json", ct)
	}

	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("discovery 不是合法 JSON: %v", err)
	}
	return doc
}

// TestDiscovery_RequiredFields OIDC Discovery 1.0 §3 列为 REQUIRED 的字段。
// 缺任何一个, 严格的 RP 会拒绝把 akasha 配置成 provider。
func TestDiscovery_RequiredFields(t *testing.T) {
	doc := fetchDiscovery(t)

	for _, f := range []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	} {
		if _, ok := doc[f]; !ok {
			t.Errorf("缺少 REQUIRED 字段 %q (OIDC Discovery 1.0 §3)", f)
		}
	}

	// issuer 必须与请求它的地址一致 —— RP 会拿它跟 id_token 的 iss 比对
	if doc["issuer"] != testIssuer {
		t.Errorf("issuer = %v, 期望 %q", doc["issuer"], testIssuer)
	}
}

// endpointFields discovery 里声明端点 URL 的字段 → 访问它该用的方法。
// 表里的字段不一定都存在 (可选端点), 存在才检查。
var endpointFields = map[string]string{
	"authorization_endpoint": http.MethodGet,
	"token_endpoint":         http.MethodPost,
	"jwks_uri":               http.MethodGet,
	"userinfo_endpoint":      http.MethodGet,
	"end_session_endpoint":   http.MethodGet,
}

// TestDiscovery_DeclaredEndpointsAreRouted 声明的每个端点都必须真的能路由到。
//
// 路径从 discovery 声明的 URL 里现取, 不写死 —— 改了 discovery 里的路径
// 却忘了改 Register, 这条会红。
func TestDiscovery_DeclaredEndpointsAreRouted(t *testing.T) {
	doc := fetchDiscovery(t)
	mux := registeredMux()

	for field, method := range endpointFields {
		raw, ok := doc[field].(string)
		if !ok {
			continue // 可选端点未声明
		}

		u, err := url.Parse(raw)
		if err != nil {
			t.Errorf("%s = %q 不是合法 URL: %v", field, raw, err)
			continue
		}
		if !strings.HasPrefix(raw, testIssuer+"/") {
			t.Errorf("%s = %q 不在 issuer %q 之下 —— 端点必须同源", field, raw, testIssuer)
		}

		req := httptest.NewRequest(method, u.Path, nil)
		if _, pattern := mux.Handler(req); pattern == "" {
			t.Errorf("discovery 声明了 %s = %q, 但 %s %s 没有注册路由 —— RP 会调到 404",
				field, raw, method, u.Path)
		}
	}
}

// TestDiscovery_RoutedEndpointsAreDeclared 反向: 实现了却没声明等于白做。
//
// 守规范的 RP 只用 discovery 里出现过的端点。userinfo / end_session
// 就是上次漏掉的那两个 —— 实现补上后如果忘了声明, 通用 RP 依然用不到。
func TestDiscovery_RoutedEndpointsAreDeclared(t *testing.T) {
	doc := fetchDiscovery(t)
	mux := registeredMux()

	// 路由存在 → 必须有对应的 discovery 字段
	routeToField := map[string]string{
		"/authorize":   "authorization_endpoint",
		"/token":       "token_endpoint",
		"/jwks":        "jwks_uri",
		"/userinfo":    "userinfo_endpoint",
		"/end_session": "end_session_endpoint",
	}

	for path, field := range routeToField {
		method := endpointFields[field]
		req := httptest.NewRequest(method, path, nil)
		if _, pattern := mux.Handler(req); pattern == "" {
			continue // 未实现就不必声明
		}
		if _, declared := doc[field]; !declared {
			t.Errorf("已实现 %s %s 但 discovery 未声明 %s —— 守规范的 RP 不会来调",
				method, path, field)
		}
	}
}

// TestDiscovery_SubjectTypeMatchesImplementation 声明 pairwise 就必须真的是 pairwise。
//
// 这条声明决定了下游会不会假设"同一个人在各应用 sub 相同"。声明与实现不符时,
// 下游的账号关联逻辑会静默出错 —— 不报错, 只是认错人。
func TestDiscovery_SubjectTypeMatchesImplementation(t *testing.T) {
	doc := fetchDiscovery(t)

	types, ok := doc["subject_types_supported"].([]any)
	if !ok || len(types) == 0 {
		t.Fatal("subject_types_supported 缺失或不是数组")
	}
	if types[0] != "pairwise" {
		t.Fatalf("声明的 subject type 是 %v, 期望 pairwise", types[0])
	}

	const internalID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if PairwiseSub("app-a", internalID, "salt") == PairwiseSub("app-b", internalID, "salt") {
		t.Error("声明了 pairwise, 但两个 client 算出相同的 sub —— 声明与实现不符")
	}
}

// TestDiscovery_AlgAndPKCEMatchImplementation 算法与 PKCE 方法的声明不能是空话。
func TestDiscovery_AlgAndPKCEMatchImplementation(t *testing.T) {
	doc := fetchDiscovery(t)

	// 全项目只签 RS256 (keys.Manager.SignClaims 写死)。声明别的 = 骗 RP
	assertOnlyValue(t, doc, "id_token_signing_alg_values_supported", "RS256")
	// ParseAuthorizeRequest 只接受 S256, plain 一律拒
	assertOnlyValue(t, doc, "code_challenge_methods_supported", "S256")
	// 只实现了 code 流
	assertOnlyValue(t, doc, "response_types_supported", "code")
}

func assertOnlyValue(t *testing.T, doc map[string]any, field, want string) {
	t.Helper()
	vals, ok := doc[field].([]any)
	if !ok {
		t.Errorf("%s 缺失或不是数组", field)
		return
	}
	if len(vals) != 1 || vals[0] != want {
		t.Errorf("%s = %v, 实现只支持 [%s]", field, vals, want)
	}
}

// TestDiscovery_ClaimsSupportedAreActuallyIssued 声明能给的 claim 必须真的会写进 token。
//
// # 这条测试改过一次实现, 值得记下来
//
// 最初是扫 issueTokens 的源码找字符串字面量。A6/A7 把 claims 组装拆成三个纯函数后,
// 它连红两次 —— 每次都得回来补扫描范围。那不是被抓到了 bug, 是【检查方式本身脆弱】:
// 它盯的是代码长什么样, 而不是代码干了什么。
//
// 现在直接调用签发路径的纯函数, 拿它们【实际产出】的 claim 全集来比对。
// 重构随便怎么搬, 只要行为不变这条就不会误报。
func TestDiscovery_ClaimsSupportedAreActuallyIssued(t *testing.T) {
	doc := fetchDiscovery(t)
	claims, ok := doc["claims_supported"].([]any)
	if !ok {
		t.Skip("未声明 claims_supported")
	}

	issued := issuableClaims()
	for _, c := range claims {
		name, _ := c.(string)
		if !issued[name] {
			t.Errorf("discovery 声明了 claim %q, 但签发路径实际不会产出它 —— RP 会白等这个字段\n"+
				"  实际能产出: %v", name, keysOfBool(issued))
		}
	}
}

// TestDiscovery_IssuedClaimsAreDeclared 反向: 发了却没声明。
//
// 守规范的 RP 会照着 claims_supported 决定要不要开某个功能; 发了不声明等于白发。
func TestDiscovery_IssuedClaimsAreDeclared(t *testing.T) {
	doc := fetchDiscovery(t)
	declared := map[string]bool{}
	if claims, ok := doc["claims_supported"].([]any); ok {
		for _, c := range claims {
			name, _ := c.(string)
			declared[name] = true
		}
	}

	for name := range issuableClaims() {
		// scope 是 access_token 的授权元数据, 不是身份 claim, 不进 claims_supported
		if name == "scope" {
			continue
		}
		if !declared[name] {
			t.Errorf("签发路径会产出 claim %q, 但 discovery 未声明 —— 守规范的 RP 不会来取", name)
		}
	}
}

// issuableClaims 走一遍签发路径, 收集在【最宽 scope】下能产出的全部 claim。
func issuableClaims() map[string]bool {
	base := jwt.MapClaims{
		"iss": testIssuer,
		"sub": "pairwise-sub-value",
		"iat": int64(1700000000),
	}
	u := &account.User{
		Email: "someone@example.com", EmailVerified: true,
		Name: "Some One", Username: "someone", AvatarURL: "https://example.com/a.png",
	}
	g := tokenGrant{ClientID: "some-client", Nonce: "n0nce", Scope: "openid email profile"}
	now := time.Unix(1700000000, 0)

	out := map[string]bool{}
	for k := range idTokenClaims(base, u, g, now, now) {
		out[k] = true
	}
	for k := range accessTokenClaims(base, g, testIssuer, now) {
		out[k] = true
	}
	// at_hash 由 issueTokens 在签完 access_token 之后补上 (它依赖签名结果, 无法在纯函数里算)
	out["at_hash"] = true
	return out
}

func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestIdentityClaims_ScopeDispatch 按 scope 分发的行为契约 (A7, 2026-08-17 定案)。
//
// 这条直接对着 OIDC Core §5.4 的 scope→claims 映射写。分发错了不会报错,
// 只会让 RP 收到它没申请的 PII (或收不到它申请了的字段)。
func TestIdentityClaims_ScopeDispatch(t *testing.T) {
	u := &account.User{
		Email:         "someone@example.com",
		EmailVerified: true,
		Name:          "Some One",
		Username:      "someone",
		AvatarURL:     "https://example.com/a.png",
	}

	cases := []struct {
		scope string
		want  []string // 期望出现的 claim (sub 由调用方补, 不在此函数职责内)
	}{
		{"openid", nil},
		{"openid email", []string{"email", "email_verified"}},
		{"openid profile", []string{"name", "preferred_username", "picture"}},
		{"openid email profile", []string{"email", "email_verified", "name", "preferred_username", "picture"}},
		// 无法识别的 scope 忽略即可 (RFC 6749 §3.3 允许), 不得因此少发或报错
		{"openid email address phone", []string{"email", "email_verified"}},
		// 子串不算命中: "emailx" 不是 email
		{"openid emailx profilez", nil},
	}

	for _, c := range cases {
		got := identityClaims(u, c.scope)
		if len(got) != len(c.want) {
			t.Errorf("scope=%q: 发了 %d 个 claim %v, 期望 %d 个 %v",
				c.scope, len(got), keysOf(got), len(c.want), c.want)
			continue
		}
		for _, w := range c.want {
			if _, ok := got[w]; !ok {
				t.Errorf("scope=%q: 缺少 claim %q", c.scope, w)
			}
		}
	}
}

// TestIdentityClaims_NeverLeaksInternalID 最要紧的一条: 分发逻辑不得漏出内部标识。
//
// pairwise 的全部价值就在于下游拿不到可关联的标识。这里把 User 的内部字段
// 填成显眼的值, 断言它们不出现在任何 claim 里。
func TestIdentityClaims_NeverLeaksInternalID(t *testing.T) {
	const marker = "LEAKED-INTERNAL-VALUE"
	u := &account.User{
		ID:         999,
		InternalID: marker,
		Email:      "someone@example.com",
		Name:       "Some One",
		Username:   "someone",
	}

	for _, scope := range []string{"openid", "openid email", "openid email profile"} {
		for k, v := range identityClaims(u, scope) {
			if s, ok := v.(string); ok && strings.Contains(s, marker) {
				t.Errorf("scope=%q: claim %q 漏出了 internal_id —— pairwise 立刻破功", scope, k)
			}
			if n, ok := v.(int64); ok && n == u.ID {
				t.Errorf("scope=%q: claim %q 漏出了 users.id", scope, k)
			}
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func registeredMux() *http.ServeMux {
	mux := http.NewServeMux()
	// Register 只取方法值挂到 mux 上, 不调用它们, 所以零值 Handler 足够
	(&Handler{}).Register(mux)
	return mux
}

// TestAccessTokenClaims_NoIdentityClaims ⭐ A6 定案的守门人。
//
// access_token 的 claim 集合是【白名单】而非黑名单 —— 断言"只有这些"而不是
// "没有 email"。理由: 将来往 base 里加字段时, 黑名单不会红, 白名单会。
// 这正是 2026-08-17 变异测试暴露的缺口 (当时把 email 加回 access_token, 无人察觉)。
func TestAccessTokenClaims_NoIdentityClaims(t *testing.T) {
	got := accessTokenClaims(testBase(), testGrant(), testIssuer, time.Unix(1700003600, 0))

	allowed := map[string]bool{
		"iss": true, "sub": true, "aud": true, "azp": true, "iat": true, "exp": true,
		"scope": true, // /userinfo 的唯一输入; 非身份信息
	}
	for k := range got {
		if !allowed[k] {
			t.Errorf("access_token 出现了未经批准的 claim %q\n"+
				"  它的 TTL 是 id_token 的 6 倍, 且会被发往资源服务器。\n"+
				"  身份信息应当走 id_token 或 /userinfo (见 A6 定案)", k)
		}
	}
	// scope 必须原样带上, 否则 /userinfo 无从判断该返回什么
	if got["scope"] != "openid email profile" {
		t.Errorf("access_token 的 scope = %v, 期望原样携带", got["scope"])
	}
}

// TestTokenAudiences 两张票的 aud 语义不同 —— 这是 A6 第二部分的核心。
//
// aud 回答"能拿去哪里用", azp 回答"发给了谁"。access_token 的 aud 一旦退回
// client_id, /userinfo 的 aud 校验就形同虚设 (任何 client 的票都能通过)。
func TestTokenAudiences(t *testing.T) {
	g := testGrant()
	now := time.Unix(1700000000, 0)

	at := accessTokenClaims(testBase(), g, testIssuer, now)
	if at["aud"] != testIssuer {
		t.Errorf("access_token 的 aud = %v, 期望资源服务器标识 %q", at["aud"], testIssuer)
	}
	if at["aud"] == g.ClientID {
		t.Error("access_token 的 aud 退回成了 client_id —— /userinfo 的 aud 校验会失去意义")
	}
	if at["azp"] != g.ClientID {
		t.Errorf("access_token 的 azp = %v, 期望 client_id %q —— /userinfo 靠它反查 pairwise 映射",
			at["azp"], g.ClientID)
	}

	// id_token 的 aud 【必须】是 client_id: OIDC Core §2 的 REQUIRED 规定。
	// 跟着 access_token 一起改会让所有守规范的 RP 拒绝验证。
	it := idTokenClaims(testBase(), &account.User{}, g, now, now)
	if it["aud"] != g.ClientID {
		t.Errorf("id_token 的 aud = %v, 期望 client_id %q (OIDC Core §2 REQUIRED)",
			it["aud"], g.ClientID)
	}
}

func testBase() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": testIssuer,
		"sub": "pairwise-sub-value",
		"iat": int64(1700000000),
	}
}

// testUser 各测试共用的用户样本, 字段值刻意可辨认。
var testUser = account.User{
	Email: "someone@example.com", EmailVerified: true,
	Name: "Some One", Username: "someone", AvatarURL: "https://example.com/a.png",
}

func testGrant() tokenGrant {
	return tokenGrant{ClientID: "some-client", Nonce: "n0nce", Scope: "openid email profile"}
}

// TestIDTokenClaims_NonceOnlyOnAuthentication nonce 只应出现在真实认证那一次。
func TestIDTokenClaims_NonceOnlyOnAuthentication(t *testing.T) {
	base := jwt.MapClaims{"iss": "i", "sub": "s", "iat": int64(1)}
	u := &account.User{Name: "n", Username: "un"}
	now := time.Unix(1700000000, 0)

	withNonce := idTokenClaims(base, u, tokenGrant{ClientID: "c", Nonce: "n0nce", Scope: "openid"}, now, now)
	if withNonce["nonce"] != "n0nce" {
		t.Errorf("code 兑换时 nonce 未回显, 得到 %v —— RP 的重放校验会失败", withNonce["nonce"])
	}

	// 刷新签发: grantFromRefresh 不带 nonce, 此时该 claim 不应存在
	refreshed := idTokenClaims(base, u, tokenGrant{ClientID: "c", Scope: "openid"}, now, now)
	if _, ok := refreshed["nonce"]; ok {
		t.Error("刷新签发的 id_token 带了 nonce —— 刷新不是新的认证事件, 严格的 RP 会因对不上而拒绝")
	}
}

// TestGrantMapping_NoFieldDropped 授权记录 → 签发依据的翻译不得丢字段。
//
// 少写一行 Scope 编译得过、跑得通, 只是刷新之后 claims 悄悄变样 ——
// 这类"静默降级"正是变异测试第一轮漏掉的 (⑤)。
func TestGrantMapping_NoFieldDropped(t *testing.T) {
	ac := &AuthCode{
		UserID: 42, ClientID: "geass", Nonce: "n1",
		CodeHash: "codehash", Scope: "openid email",
	}
	got := grantFromCode(ac)
	want := tokenGrant{UserID: 42, ClientID: "geass", Nonce: "n1", FamilyID: "codehash", Scope: "openid email"}
	if got != want {
		t.Errorf("grantFromCode 结果不符\n  得到: %+v\n  期望: %+v", got, want)
	}

	rt := &RefreshToken{UserID: 42, ClientID: "geass", FamilyID: "codehash", Scope: "openid email"}
	gotR := grantFromRefresh(rt)
	// Nonce 刻意不继承, 其余必须原样传递
	wantR := tokenGrant{UserID: 42, ClientID: "geass", FamilyID: "codehash", Scope: "openid email"}
	if gotR != wantR {
		t.Errorf("grantFromRefresh 结果不符 (scope 丢失会让刷新后的 claims 变样)\n  得到: %+v\n  期望: %+v", gotR, wantR)
	}
}

// TestTokenGrant_AllFieldsMapped tokenGrant 加了字段就必须决定两条映射怎么填。
//
// 靠反射数字段数量 —— 加字段时这条会红, 强制你回去看 grantFromCode /
// grantFromRefresh 是否需要同步。不这么做的话, 新字段会默默保持零值。
func TestTokenGrant_AllFieldsMapped(t *testing.T) {
	const known = 5 // UserID / ClientID / Nonce / FamilyID / Scope
	if n := reflect.TypeOf(tokenGrant{}).NumField(); n != known {
		t.Errorf("tokenGrant 现在有 %d 个字段 (原 %d)。\n"+
			"  请确认 grantFromCode 与 grantFromRefresh 都已决定新字段怎么填,\n"+
			"  再把这里的数字改过来 —— 漏填不会报错, 只会静默取零值", n, known)
	}
}
