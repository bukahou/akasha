package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 轮换期的验签能力。
//
// # 为什么这组测试存在
//
// keys 包用 26 行注释描述了轮换模型: 新私钥签新票, JWKS 输出全部未 retire 的
// 公钥, 旧票在自然过期前始终可验。但 2026-08-18 的代码走查发现, parse() 永远
// 只用【当前】那把公钥 —— 于是:
//
//	下游  按 kid 从 JWKS 取公钥 → 旧票验得过 ✅
//	akasha 自己只认当前公钥      → 旧票验不过 ✗
//
// 后果不会立刻显形 (要等真的轮换一次): /userinfo 对旧 access_token 返 401,
// 登出时的 id_token_hint 验签失败导致回跳静默失效。文档描述得越详细,
// 越没人想到去验证它是不是真的。

// secondKey 轮换后的"旧密钥"用 —— 与 testKey 是两把不同的密钥。
var secondKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

// newRotatedManager 模拟"刚换过密钥"的状态: 当前私钥是 testKey,
// 而缓存里还留着上一把 (secondKey) 的公钥 —— 正是 JWKS 会一并输出的那把。
func newRotatedManager(t *testing.T) (m *Manager, oldKid string, oldPriv *rsa.PrivateKey) {
	t.Helper()
	m = newTestManager(t)

	oldPriv = secondKey()
	oldKid, _, err := fingerprint(&oldPriv.PublicKey)
	if err != nil {
		t.Fatalf("计算旧 kid 失败: %v", err)
	}
	m.verifyKeys = map[string]*rsa.PublicKey{oldKid: &oldPriv.PublicKey}
	// 标成刚刷过, 避免测试里触发查库 (db 为 nil)
	m.lastRefresh = time.Now()
	return m, oldKid, oldPriv
}

func mustPublicPEM(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	_, pemStr, err := fingerprint(pub)
	if err != nil {
		t.Fatalf("导出公钥 PEM 失败: %v", err)
	}
	return pemStr
}

func signWith(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	return s
}

// TestVerify_AcceptsPreviousKey ⭐ 轮换后, 上一把密钥签的票仍然验得过。
func TestVerify_AcceptsPreviousKey(t *testing.T) {
	m, oldKid, oldPriv := newRotatedManager(t)

	old := signWith(t, oldPriv, oldKid, validClaims())
	claims, err := m.VerifyToken(old)
	if err != nil {
		t.Fatalf("旧密钥签的 token 验签失败: %v\n"+
			"  JWKS 已经把这把公钥给了下游, akasha 自己却认不出来 ——\n"+
			"  轮换窗口内 /userinfo 会 401, 登出的 id_token_hint 也会失效", err)
	}
	if claims["sub"] != "test-subject" {
		t.Errorf("claims 解析异常: %v", claims)
	}
}

// TestVerify_CurrentKeyNeedsNoLookup 当前密钥走快路径, 不碰缓存也不碰数据库。
//
// 绝大多数请求验的都是刚签发的票。这条确保常规路径没有因为轮换支持而
// 变成"每次验签查一次库"。
func TestVerify_CurrentKeyNeedsNoLookup(t *testing.T) {
	m := newTestManager(t)
	m.verifyKeys = nil // 缓存为空; db 也是 nil —— 一旦走查库路径必然报错
	m.lastRefresh = time.Time{}

	tok, err := m.SignClaims(validClaims())
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if _, err := m.VerifyToken(tok); err != nil {
		t.Errorf("当前密钥签的 token 验签失败: %v —— 快路径应当完全不依赖缓存与数据库", err)
	}
}

// TestVerify_RejectsUnknownKid 未知 kid 必须拒绝, 且不能退回"拿当前公钥碰运气"。
func TestVerify_RejectsUnknownKid(t *testing.T) {
	m, _, _ := newRotatedManager(t)

	// 用当前私钥签, 但谎报一个不存在的 kid
	forged := signWith(t, testKey(), "kid-that-never-existed", validClaims())
	if _, err := m.VerifyToken(forged); err == nil {
		t.Error("未知 kid 的 token 被接受了 —— kid 必须真的用于选 key, 而不是摆设")
	}
}

// TestVerify_ForeignKeyRejected 别人的密钥签的票, 即使 kid 对得上也必须拒。
//
// kid 是索引不是凭证。这条确保按 kid 取到公钥之后, 签名本身依然被验证。
func TestVerify_ForeignKeyRejected(t *testing.T) {
	m, oldKid, _ := newRotatedManager(t)

	foreign, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成外部密钥失败: %v", err)
	}
	// 冒用一个我们认得的 kid, 但用完全无关的私钥签
	forged := signWith(t, foreign, oldKid, validClaims())
	if _, err := m.VerifyToken(forged); err == nil {
		t.Error("外部密钥签的 token 被接受了 —— kid 只是索引, 签名必须仍然算数")
	}
}

// TestVerify_AlgConfusionStillBlocked 引入按 kid 选 key 之后, 算法白名单不能失效。
//
// 这是本仓最重要的一条防线: 攻击者把 header 改成 alg=HS256, 拿【公开的】公钥
// 当 HMAC 密钥重签。改动验签路径时最容易顺手破坏它。
func TestVerify_AlgConfusionStillBlocked(t *testing.T) {
	m, oldKid, oldPriv := newRotatedManager(t)

	pubPEM := mustPublicPEM(t, &oldPriv.PublicKey)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims())
	tok.Header["kid"] = oldKid // 用一个我们认得的 kid, 让它能取到公钥
	forged, err := tok.SignedString([]byte(pubPEM))
	if err != nil {
		t.Fatalf("构造攻击 token 失败: %v", err)
	}
	if _, err := m.VerifyToken(forged); err == nil {
		t.Error("alg confusion 攻击成功 —— 按 kid 选 key 的改动破坏了算法白名单")
	}
}

// TestRefreshVerifyKeys_RateLimited 未知 kid 不该每次都打数据库。
//
// 攻击者伪造一堆随机 kid 就能构成一个廉价的放大面。
func TestRefreshVerifyKeys_RateLimited(t *testing.T) {
	m := newTestManager(t)
	m.verifyKeys = map[string]*rsa.PublicKey{}
	m.lastRefresh = time.Now() // 刚刷过

	// db 为 nil: 若真的去查库会返回"未配置数据库"的错误; 被限流则返回 nil
	if err := m.refreshVerifyKeys(t.Context()); err != nil {
		t.Errorf("距上次刷新不足 %v 时应当直接跳过, 却尝试了查库: %v", verifyKeyRefreshInterval, err)
	}

	// 超过间隔后才真正尝试 (此处 db 为 nil, 预期报错 —— 说明它确实去查了)
	m.lastRefresh = time.Now().Add(-2 * verifyKeyRefreshInterval)
	if err := m.refreshVerifyKeys(t.Context()); err == nil {
		t.Error("超过刷新间隔后应当真正尝试查库")
	} else if !strings.Contains(err.Error(), "数据库") {
		t.Errorf("预期是查库相关的错误, 得到: %v", err)
	}
}
