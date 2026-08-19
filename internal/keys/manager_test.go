package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testKey 生成一次复用 —— RSA-2048 生成要上百毫秒, 每个用例来一次会让整个包变慢。
var testKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

// newTestManager 构造一个不依赖数据库的 Manager。
// 签名与验签路径都只用到 private, db 仅在公钥登记与 JWKS 时才需要。
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	priv := testKey()
	kid, _, err := fingerprint(&priv.PublicKey)
	if err != nil {
		t.Fatalf("计算 kid 失败: %v", err)
	}
	return &Manager{kid: kid, private: priv}
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": "https://akasha.test",
		"sub": "test-subject",
		"aud": "test-client",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
}

// TestVerifyToken_RejectsAlgConfusion 是本仓最重要的一条测试。
//
// # 攻击原理
//
// akasha 用 RSA 私钥签名, 公钥经 /jwks 【公开】给所有人。攻击者据此构造:
//
//	① 取走公开的公钥
//	② 把 JWT header 的 alg 从 RS256 改成 HS256
//	③ 用【公钥的字节】当作 HMAC 密钥重新签名
//
// 若验证方"信任 token 自己声明的 alg", 就会拿公钥去做 HMAC 校验 —— 而攻击者
// 正是用同一份公钥签的, 校验必然通过。于是任何人都能伪造任意身份的 token,
// 整个信任链归零。
//
// 防线是 VerifyToken 里那句算法类型断言。它看起来只是一行, 删掉后【功能完全
// 正常】—— 正常 token 照签照验, 没有任何症状 —— 但系统已经彻底洞开。
// 这正是它必须由测试守住而不能只靠注释的原因。
func TestVerifyToken_RejectsAlgConfusion(t *testing.T) {
	m := newTestManager(t)
	priv := testKey()

	// 攻击者能拿到的东西: 公钥的 PEM (就是 /jwks 上那份的等价物)
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("序列化公钥失败: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// 用公钥当 HMAC 密钥伪造一张 "管理员" token
	forgedClaims := validClaims()
	forgedClaims["sub"] = "victim-account"
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, forgedClaims).SignedString(pubPEM)
	if err != nil {
		t.Fatalf("构造伪造 token 失败: %v", err)
	}

	if _, err := m.VerifyToken(forged); err == nil {
		t.Fatal("HS256 伪造 token 被接受 —— alg confusion 防护失效, 任何人都可伪造任意身份")
	}
}

func TestVerifyToken(t *testing.T) {
	m := newTestManager(t)

	t.Run("正常签发的 token 通过", func(t *testing.T) {
		signed, err := m.SignClaims(validClaims())
		if err != nil {
			t.Fatalf("签名失败: %v", err)
		}
		claims, err := m.VerifyToken(signed)
		if err != nil {
			t.Fatalf("验证自己签发的 token 失败: %v", err)
		}
		if claims["sub"] != "test-subject" {
			t.Errorf("sub = %v, 期望 test-subject", claims["sub"])
		}
	})

	t.Run("篡改 payload 后签名失效", func(t *testing.T) {
		signed, err := m.SignClaims(validClaims())
		if err != nil {
			t.Fatalf("签名失败: %v", err)
		}
		parts := strings.Split(signed, ".")
		if len(parts) != 3 {
			t.Fatalf("JWT 结构异常: %d 段", len(parts))
		}
		// 换成另一段合法 base64 的 payload, 签名保持不动
		other, err := m.SignClaims(jwt.MapClaims{
			"iss": "https://akasha.test", "sub": "attacker",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		if err != nil {
			t.Fatalf("签名失败: %v", err)
		}
		tampered := parts[0] + "." + strings.Split(other, ".")[1] + "." + parts[2]

		if _, err := m.VerifyToken(tampered); err == nil {
			t.Fatal("篡改 payload 后仍验证通过")
		}
	})

	t.Run("另一把私钥签的 token 被拒", func(t *testing.T) {
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("生成密钥失败: %v", err)
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims())
		signed, err := tok.SignedString(otherKey)
		if err != nil {
			t.Fatalf("签名失败: %v", err)
		}
		if _, err := m.VerifyToken(signed); err == nil {
			t.Fatal("其他私钥签发的 token 被接受")
		}
	})

	t.Run("过期 token 被拒", func(t *testing.T) {
		claims := validClaims()
		claims["exp"] = time.Now().Add(-time.Hour).Unix()
		signed, err := m.SignClaims(claims)
		if err != nil {
			t.Fatalf("签名失败: %v", err)
		}
		if _, err := m.VerifyToken(signed); err == nil {
			t.Fatal("过期 token 被接受")
		}
	})
}

// TestVerifyTokenIgnoringExpiry id_token_hint 专用路径: 容忍过期, 但绝不容忍伪造。
func TestVerifyTokenIgnoringExpiry(t *testing.T) {
	m := newTestManager(t)

	t.Run("过期 token 仍可解析", func(t *testing.T) {
		claims := validClaims()
		claims["exp"] = time.Now().Add(-24 * time.Hour).Unix()
		signed, err := m.SignClaims(claims)
		if err != nil {
			t.Fatalf("签名失败: %v", err)
		}
		got, err := m.VerifyTokenIgnoringExpiry(signed)
		if err != nil {
			t.Fatalf("过期的 id_token_hint 应当仍可用于识别: %v", err)
		}
		if got["aud"] != "test-client" {
			t.Errorf("aud = %v, 期望 test-client", got["aud"])
		}
	})

	t.Run("放宽过期不等于放宽签名", func(t *testing.T) {
		priv := testKey()
		pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
		forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims()).SignedString(pubPEM)
		if err != nil {
			t.Fatalf("构造伪造 token 失败: %v", err)
		}
		if _, err := m.VerifyTokenIgnoringExpiry(forged); err == nil {
			t.Fatal("宽松路径同样必须拒绝 alg confusion")
		}
	})
}

// TestFingerprint_Deterministic kid 必须由公钥内容决定。
//
// upsertPublicKey 靠 kid 去重 —— 若 kid 带随机性, 每次重启都会往 signing_keys
// 插一条新记录, JWKS 里堆满同一把公钥的不同 kid, 下游缓存也会失效。
func TestFingerprint_Deterministic(t *testing.T) {
	priv := testKey()
	kid1, pem1, err := fingerprint(&priv.PublicKey)
	if err != nil {
		t.Fatalf("fingerprint 失败: %v", err)
	}
	kid2, pem2, err := fingerprint(&priv.PublicKey)
	if err != nil {
		t.Fatalf("fingerprint 失败: %v", err)
	}
	if kid1 != kid2 {
		t.Errorf("同一把公钥算出两个 kid: %s != %s", kid1, kid2)
	}
	if pem1 != pem2 {
		t.Error("同一把公钥导出两份不同的 PEM")
	}
	if len(kid1) != 16 {
		t.Errorf("kid 长度 = %d, 期望 16 (SHA-256 前 8 字节的 hex)", len(kid1))
	}

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	otherKid, _, err := fingerprint(&other.PublicKey)
	if err != nil {
		t.Fatalf("fingerprint 失败: %v", err)
	}
	if otherKid == kid1 {
		t.Error("不同公钥算出了相同的 kid")
	}
}

// TestSignClaims_CarriesKid 下游靠 header 里的 kid 从 JWKS 里精确选公钥。
// 轮换期间 JWKS 有多把公钥, 没有 kid 就只能逐个试。
func TestSignClaims_CarriesKid(t *testing.T) {
	m := newTestManager(t)
	signed, err := m.SignClaims(validClaims())
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	tok, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if tok.Header["kid"] != m.Kid() {
		t.Errorf("header kid = %v, 期望 %s", tok.Header["kid"], m.Kid())
	}
	if tok.Header["alg"] != "RS256" {
		t.Errorf("alg = %v, 期望 RS256", tok.Header["alg"])
	}
}
