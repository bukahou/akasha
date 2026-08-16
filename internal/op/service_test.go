package op

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// TestPairwiseSub_IsolatesClients pairwise 的全部价值: 同一个人在不同应用拿到
// 不同的 sub, 两个应用即使互相比对也认不出这是同一个人。
//
// 若哪天有人"顺手简化"成 sub = internal_id, 功能一切正常 —— 登录照常、
// token 照发 —— 但下游之间的身份隔离已经彻底消失, 且没有任何症状。
func TestPairwiseSub_IsolatesClients(t *testing.T) {
	// 测试数据一律用明显虚构的值 —— 本仓公开, 真实用户派生出的标识不该进来。
	// internal_id 的实际形态是 SHA256 的 hex, 这里只需长度与字符集对得上。
	const (
		internalID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		salt       = "test-salt-do-not-use-in-production"
	)

	geass := PairwiseSub("geass", internalID, salt)
	atlhyper := PairwiseSub("atlhyper", internalID, salt)

	if geass == atlhyper {
		t.Fatal("同一用户在两个 client 拿到相同 sub —— pairwise 隔离失效")
	}
	if strings.Contains(geass, internalID) || strings.Contains(atlhyper, internalID) {
		t.Fatal("sub 中包含 internal_id —— 下游可直接读出内部标识")
	}
	if len(geass) != 64 {
		t.Errorf("sub 长度 = %d, 期望 64 (HMAC-SHA256 的 hex)", len(geass))
	}
}

func TestPairwiseSub_Deterministic(t *testing.T) {
	const (
		internalID = "abc123"
		salt       = "s"
	)
	// 稳定性是"重建后自动恢复"的前提: 同样的输入必须永远算出同样的 sub,
	// 否则用户重新登录后下游会把他当成新人
	first := PairwiseSub("geass", internalID, salt)
	for i := 0; i < 5; i++ {
		if got := PairwiseSub("geass", internalID, salt); got != first {
			t.Fatalf("第 %d 次计算结果不同: %s != %s", i+1, got, first)
		}
	}
}

func TestPairwiseSub_SaltMatters(t *testing.T) {
	const internalID = "abc123"
	a := PairwiseSub("geass", internalID, "salt-A")
	b := PairwiseSub("geass", internalID, "salt-B")
	if a == b {
		t.Fatal("换了 salt 却算出相同 sub —— salt 没有真正参与计算")
	}
}

// TestPairwiseSub_NoDelimiterAmbiguity 分隔符必须能挡住拼接歧义。
//
// 若用普通字符 (如 ":") 作分隔, ("goog", "le:1") 与 ("google", ":1") 会拼成
// 同一个字符串, 于是两个【不同】的 (client, 用户) 组合算出同一个 sub ——
// 一个用户能拿到另一个用户的身份。用 \x00 是因为 client_id 与 internal_id
// 都是可打印字符, 不可能含它。
func TestPairwiseSub_NoDelimiterAmbiguity(t *testing.T) {
	const salt = "s"
	a := PairwiseSub("goog", "le\x00xyz", salt)
	b := PairwiseSub("google", "xyz", salt)
	if a == b {
		t.Fatal("不同的 (client, internal_id) 组合算出相同 sub —— 存在拼接歧义")
	}
}

// TestAccessTokenHash at_hash 必须严格按 OIDC Core §3.1.3.6:
// SHA-256 后取【左半边】(前 16 字节) 再 base64url 无填充。
//
// 取全长或右半边都会让 AppAuth-iOS、Nimbus 这类严格 RP 判 id_token 非法 ——
// 而你自己的应用完全正常, 问题只在别人接入时出现。
func TestAccessTokenHash(t *testing.T) {
	const token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature"

	got := accessTokenHash(token)

	sum := sha256.Sum256([]byte(token))
	want := base64.RawURLEncoding.EncodeToString(sum[:16]) // 左半边 = 前 128 位
	if got != want {
		t.Errorf("at_hash = %s, 期望 %s", got, want)
	}
	// base64url 无填充下, 16 字节 → 22 字符
	if len(got) != 22 {
		t.Errorf("at_hash 长度 = %d, 期望 22 —— 可能取了全长而非左半边", len(got))
	}
	if strings.ContainsAny(got, "+/=") {
		t.Errorf("at_hash 含标准 base64 字符 %q, 应为 base64url 无填充", got)
	}
}

// TestComputeS256 PKCE 的 challenge 计算 (RFC 7636 §4.2)。
// 用规范附录 B 给出的官方测试向量 —— 这是能拿到的最权威断言。
func TestComputeS256(t *testing.T) {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	if got := computeS256(verifier); got != challenge {
		t.Errorf("computeS256(%q) = %q, RFC 7636 附录 B 给出的是 %q", verifier, got, challenge)
	}
}

func TestRandomOpaque(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		v, err := randomOpaque()
		if err != nil {
			t.Fatalf("生成失败: %v", err)
		}
		if len(v) != 64 {
			t.Fatalf("长度 = %d, 期望 64 (32 字节的 hex)", len(v))
		}
		if seen[v] {
			t.Fatal("100 次生成出现重复 —— 熵严重不足")
		}
		seen[v] = true
	}
}

func TestHashOpaque(t *testing.T) {
	// 凭证入库前一律哈希: 拖库者拿到的是哈希, 无法还原出可用的 token
	const plain = "some-refresh-token"
	h := hashOpaque(plain)
	if h == plain {
		t.Fatal("hashOpaque 返回了原文")
	}
	if len(h) != 64 {
		t.Errorf("长度 = %d, 期望 64", len(h))
	}
	if hashOpaque(plain) != h {
		t.Error("同一输入两次得到不同哈希")
	}
}
