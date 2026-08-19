package op

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestAccessTokenBearer /userinfo 对已验签 token 的准入判断。
//
// 验签只证明"这张票是 akasha 签的", 不证明"这张票该拿来干这个"。
// 下面每一条都是【签名完全合法】却必须被拒的场景。
func TestAccessTokenBearer(t *testing.T) {
	valid := func() jwt.MapClaims {
		return accessTokenClaims(testBase(), testGrant(), testIssuer, time.Unix(1700003600, 0))
	}

	t.Run("正常的 access_token 放行", func(t *testing.T) {
		clientID, sub, reason := accessTokenBearer(valid(), testIssuer)
		if reason != "" {
			t.Fatalf("合法 token 被拒: %s", reason)
		}
		if clientID != "some-client" {
			t.Errorf("clientID = %q, 期望取自 azp", clientID)
		}
		if sub != "pairwise-sub-value" {
			t.Errorf("sub = %q, 期望取自 sub claim", sub)
		}
	})

	t.Run("发给别的资源服务器的票必须拒", func(t *testing.T) {
		c := valid()
		c["aud"] = "https://some-other-api.example.com"
		if _, _, reason := accessTokenBearer(c, testIssuer); reason == "" {
			t.Error("aud 指向别处的 token 被放行 —— 任何 akasha 签的票都能换用户资料了")
		}
	})

	t.Run("aud 退回 client_id 时必须拒", func(t *testing.T) {
		// A6 之前的形态。若哪天签发端改回去, 这里要立刻发现
		c := valid()
		c["aud"] = "some-client"
		if _, _, reason := accessTokenBearer(c, testIssuer); reason == "" {
			t.Error("aud=client_id 的旧形态 token 被放行 —— aud 校验失去意义")
		}
	})

	t.Run("拿 id_token 冒充 access_token 必须拒", func(t *testing.T) {
		// id_token 的 aud 是 client_id 而非 issuer, 所以第一道就该拦下
		id := idTokenClaims(testBase(), &testUser, testGrant(), time.Unix(1700000000, 0), time.Unix(1700000600, 0))
		if _, _, reason := accessTokenBearer(id, testIssuer); reason == "" {
			t.Error("id_token 被当成 access_token 放行 —— 两张票的用途必须分开")
		}
	})

	t.Run("缺 azp 必须拒", func(t *testing.T) {
		c := valid()
		delete(c, "azp")
		if _, _, reason := accessTokenBearer(c, testIssuer); reason == "" {
			t.Error("缺 azp 被放行 —— 无从确定该查哪个 client 的 pairwise 映射")
		}
	})

	t.Run("缺 sub 必须拒", func(t *testing.T) {
		c := valid()
		delete(c, "sub")
		if _, _, reason := accessTokenBearer(c, testIssuer); reason == "" {
			t.Error("缺 sub 被放行")
		}
	})

	t.Run("拒绝时不得返回任何标识", func(t *testing.T) {
		c := valid()
		c["aud"] = "elsewhere"
		clientID, sub, _ := accessTokenBearer(c, testIssuer)
		if clientID != "" || sub != "" {
			t.Errorf("拒绝路径返回了 (%q, %q) —— 调用方若忘了看 reason 就会拿它去查库", clientID, sub)
		}
	})
}
