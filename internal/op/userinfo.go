package op

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bukahou/akasha/internal/account"
)

// # UserInfo 端点 (OIDC Core §5.3)
//
// RP 拿 access_token 来问"这个 token 对应的用户是谁"。
//
// # 本项目其实不需要它
//
// akasha 的 id_token 已含全部 claims, 第一方应用拿到就够了。实现它纯粹为了
// 互操作性: 通用 RP 库 (尤其配置为"从 userinfo 补全用户信息"时) 会来调,
// 缺这个端点就会出现"接 Keycloak 正常、接 akasha 报错"。
//
// # pairwise 带来的反查难题
//
// sub = HMAC(salt, client_id \0 internal_id) 是单向的, 拿到 (azp, sub) 推不回用户。
// 而 access_token 里【绝不能】放内部标识 —— 放了下游一比对就破功。
// 解法是服务端记一张 (client_id, sub) → user_id 的映射表 (见 pairwise_subs)。

// userinfo GET/POST /userinfo, Bearer 认证。
func (h *Handler) userinfo(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		// RFC 6750 §3: 认证失败要在 WWW-Authenticate 里说明原因
		w.Header().Set("WWW-Authenticate", `Bearer realm="akasha", error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	// access_token 是本服务签的 RS256 JWT, 直接验签即可 —— 无需查库。
	// 这里【必须】校验过期 (与 id_token_hint 不同): 它承担的是访问授权。
	claims, err := h.km.VerifyToken(token)
	if err != nil {
		slog.Info("userinfo 的 access_token 验签失败", "err", err)
		w.Header().Set("WWW-Authenticate", `Bearer realm="akasha", error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	azp, sub, reason := accessTokenBearer(claims, h.issuer)
	if reason != "" {
		slog.Info("userinfo 拒绝 access_token", "reason", reason)
		w.Header().Set("WWW-Authenticate", `Bearer realm="akasha", error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	userID, err := h.svc.LookupUserBySub(r.Context(), azp, sub)
	if err != nil {
		slog.Error("userinfo 反查失败", "err", err, "client_id", azp)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if userID == 0 {
		// token 签名有效但映射不存在: 用户已被删, 或映射登记时出过错
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	u, err := h.svc.UserClaims(r.Context(), userID)
	if err != nil {
		slog.Error("userinfo 取用户失败", "err", err, "user_id", userID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if u == nil || u.Status != account.StatusActive {
		// 封禁用户的 access_token 在过期前仍能验签通过 —— userinfo 这里能拦下,
		// 这也是 userinfo 相对 id_token 的一点实际价值: 它反映的是【当前】状态
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access_denied"})
		return
	}

	// 字段集由 access_token 里的 scope 决定, 与 id_token 走同一份映射 ——
	// 两个出口给出不一致的字段集会让 RP 无所适从 (它无从判断哪个才算数)。
	scope, _ := claims["scope"].(string)
	resp := identityClaims(u, scope)
	// sub 无条件返回, 且必须与 access_token 中的一致
	// (OIDC Core §5.3.2 要求 RP 校验这点; 不一致时 RP 应当拒绝这次响应)
	resp["sub"] = sub

	writeJSON(w, http.StatusOK, resp)
}

// bearerToken 从 Authorization 头取 Bearer 凭证。
//
// 只认请求头。规范也允许表单字段与 query 参数, 但后两者会把 token 留在
// 访问日志与 Referer 里 —— 不提供比提供更安全, 且主流 RP 都用请求头。
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return strings.TrimSpace(auth[len(prefix):])
	}
	return ""
}

// accessTokenBearer 从【已验签】的 access_token claims 中取出反查所需的 (client_id, sub),
// 顺带校验这张票确实是发给本服务的。reason 非空表示拒绝, 内容仅供日志。
//
// # 为什么要查 aud
//
// 此前完全不查 —— 只要签名对就认。当时勉强说得过去 (akasha 签的票只有这一种用途),
// 但 A6 给 aud 赋予了真实语义之后, 不查就等于【任何一张 akasha 签的票都能换用户资料】,
// 包括将来给别的资源服务器签的。RFC 9068 §4 把这条列为资源服务器的必做校验。
//
// # 为什么反查用 azp 而不是 aud
//
// aud 回答"这张票能拿去哪用" (= akasha), azp 回答"这张票发给了谁" (= client_id)。
// pairwise 映射的键是 client_id, 所以要用 azp。
// A6 之前两者恰好都是 client_id, 换成 aud 也能跑 —— 现在不行了。
//
// 单独抽成纯函数是因为 keys.Manager 造不出测试实例 (字段不导出且构造要 DB),
// 内联在 handler 里这几条判断就没法断言。
func accessTokenBearer(claims jwt.MapClaims, issuer string) (clientID, sub, reason string) {
	if aud, _ := claims["aud"].(string); aud != issuer {
		return "", "", "aud 不是本服务: " + aud
	}
	sub, _ = claims["sub"].(string)
	clientID, _ = claims["azp"].(string)
	if sub == "" {
		return "", "", "缺少 sub"
	}
	if clientID == "" {
		// id_token 有 azp 而 access_token 若缺失, 多半是拿 id_token 冒充 access_token
		return "", "", "缺少 azp"
	}
	return clientID, sub, ""
}
