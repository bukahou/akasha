package op

import (
	"log/slog"
	"net/http"
	"strings"

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
// sub = HMAC(salt, client_id \0 internal_id) 是单向的, 拿到 (aud, sub) 推不回用户。
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

	sub, _ := claims["sub"].(string)
	aud, _ := claims["aud"].(string)
	if sub == "" || aud == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	userID, err := h.svc.LookupUserBySub(r.Context(), aud, sub)
	if err != nil {
		slog.Error("userinfo 反查失败", "err", err, "client_id", aud)
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

	// 返回的 sub 必须与 access_token 中的一致 (OIDC Core §5.3.2 要求 RP 校验这点)
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":                sub,
		"email":              u.Email,
		"email_verified":     u.EmailVerified,
		"name":               u.Name,
		"preferred_username": u.Username,
		"picture":            u.AvatarURL,
	})
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
