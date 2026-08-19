package op

import (
	"log/slog"
	"net/http"
	"net/url"
)

// # RP 发起的登出 (OIDC RP-Initiated Logout 1.0)
//
// # akasha 无会话, 这个端点还有什么用
//
// 它确实没有会话可结束 —— 但登出流程的价值不止于此:
//
//  1. RP 读 discovery 决定"要不要提供登出联动"。没有 end_session_endpoint,
//     通用 RP 库会认为本 OP 不支持登出, 用户在下游点登出后仍可能被静默登回。
//  2. 它是把用户送回下游落地页的标准出口 —— 下游清完自己的会话后跳来这里,
//     再由这里跳回下游的"已登出"页面。
//
// 所以本实现的重点全在【正确地把人送回去】, 而不是清理状态。
//
// # 新增的攻击面
//
// post_logout_redirect_uri 是一个由请求方指定的跳转目标 —— 与 redirect_uri
// 同性质的开放重定向面。规范要求它必须预先注册, 本实现照做: 未注册的地址一律
// 不跳, 改为在本站显示已登出页。

// endSession GET/POST /end_session。
func (h *Handler) endSession(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			q = r.Form
		}
	}

	postLogoutURI := q.Get("post_logout_redirect_uri")
	state := q.Get("state")

	// 无回跳目标: 纯粹告知"已登出"即可
	if postLogoutURI == "" {
		h.renderLoggedOut(w)
		return
	}

	// 要跳转, 就必须先确定这是哪个 client —— 白名单是按 client 存的。
	// client_id 参数优先; 缺失时从 id_token_hint 的 aud 推断 (规范允许两者其一)。
	clientID := q.Get("client_id")
	if clientID == "" {
		clientID = h.clientFromIDTokenHint(q.Get("id_token_hint"))
	}
	if clientID == "" {
		slog.Info("登出请求无法确定 client, 不执行回跳")
		h.renderLoggedOut(w)
		return
	}

	c, err := h.clients.FindByClientID(r.Context(), clientID)
	if err != nil {
		slog.Info("登出请求指向未注册的 client", "client_id", clientID)
		h.renderLoggedOut(w)
		return
	}
	if err := h.clients.ValidatePostLogoutRedirectURI(c, postLogoutURI); err != nil {
		// 关键防线: 未注册的地址绝不跳 —— 否则任何人都能构造一个登出链接
		// 把用户送去钓鱼站, 而链接本身指向的是可信域名
		slog.Warn("登出回跳地址不在白名单", "client_id", clientID)
		h.renderLoggedOut(w)
		return
	}

	dest := postLogoutURI
	if state != "" {
		// state 原样回传, RP 靠它把这次登出与自己发起的请求对上
		if u, perr := url.Parse(postLogoutURI); perr == nil {
			qq := u.Query()
			qq.Set("state", state)
			u.RawQuery = qq.Encode()
			dest = u.String()
		}
	}
	slog.Info("登出回跳", "client_id", clientID)
	http.Redirect(w, r, dest, http.StatusFound)
}

// clientFromIDTokenHint 从 id_token_hint 中取出 client_id (aud)。
//
// 必须验签: 否则任何人都能伪造一个 hint 来指定登出目标, 绕过"这个 client 是谁"
// 的判断。但【不检查过期】—— 用户登出时手上那张 id_token 通常已经过期,
// 它在这里只用于识别身份来源, 不承担任何授权作用。
//
// 任何失败都返回空串: hint 是可选的辅助信息, 坏了就当没提供, 不该让登出失败。
func (h *Handler) clientFromIDTokenHint(hint string) string {
	if hint == "" {
		return ""
	}
	claims, err := h.km.VerifyTokenIgnoringExpiry(hint)
	if err != nil {
		slog.Info("id_token_hint 验签失败, 忽略", "err", err)
		return ""
	}
	aud, _ := claims["aud"].(string)
	return aud
}

func (h *Handler) renderLoggedOut(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(loggedOutHTML))
}

// loggedOutHTML 登出落地页。
//
// 内联而非用模板: op 是协议包, 引入模板渲染会让它依赖 login 包的资产。
// 这一页没有动态数据, 内联是最小代价的做法。
const loggedOutHTML = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>已登出 — Akasha</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:system-ui,-apple-system,"Noto Sans CJK SC",sans-serif;
background:radial-gradient(1200px 600px at 50% -10%,#241b3d,#0f0d17 60%);color:#e9e6f5}
.card{max-width:360px;padding:36px 32px;background:rgba(255,255,255,.04);
border:1px solid rgba(255,255,255,.1);border-radius:16px;text-align:center}
h1{margin:0;font-size:24px;letter-spacing:6px}
p{margin:14px 0 0;font-size:13px;line-height:1.8;color:#a9a3c4}
</style></head>
<body><div class="card"><h1>AKASHA</h1>
<p>你已登出身份中枢。<br>关闭此页即可，或从应用重新登录。</p>
</div></body></html>`
