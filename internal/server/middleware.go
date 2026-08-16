package server

import (
	"net/http"
	"strings"
)

// # 为什么 IdP 尤其需要这组头
//
// 登录页是钓鱼与点击劫持的首选目标: 攻击者把真实的 akasha 登录框透明嵌进自己的
// 页面, 用户看到的地址栏是攻击者的域名, 填的却是真实表单; 或用透明 iframe 覆盖
// 诱导点击完成一次非本意的授权。对标产品 (Keycloak / Hydra / Auth0) 无一例外
// 默认发送这些头。
//
// 本项目此前一个都没有 —— 2026-08-16 审计的三条阻断项之一。
const (
	// cspPolicy 默认拒绝一切外部资源。
	//
	//	default-src 'none'    基线全拒, 下面逐项开口子
	//	style-src 'unsafe-inline'  登录页样式内联在模板里 (无构建链, 不引外部 CSS)。
	//	                      开这个口子的风险前提是"能注入 HTML", 而模板走
	//	                      html/template 自动转义, 该前提不成立
	//	img-src https: data:  留给上游头像等图片
	//	form-action 'self'    表单只能提交回本站 —— 挡住"注入一个指向外部的 form"
	//	frame-ancestors 'none' 任何站点都不能 iframe 本页 (点击劫持防线)
	//	base-uri 'none'       禁 <base> 改写相对 URL 的注入手法
	cspPolicy = "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

	// hstsPolicy 一年 + 子域。仅在 issuer 为 https 时发送 ——
	// 明文 HTTP 下浏览器会忽略它, 发了只是噪音。
	hstsPolicy = "max-age=31536000; includeSubDomains"
)

// SecurityHeaders 给所有响应加上浏览器侧防护头。
//
// https 由 issuer 是否 https 决定, 而非猜测请求协议 —— 生产在反向代理后面,
// r.TLS 恒为 nil, 靠它判断会永远不发 HSTS。
func SecurityHeaders(issuer string, next http.Handler) http.Handler {
	https := strings.HasPrefix(issuer, "https://")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", cspPolicy)
		// X-Frame-Options 是 frame-ancestors 的老浏览器回退, 两者并存是通行做法
		h.Set("X-Frame-Options", "DENY")
		// 禁 MIME 嗅探: 防止把 JSON 响应当成 HTML/JS 执行
		h.Set("X-Content-Type-Options", "nosniff")
		// 不外泄 Referer —— URL 里可能带 state/code 等一次性凭证
		h.Set("Referrer-Policy", "no-referrer")
		if https {
			h.Set("Strict-Transport-Security", hstsPolicy)
		}
		next.ServeHTTP(w, r)
	})
}

// CORS 给浏览器可直连的端点放行跨源请求。
//
// # 为什么需要
//
// SPA 作为 public client 时, 换 token 这一步发生在【浏览器里】而不是服务端。
// 没有 CORS 头, 浏览器会在 JS 拿到响应前就把它拦掉 —— 这不是 akasha 拒绝了
// 请求, 而是浏览器的同源策略, 服务端日志里甚至看不出异常。
//
// # 为什么可以对所有来源放行
//
// 这几个端点的安全性【不依赖】来源限制:
//   - /token      靠 code + PKCE verifier + (机密客户端的) secret 保护,
//     三者都不是浏览器自动附带的东西
//   - /jwks       公钥, 本就是公开数据
//   - /discovery  公开元数据
//
// 关键是【不带 credentials】: 不回 Access-Control-Allow-Credentials,
// 于是浏览器不会在跨源请求上自动附带 cookie —— 联邦状态 cookie 不会被
// 任意站点借用。这也是不能简单地给所有路由加 CORS 的原因: /authorize 与
// /federation/* 依赖 cookie, 给它们开跨源等于自毁 CSRF 防线。
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if corsAllowedPaths[r.URL.Path] {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			h.Set("Access-Control-Max-Age", "3600")
			// 预检请求就此结束, 不必进业务 handler
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// corsAllowedPaths 允许跨源访问的端点白名单。
// 只列不依赖 cookie 的端点 —— 名单之外一律不发 CORS 头。
var corsAllowedPaths = map[string]bool{
	"/token":                            true,
	"/jwks":                             true,
	"/.well-known/openid-configuration": true,
}

// maxRequestBody 请求体上限 (64KB)。
// 本服务最大的请求是 token 端点的表单, 实际不过几百字节;
// 没有上限时 ParseForm 会把整个 body 读进内存, 与慢速请求构成资源耗尽面。
const maxRequestBody = 64 << 10

// LimitBody 限制请求体大小。超限时 ParseForm 会返回错误, 由各 handler 转成 400。
func LimitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}
