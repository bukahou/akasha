package login

import (
	"context"
	"net/http"
)

// Handler 托管柜台页 —— akasha 唯一面向人类的表面。
//
// 它只做一件事: 把用户引向某个上游 provider。没有密码表单 (2026-08-09 无密码定案),
// 也没有登出 (2026-08-16 无会话定案 —— 没有登录态自然无从登出)。
// Deps 本包需要、却不该自己知道的东西, 由装配方注入。
//
// 全部经注入而非 import, 换来的是本包【不依赖任何内部包】——
// 一个什么都不知道的渲染器最好推理。代价是给只有一个实现的函数做注入,
// 确实有仪式成分; 但 login → op 那条依赖曾真实存在过 (2026-08-18 移除),
// 而 federation 遇到同样需求时用的就是注入 —— 同一个问题一种解法。
type Deps struct {
	// Providers 上游名列表, 仅用于渲染按钮 (本包不与 federation 包耦合)
	Providers []string
	// SafeNext 校验回跳目标是否为本站合法断点 (判据属于 op, 它认得自己的端点)
	SafeNext func(next string) bool
	// ClientName 由停车的请求取出目标应用的展示名, 用于渲染"继续前往 xx"。
	// 拿不到就返回空串, 页面少一行字, 绝不能让登录失败。
	ClientName func(ctx context.Context, next string) string
}

type Handler struct {
	render *renderer
	deps   Deps
}

func NewHandler(deps Deps) (*Handler, error) {
	rd, err := newRenderer()
	if err != nil {
		return nil, err
	}
	return &Handler{render: rd, deps: deps}, nil
}

func (h *Handler) Register(mux *http.ServeMux) {
	// "GET /{$}" 只匹配根路径本身; 写成 "GET /" 会变成兜底路由,
	// 把所有未注册路径 (含拼错的端点) 都吞进来, 掩盖 404
	mux.HandleFunc("GET /{$}", h.showNotice)
	mux.HandleFunc("GET /login", h.showLogin)
}

// showLogin 展示上游登录入口。
//
// error 由联邦回调失败时回跳带入 (见 federation.failBack)。
// next 是停车的 authorize 断点 —— 没有它, 这次登录就没有归宿 (见 showNotice)。
func (h *Handler) showLogin(w http.ResponseWriter, r *http.Request) {
	next := h.sanitizeNext(r.URL.Query().Get("next"))
	// 只在 next 合法时才查名字 —— 拿一个没过白名单的 next 去反查, 等于让
	// 任意构造的 client_id 都能触发一次数据库查询
	var clientName string
	if next != "" && h.deps.ClientName != nil {
		clientName = h.deps.ClientName(r.Context(), next)
	}
	h.render.renderLogin(w, http.StatusOK, loginPageData{
		Next:       next,
		ErrorMsg:   safeErrorMsg(r.URL.Query().Get("error")),
		Providers:  h.deps.Providers,
		ClientName: clientName,
	})
}

// showNotice 根路径说明页。
//
// akasha 无会话, 所以这里没有"已登录"状态可展示 —— 它纯粹是个说明:
// 本服务是协议中转站, 不提供业务功能, 请从各应用发起登录。
//
// 存在的理由是给两种走错路的人一个交代: 直接访问域名的人, 以及在登录页
// 没有 next 就点了上游按钮、认证完无处可去的人 (?authenticated=1)。
func (h *Handler) showNotice(w http.ResponseWriter, r *http.Request) {
	h.render.renderNotice(w, noticePageData{
		Authenticated: r.URL.Query().Get("authenticated") == "1",
	})
}

// sanitizeNext 只放行本站合法断点 (防开放重定向); 其余一律清空。
func (h *Handler) sanitizeNext(next string) string {
	if h.deps.SafeNext(next) {
		return next
	}
	return ""
}

// 联邦失败的原因码 → 给人看的文案。
//
// 只认白名单里的原因码, 不直接回显 query 参数 —— 否则攻击者可构造
// /login?error=<任意文案> 伪造提示 (例如"请致电 XXX 解锁账号"), 借可信域名行骗。
var errorMsgByCode = map[string]string{
	"cancelled": "登录已取消, 可重新选择登录方式",
	"state":     "登录会话已失效或超时, 请重新登录",
	"upstream":  "第三方登录失败, 请稍后重试",
	"banned":    "账号已封禁",
	"internal":  "服务器内部错误, 请稍后重试",
}

func safeErrorMsg(code string) string {
	return errorMsgByCode[code] // 未知原因码返回空串, 页面不显示错误块
}
