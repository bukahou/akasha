// Package login 托管柜台页: 所有登录方式的唯一入口 (密码表单 + 未来联邦按钮)。
package login

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

// renderer html/template 加载与渲染 (模板 embed 进二进制, 部署无外部文件依赖)。
type renderer struct {
	tmpl *template.Template
}

func newRenderer() (*renderer, error) {
	t, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &renderer{tmpl: t}, nil
}

// loginPageData 登录页模板数据。
type loginPageData struct {
	Next     string // 登录成功后的回跳 (/authorize?...)
	ErrorMsg string
	// Providers 已注册的上游 (google/...)。无密码定案后这才是正式入口,
	// 下面的密码表单是 M1 遗留的临时入口, M2 联邦跑通后移除。
	Providers []string
}

// providerLabel 上游名 → 按钮文案。未知 provider 原样显示, 不至于渲染出空按钮。
var providerLabel = map[string]string{
	"google": "使用 Google 登录",
	"github": "使用 GitHub 登录",
}

func (d loginPageData) Label(provider string) string {
	if s, ok := providerLabel[provider]; ok {
		return s
	}
	return "使用 " + provider + " 登录"
}

func (rd *renderer) renderLogin(w http.ResponseWriter, status int, data loginPageData) {
	rd.render(w, status, "login.html", data)
}

// noticePageData 根路径说明页的模板数据。
type noticePageData struct {
	// Authenticated 用户刚完成了一次上游认证, 但没有应用在等这个结果
	// (在登录页没有 next 就点了上游按钮)。需要额外解释一句为什么"没反应"。
	Authenticated bool
}

func (rd *renderer) renderNotice(w http.ResponseWriter, data noticePageData) {
	rd.render(w, http.StatusOK, "notice.html", data)
}

func (rd *renderer) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := rd.tmpl.ExecuteTemplate(w, name, data); err != nil {
		// 已经写过 header 了, 这里只能记录 —— 所以模板错误必须在启动时就被 ParseFS 抓住
		slog.Error("页面渲染失败", "err", err, "template", name)
	}
}
