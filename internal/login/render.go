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
}

func (rd *renderer) renderLogin(w http.ResponseWriter, status int, data loginPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := rd.tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		slog.Error("登录页渲染失败", "err", err)
	}
}
