package login

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/bukahou/akasha/internal/account"
	"github.com/bukahou/akasha/internal/op"
	"github.com/bukahou/akasha/internal/session"
)

// Handler 托管登录页: GET 展示柜台 / POST 验密码建会话 / POST logout 清会话。
type Handler struct {
	accounts *account.Service
	sessions *session.Store
	render   *renderer
}

func NewHandler(accounts *account.Service, sessions *session.Store) (*Handler, error) {
	rd, err := newRenderer()
	if err != nil {
		return nil, err
	}
	return &Handler{accounts: accounts, sessions: sessions, render: rd}, nil
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", h.showLogin)
	mux.HandleFunc("POST /login", h.submitLogin)
	mux.HandleFunc("POST /logout", h.logout)
}

func (h *Handler) showLogin(w http.ResponseWriter, r *http.Request) {
	h.render.renderLogin(w, http.StatusOK, loginPageData{Next: safeNext(r.URL.Query().Get("next"))})
}

func (h *Handler) submitLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "表单解析失败", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"))

	u, err := h.accounts.VerifyPassword(r.Context(), r.PostFormValue("login_name"), r.PostFormValue("password"))
	if err != nil {
		msg := "服务器内部错误, 请稍后重试"
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, account.ErrInvalidCredentials),
			errors.Is(err, account.ErrPasswordLoginOff),
			errors.Is(err, account.ErrUserBanned):
			msg = err.Error()
			status = http.StatusUnauthorized
		default:
			slog.Error("密码登录失败", "err", err)
		}
		h.render.renderLogin(w, status, loginPageData{Next: next, ErrorMsg: msg})
		return
	}

	if err := h.sessions.Issue(r.Context(), w, u.ID, r.UserAgent(), clientIP(r)); err != nil {
		slog.Error("建会话失败", "err", err, "user_id", u.ID)
		h.render.renderLogin(w, http.StatusInternalServerError, loginPageData{Next: next, ErrorMsg: "服务器内部错误, 请稍后重试"})
		return
	}
	slog.Info("密码登录成功", "user_id", u.ID)

	// 恢复停车的 authorize 事务; 无 next (直接访问登录页) 回根
	if next == "" {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if err := h.sessions.Revoke(r.Context(), w, r); err != nil {
		slog.Error("登出失败", "err", err)
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// safeNext 只放行本站 /authorize 断点 (防开放重定向); 其余一律清空。
func safeNext(next string) string {
	if op.SafeLocalNext(next) {
		return next
	}
	return ""
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	return r.RemoteAddr
}
