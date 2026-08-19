package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestHandler(t *testing.T, deps Deps) *Handler {
	t.Helper()
	if deps.SafeNext == nil {
		deps.SafeNext = func(n string) bool { return strings.HasPrefix(n, "/authorize?") }
	}
	h, err := NewHandler(deps)
	if err != nil {
		t.Fatalf("构造登录页失败: %v", err)
	}
	return h
}

func render(h *Handler, target string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	h.Register(mux)
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	return w
}

// TestLoginPage_ShowsDestination ⭐ 登录页必须告诉用户"你正在登录到哪"。
//
// 这不只是 UX。攻击者诱导你点一个看似 atlhyper 的链接, 页面上却写着 geass ——
// 那一刻是用户唯一能察觉的机会。schema 注释早就承诺了这一行, 一直没兑现。
func TestLoginPage_ShowsDestination(t *testing.T) {
	h := newTestHandler(t, Deps{
		Providers:  []string{"google"},
		ClientName: func(context.Context, string) string { return "Geass 影视库" },
	})

	body := render(h, "/login?next=%2Fauthorize%3Fclient_id%3Dgeass").Body.String()
	if !strings.Contains(body, "Geass 影视库") {
		t.Error("登录页没有显示目标应用名 —— 用户无从判断自己在登录到哪")
	}
}

// TestLoginPage_NoDestinationWithoutName 拿不到名字时页面照常, 只是少一行。
func TestLoginPage_NoDestinationWithoutName(t *testing.T) {
	h := newTestHandler(t, Deps{
		Providers:  []string{"google"},
		ClientName: func(context.Context, string) string { return "" },
	})

	w := render(h, "/login?next=%2Fauthorize%3Fclient_id%3Dgeass")
	if w.Code != http.StatusOK {
		t.Errorf("返回 %d, 期望 200 —— 名字拿不到绝不能让登录页失败", w.Code)
	}
	if strings.Contains(w.Body.String(), "继续前往") {
		t.Error("名字为空时仍渲染了'继续前往'那一行")
	}
}

// TestLoginPage_SkipsLookupForUnsafeNext ⭐ 不合法的 next 不得触发反查。
//
// 反查要查数据库。拿一个没过白名单的 next 去查, 等于让任意构造的 client_id
// 都能触发一次数据库查询 —— 一个免费的放大面。
func TestLoginPage_SkipsLookupForUnsafeNext(t *testing.T) {
	called := false
	h := newTestHandler(t, Deps{
		Providers: []string{"google"},
		ClientName: func(context.Context, string) string {
			called = true
			return "不该被查到"
		},
	})

	render(h, "/login?next=https%3A%2F%2Fevil.test%2Fsteal")
	if called {
		t.Error("非法 next 触发了 client 反查 —— 任意构造的 client_id 都能打一次数据库")
	}
}

// TestLoginPage_EscapesClientName 名字来自数据库, 但仍须转义。
//
// clients.name 由管理员手写, 不是用户输入 —— 但"可信来源"不等于"格式安全",
// 而 html/template 的自动转义正是防这类疏忽的。这条确认它没被 template.HTML 绕过。
func TestLoginPage_EscapesClientName(t *testing.T) {
	h := newTestHandler(t, Deps{
		Providers:  []string{"google"},
		ClientName: func(context.Context, string) string { return `<script>alert(1)</script>` },
	})

	body := render(h, "/login?next=%2Fauthorize%3Fclient_id%3Dx").Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("client 名字被原样注入页面 —— html/template 的自动转义被绕过了")
	}
}

// TestLoginPage_UnsafeNextNotRendered 非法 next 不得出现在按钮 href 里。
func TestLoginPage_UnsafeNextNotRendered(t *testing.T) {
	h := newTestHandler(t, Deps{Providers: []string{"google"}})

	body := render(h, "/login?next=https%3A%2F%2Fevil.test%2Fsteal").Body.String()
	if strings.Contains(body, "evil.test") {
		t.Error("非法 next 出现在了页面里 —— 开放重定向")
	}
}
