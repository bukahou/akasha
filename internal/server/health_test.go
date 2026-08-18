package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 探针分层配错不会报错, 只会在真出故障时反应错误 —— 而那时没人会想到
// "是探针配错了"。这组测试把两个端点的语义差别钉死。

func healthMux(checks ...Check) *http.ServeMux {
	mux := http.NewServeMux()
	NewHealth(checks...).Register(mux)
	return mux
}

func get(mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

// TestLiveness_IgnoresDependencies ⭐ liveness 绝不能查外部依赖。
//
// 查了会导致: 数据库挂掉 → 所有 Pod 的 liveness 失败 → K8s 把它们全部重启。
// 既救不了数据库, 还会在它恢复时制造一波冷启动。
func TestLiveness_IgnoresDependencies(t *testing.T) {
	// 注入一个必然失败的检查项 —— liveness 应当完全无视它
	mux := healthMux(Check{Name: "database", Probe: func(context.Context) error {
		return errors.New("数据库已挂")
	}})

	for _, path := range []string{"/healthz", "/health"} {
		if code := get(mux, path).Code; code != http.StatusOK {
			t.Errorf("%s 返回 %d, 期望 200\n"+
				"  liveness 查了依赖 = 数据库故障时所有 Pod 被重启一遍", path, code)
		}
	}
}

// TestReadiness_FailsOnBrokenDependency 就绪必须真的查, 且指名道姓。
func TestReadiness_FailsOnBrokenDependency(t *testing.T) {
	mux := healthMux(
		Check{Name: "signing-key", Probe: func(context.Context) error { return nil }},
		Check{Name: "database", Probe: func(context.Context) error { return errors.New("connection refused") }},
	)

	w := get(mux, "/readyz")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz 返回 %d, 期望 503 —— 依赖不可用时 Pod 必须被摘出负载均衡", w.Code)
	}
	if !strings.Contains(w.Body.String(), "database") {
		t.Errorf("响应体 = %q, 应当指出是哪一项没就绪", w.Body.String())
	}
}

// TestReadiness_NeverLeaksErrorDetail 响应体只给检查项名字, 不回显错误。
//
// 探针端点在集群里是可达的, 而数据库错误里可能带 DSN 片段 (主机名、用户名)。
func TestReadiness_NeverLeaksErrorDetail(t *testing.T) {
	const secret = "user:passw0rd@tcp(10.0.0.5:3306)"
	mux := healthMux(Check{Name: "database", Probe: func(context.Context) error {
		return errors.New("dial failed: " + secret)
	}})

	if body := get(mux, "/readyz").Body.String(); strings.Contains(body, secret) {
		t.Errorf("就绪响应回显了错误详情, 其中含连接串: %q", body)
	}
}

// TestReadiness_AllPass 全部通过才算就绪。
func TestReadiness_AllPass(t *testing.T) {
	mux := healthMux(
		Check{Name: "database", Probe: func(context.Context) error { return nil }},
		Check{Name: "signing-key", Probe: func(context.Context) error { return nil }},
	)
	if w := get(mux, "/readyz"); w.Code != http.StatusOK {
		t.Errorf("/readyz 返回 %d, 期望 200", w.Code)
	}
}

// TestHealth_NoStore 探针响应不该被任何中间层缓存 —— 缓存住就等于探针失效。
func TestHealth_NoStore(t *testing.T) {
	mux := healthMux()
	for _, path := range []string{"/healthz", "/readyz", "/health"} {
		if cc := get(mux, path).Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s 的 Cache-Control = %q, 期望 no-store —— 被缓存的探针等于没有探针", path, cc)
		}
	}
}
