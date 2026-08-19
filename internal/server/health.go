package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// # 为什么要分成两个端点
//
// K8s 的两个探针问的是【不同的问题】, 用同一个答案回答两者会导致真实故障:
//
//	liveness  "这个进程还有救吗?"   → 答否就【重启容器】
//	readiness "现在能接流量吗?"     → 答否就【摘出负载均衡】
//
// 数据库挂掉时正确的反应是"摘出去等它恢复", 而不是"把所有 Pod 重启一遍"——
// 后者既救不了 DB, 还会在它恢复时制造一波冷启动。反过来, 只有 liveness 时
// DB 挂掉的 Pod 会被判定就绪并继续接流量, 每个请求都 500。
//
// 所以 liveness 必须【不查任何外部依赖】: 进程能响应就算活着。
// 依赖检查全部归 readiness。
//
// 本包不认识数据库也不认识密钥 —— 检查项由装配方以函数注入,
// server 因此保持零内部依赖。

// Check 一项就绪检查。Name 会出现在响应体里, 便于一眼看出是谁没就绪。
type Check struct {
	Name  string
	Probe func(ctx context.Context) error
}

// readinessTimeout 单次就绪检查的上限。
// 探针本身有超时, 这里更短一点, 保证我们主动返回而不是被 kubelet 掐断 ——
// 前者能在响应体里说明是哪一项超时, 后者只留下一条无信息量的超时记录。
const readinessTimeout = 2 * time.Second

// Health 存活与就绪端点。
type Health struct {
	checks []Check
}

func NewHealth(checks ...Check) *Health { return &Health{checks: checks} }

func (h *Health) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.live)
	mux.HandleFunc("GET /readyz", h.ready)
	// /health 保留为 /healthz 的别名 —— 它在旧文档与部署清单里出现过,
	// 悄悄消失会让探针配置在某次发版后突然 404
	mux.HandleFunc("GET /health", h.live)
}

// live 存活: 只要能走到这里, 进程就是活的。刻意不做任何检查。
func (h *Health) live(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// ready 就绪: 全部检查通过才算。任一项失败返回 503 并指名道姓。
func (h *Health) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()

	for _, c := range h.checks {
		if err := c.Probe(ctx); err != nil {
			// 探针失败是运维要看的事件, 但它可能每秒发生一次 —— 用 Warn 而非 Error,
			// 且把原因带上: "not ready" 三个字对排查毫无帮助
			slog.Warn("就绪检查未通过", "check", c.Name, "err", err)
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
			// 响应体只给检查项名字, 不回显 err —— 错误里可能带 DSN 片段
			_, _ = w.Write([]byte("not ready: " + c.Name))
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}
