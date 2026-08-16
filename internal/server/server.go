// Package server http.Server 启停 + 优雅关停 (geass pkg/server 模式的本仓版)。
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"
)

// Run 阻塞运行 HTTP 服务直到 SIGINT/SIGTERM, 然后 10s 窗口优雅关停。
func Run(addr string, handler http.Handler) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// # 超时必须逐项显式设置
	//
	// http.Server 的零值意味着【无超时】。公网暴露的服务不设这些, 慢速请求
	// (Slowloris 变体) 能长期占住连接直到耗尽资源 —— 攻击成本极低。
	//
	// 取值依据: 本服务最慢的一次请求是联邦回调 (要出站调上游换 token),
	// 通常 1-3 秒; 30 秒给足余量又不至于让挂起的连接堆积。
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
		// 读完请求头的窗口 —— 挡住只发一半头就赖着不走的连接
		ReadHeaderTimeout: 10 * time.Second,
		// 读完整个请求 (含 body)
		ReadTimeout: 30 * time.Second,
		// 从读完请求头到写完响应的总时长, 覆盖 handler 执行时间
		WriteTimeout: 30 * time.Second,
		// keep-alive 连接的空闲上限
		IdleTimeout: 120 * time.Second,
		// 请求头总大小上限 (默认 1MB 偏大)
		MaxHeaderBytes: 64 << 10,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("akasha 服务监听中", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("收到退出信号, 开始优雅关停")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
