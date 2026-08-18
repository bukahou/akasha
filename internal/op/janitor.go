package op

import (
	"context"
	"log/slog"
	"time"
)

// # 为什么需要清理
//
// auth_codes 与 refresh_tokens 只增不减: 每次登录写一行 code, 每次刷新写一行
// refresh。它们的生命周期分别是 60 秒和 30 天, 过期之后再无用途, 但没人删。
// 表会一直长, 索引跟着变大, 备份也跟着变大。
//
// # 保留期为什么不是零
//
// 刚过期的行是排查失败登录时最有用的东西 ("这个 code 是什么时候签的、给谁的")。
// 立刻删掉等于把现场一起清了。所以过期之后还留一段, 只清理确实没人会再看的。
//
// # pairwise_subs 为什么不清理
//
// 它是 /userinfo 的反查表, 与 token 的生命周期无关 —— 删掉等于让老用户的
// userinfo 永久失效。这张表的增长是按【用户 × client】而非按次数, 量级完全不同。
const (
	// authCodeRetention code 过期后再保留多久。TTL 只有 60 秒, 一小时足够排查。
	authCodeRetention = time.Hour
	// refreshRetention refresh 过期后再保留多久。
	// 已撤销的行有审计价值 (它记录了一次重放检测), 但那件事发生时已经打了
	// Warn 日志, 行本身留 7 天足够回溯。
	refreshRetention = 7 * 24 * time.Hour
	// janitorInterval 清理间隔。这不是一个需要及时的任务, 一小时一次即可。
	janitorInterval = time.Hour
)

// Janitor 定期清理过期的一次性凭证。
//
// 多副本部署时每个副本都会跑它 —— 这是安全的: DELETE 是幂等的, 谁先跑到
// 谁删掉, 后到的拿到 0 行。为此引入选主机制不值得。
type Janitor struct {
	repo *Repository
}

func NewJanitor(repo *Repository) *Janitor { return &Janitor{repo: repo} }

// Run 阻塞运行直到 ctx 取消。启动时先跑一次, 之后按间隔重复。
//
// 启动即跑一次是有意的: 进程重启比一小时频繁得多的话, 只靠 ticker 永远轮不到。
func (j *Janitor) Run(ctx context.Context) {
	j.purgeOnce(ctx)

	ticker := time.NewTicker(janitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("过期数据清理已停止")
			return
		case <-ticker.C:
			j.purgeOnce(ctx)
		}
	}
}

func (j *Janitor) purgeOnce(ctx context.Context) {
	codes, refreshes, err := j.repo.PurgeExpired(ctx, time.Now())
	if err != nil {
		// 清理失败不影响任何在线功能, 记下来等下一轮即可 —— 绝不能因此退出
		slog.Error("清理过期数据失败", "err", err)
		return
	}
	if codes > 0 || refreshes > 0 {
		slog.Info("清理过期数据", "auth_codes", codes, "refresh_tokens", refreshes)
	}
}
