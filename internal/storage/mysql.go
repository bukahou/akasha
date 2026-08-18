// Package storage 数据库连接的装配与日志策略。
//
// # 存在理由
//
// main.go 是装配蓝图, 不该含 GORM 的配置细节 (日志级别 / 慢查询阈值 / 参数过滤)。
// 这些是"存储层策略", 集中在本包 —— 换驱动或调策略只动这里, 装配蓝图保持可读。
package storage

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// parseLogLevel 配置值 → GORM 日志级别。无法识别的值退回 warn 并告警,
// 而不是静默用默认值 —— 后者会让"我明明配了 info 怎么没生效"变成一桩悬案。
func parseLogLevel(v string) gormlogger.LogLevel {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "silent":
		return gormlogger.Silent
	case "error":
		return gormlogger.Error
	case "warn", "":
		return gormlogger.Warn
	case "info":
		return gormlogger.Info
	default:
		slog.Warn("无法识别的数据库日志级别, 已退回 warn", "value", v)
		return gormlogger.Warn
	}
}

// slowQueryThreshold 超过此时长的 SQL 以 WARN 记录。
// 本项目全部查询都走唯一索引, 200ms 已经极宽松 —— 真触发就说明出事了
// (索引失效 / 网络劣化 / 表膨胀), 值得被日志叫醒。
const slowQueryThreshold = 200 * time.Millisecond

// 连接池参数。
//
// # 为什么必须显式设置
//
// database/sql 的默认值是 MaxIdleConns=2 且【MaxOpenConns 无上限】。两头都不对:
//
//	无上限   → 突发流量下连接数可以冲到几百, 先打爆的是数据库而不是本服务。
//	          TiDB Cloud Serverless 有连接数配额, 超了是整库拒绝服务
//	空闲仅 2 → 稍有并发就要反复新建连接。每次新建都含 TLS 握手 (生产强制 TLS),
//	          在东京到本地这种链路上是几十毫秒级的开销, 且全落在用户等待里
const (
	// maxOpenConns 本服务的查询全部走唯一索引且都是毫秒级, 25 条足够支撑
	// 远超实际的并发; 真到上限时排队等待也好过压垮数据库。
	maxOpenConns = 25
	// maxIdleConns 与 maxOpen 同量级, 避免"用完就关、下次再建"的抖动。
	// 空闲连接的成本只是数据库侧的一个会话, 远低于反复握手。
	maxIdleConns = 25
	// connMaxLifetime 连接的硬上限。云数据库与中间的负载均衡都会单方面掐掉
	// 长连接, 客户端不主动轮换就会周期性地撞上"连接已被对端关闭"。
	// 比常见的空闲超时短一截, 让轮换发生在我们自己手里。
	connMaxLifetime = 5 * time.Minute
	// connMaxIdleTime 空闲太久的连接主动回收, 免得低峰期挂着一堆没用的会话。
	connMaxIdleTime = 2 * time.Minute
)

// OpenMySQL 建立连接池并装上日志桥接。失败即返回 error 让调用方 fail-fast。
func OpenMySQL(dsn, logLevel string) (*gorm.DB, error) {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: newGormLogger(logLevel)})
	if err != nil {
		return nil, fmt.Errorf("连接数据库失败: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("取底层连接池失败: %w", err)
	}
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxIdleConns)
	sqlDB.SetConnMaxLifetime(connMaxLifetime)
	sqlDB.SetConnMaxIdleTime(connMaxIdleTime)
	return db, nil
}

// PingContext 探活底层连接 (就绪探针用)。
//
// 单独导出而不是让 main 自己 db.DB().PingContext(): 那会把"怎么从 GORM 拿到
// 底层池"这个细节泄漏到装配蓝图里, 而本包存在的理由正是收口这类细节。
func PingContext(ctx context.Context, db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

// newGormLogger GORM 日志桥接到 slog。
//
// 用 GORM 官方的 slog 适配器而非自研桥接 —— 上游已实现且随 GORM 演进,
// 自己写一份只会多一处要维护的代码。代价是 msg 固定为英文 "SQL executed"
// (项目其余部分是中文 msg), 换来的是零维护 + 机器侧按 msg 过滤更方便。
//
// # 三项配置分别修的是什么 (2026-08-10 M1.5 验收发现)
//
// ① IgnoreRecordNotFoundError —— 查无结果不是错误。
//
//	登录时用户不存在、首次启动时公钥未登记, 都是完全正常的业务路径。
//	默认配置把它们打成红色 ERROR, 运维看日志会误判成故障。
//
// ② ParameterizedQueries —— 参数永不进日志。★ 安全相关
//
//	默认会把参数展开成完整 SQL: `WHERE username = 'alice'`。
//	登录查询的参数就是用户在输入框里打的东西 —— 若有人误把密码敲进用户名框,
//	密码就明文落进了日志。开启后只记 `WHERE username = ?`, 参数一律不出现。
//
// ③ Logger 走 slog —— 日志格式统一。
//
//	默认 logger 输出带 ANSI 颜色的纯文本, 与本服务的 JSON 日志混在一起,
//	集群侧采集器解析会失败。桥接到 slog 后全链路都是 JSON。
func newGormLogger(level string) gormlogger.Interface {
	return gormlogger.NewSlogLogger(slog.Default(), gormlogger.Config{
		LogLevel:                  parseLogLevel(level),
		SlowThreshold:             slowQueryThreshold,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
	})
}
