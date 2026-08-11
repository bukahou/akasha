// Package storage 数据库连接的装配与日志策略。
//
// # 存在理由
//
// main.go 是装配蓝图, 不该含 GORM 的配置细节 (日志级别 / 慢查询阈值 / 参数过滤)。
// 这些是"存储层策略", 集中在本包 —— 换驱动或调策略只动这里, 装配蓝图保持可读。
package storage

import (
	"fmt"
	"log/slog"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// slowQueryThreshold 超过此时长的 SQL 以 WARN 记录。
// 本项目全部查询都走唯一索引, 200ms 已经极宽松 —— 真触发就说明出事了
// (索引失效 / 网络劣化 / 表膨胀), 值得被日志叫醒。
const slowQueryThreshold = 200 * time.Millisecond

// OpenMySQL 建立连接池并装上日志桥接。失败即返回 error 让调用方 fail-fast。
func OpenMySQL(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: newGormLogger()})
	if err != nil {
		return nil, fmt.Errorf("连接数据库失败: %w", err)
	}
	return db, nil
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
func newGormLogger() gormlogger.Interface {
	return gormlogger.NewSlogLogger(slog.Default(), gormlogger.Config{
		LogLevel:                  gormlogger.Warn, // 屏蔽逐条 SQL, 只留慢查询与真实错误
		SlowThreshold:             slowQueryThreshold,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
	})
}
