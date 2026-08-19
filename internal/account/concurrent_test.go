package account

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 并发建号的正确性没法用纯函数验证 —— 它的判据是"数据库里最后剩下什么"。
// 所以这一组【需要真实数据库】, 默认跳过, 只在显式给出 AKASHA_TEST_DB_DSN 时运行:
//
//	AKASHA_TEST_DB_DSN="$AKASHA_DB_DSN" go test ./internal/account/ -run Concurrent -v
//
// 单独用一个环境变量而不是复用 AKASHA_DB_DSN, 是为了让"跑测试"必须是一个
// 有意识的动作 —— 它会往库里写数据, 不该因为终端里恰好加载了开发配置就发生。
func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("AKASHA_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("未设置 AKASHA_TEST_DB_DSN, 跳过需要数据库的测试")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("连接测试数据库失败: %v", err)
	}
	return db
}

// TestConcurrentFirstLogin 同一个上游身份并发首次登录。
//
// # 这条测试防的是什么
//
// 曾经 InsertUser 与 InsertIdentity 是两次独立调用, 没有事务。并发下:
//
//	请求 A: GetIdentity → nil → InsertUser ✓ → InsertIdentity ✓
//	请求 B: GetIdentity → nil → InsertUser ✓ → InsertIdentity ✗ 撞唯一索引
//	                              ↑ 这一行留在库里了
//
// 结果是一条占着 username、却没有任何 identity 指向它的孤儿记录 ——
// 唯一索引挡住了重复关联, 挡不住这个。判据因此不是"有没有报错",
// 而是【库里最后剩下几条 user】。
func TestConcurrentFirstLogin(t *testing.T) {
	db := testDB(t)
	repo := NewRepository(db)
	svc := NewService(repo)

	// 用时间戳造一个本次运行独有的上游身份, 避免与历史数据串味
	subject := fmt.Sprintf("test-subject-%d", time.Now().UnixNano())
	id := UpstreamIdentity{
		Provider:      "testprovider",
		Subject:       subject,
		Email:         fmt.Sprintf("concurrent-%d@example.test", time.Now().UnixNano()),
		EmailVerified: true,
		Name:          "Concurrent Test",
	}
	internalID := DeriveInternalID(id.Provider, id.Subject)

	t.Cleanup(func() {
		db.Exec("DELETE fi FROM federated_identities fi JOIN users u ON fi.user_id = u.id WHERE u.internal_id = ?", internalID)
		db.Exec("DELETE FROM users WHERE internal_id = ?", internalID)
	})

	const racers = 8
	var wg sync.WaitGroup
	results := make([]*User, racers)
	errs := make([]error, racers)
	start := make(chan struct{})

	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // 尽量让它们真的同时冲进去
			results[i], errs[i] = svc.ResolveUpstreamIdentity(context.Background(), id)
		}()
	}
	close(start)
	wg.Wait()

	// ① 全部应当成功 —— 并发不该让任何一个用户看到 500
	for i, err := range errs {
		if err != nil {
			t.Errorf("第 %d 个并发请求失败: %v\n  并发首登应当复用先建好的账号, 而不是把错误抛给用户", i, err)
		}
	}

	// ② 所有人必须拿到【同一个】用户
	var first int64
	for i, u := range results {
		if u == nil {
			continue
		}
		if first == 0 {
			first = u.ID
		} else if u.ID != first {
			t.Errorf("第 %d 个请求拿到 user_id=%d, 与第一个 %d 不同 —— 同一个上游身份被建成了多个账号", i, u.ID, first)
		}
	}

	// ③ ⭐ 核心判据: 库里只能有一条 user、一条 identity。多出来的就是孤儿
	var userCount, identityCount int64
	db.Table("users").Where("internal_id = ?", internalID).Count(&userCount)
	db.Table("federated_identities").Where("provider = ? AND subject = ?", id.Provider, id.Subject).Count(&identityCount)

	if userCount != 1 {
		t.Errorf("users 表里有 %d 条记录, 期望 1 条\n"+
			"  多出来的是孤儿行: 占着 username, 却没有 identity 指向它", userCount)
	}
	if identityCount != 1 {
		t.Errorf("federated_identities 表里有 %d 条记录, 期望 1 条", identityCount)
	}
}
