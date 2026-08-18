package op

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// PurgeExpired 是本仓唯一的 DELETE。WHERE 写错不会报错, 只会把还在用的
// refresh token 删掉 —— 所有用户在下次刷新时被静默登出, 且无从追溯。
// 这类语句必须对着【真实数据库】验, SQL 方言与时间比较都不能靠推理。
//
// 与 account 的并发测试同一模式, 默认跳过:
//
//	AKASHA_TEST_DB_DSN="$AKASHA_DB_DSN" go test ./internal/op/ -run Purge -v
func purgeTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("AKASHA_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("未设置 AKASHA_TEST_DB_DSN, 跳过需要数据库的测试")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("连接测试数据库失败: %v", err)
	}
	return db
}

// TestPurgeExpired ⭐ 只删过了保留期的, 一行都不能多删。
//
// 布置六行数据横跨保留期两侧, 断言【每一行】的去留 —— 而不只是
// "删掉的条数对不对"。条数对而删错行, 是这类 bug 最典型的形态。
func TestPurgeExpired(t *testing.T) {
	db := purgeTestDB(t)
	repo := NewRepository(db)

	now := time.Now()
	tag := fmt.Sprintf("purge-test-%d", now.UnixNano())

	// (名字, expires_at, 是否应当被删)
	codes := []struct {
		name    string
		expires time.Time
		purged  bool
	}{
		{"code-live", now.Add(time.Minute), false},                        // 还没过期
		{"code-just-expired", now.Add(-time.Minute), false},               // 刚过期, 排查还用得上
		{"code-within-retention", now.Add(-authCodeRetention / 2), false}, // 保留期内
		{"code-past-retention", now.Add(-authCodeRetention - time.Minute), true},
	}
	refreshes := []struct {
		name    string
		expires time.Time
		revoked bool
		purged  bool
	}{
		{"refresh-live", now.Add(24 * time.Hour), false, false},                    // 在用
		{"refresh-revoked-live", now.Add(24 * time.Hour), true, false},             // 已撤销但没过期: 仍须挡重放
		{"refresh-within-retention", now.Add(-refreshRetention / 2), false, false}, // 过期但在保留期内
		{"refresh-past-retention", now.Add(-refreshRetention - time.Hour), false, true},
		{"refresh-revoked-past", now.Add(-refreshRetention - time.Hour), true, true}, // 撤销记录也有保留期
	}

	for i, c := range codes {
		if err := repo.InsertCode(context.Background(), &AuthCode{
			CodeHash: fmt.Sprintf("%s-%d", tag, i), ClientID: tag, UserID: 1,
			RedirectURI: "https://example.test/cb", Scope: "openid", ExpiresAt: c.expires,
		}); err != nil {
			t.Fatalf("插入 %s 失败: %v", c.name, err)
		}
	}
	for i, rt := range refreshes {
		if err := repo.InsertRefresh(context.Background(), &RefreshToken{
			TokenHash: fmt.Sprintf("%s-r%d", tag, i), FamilyID: tag, UserID: 1,
			ClientID: tag, Scope: "openid", ExpiresAt: rt.expires, Revoked: rt.revoked,
		}); err != nil {
			t.Fatalf("插入 %s 失败: %v", rt.name, err)
		}
	}
	t.Cleanup(func() {
		db.Where("client_id = ?", tag).Delete(&AuthCode{})
		db.Where("client_id = ?", tag).Delete(&RefreshToken{})
	})

	if _, _, err := repo.PurgeExpired(context.Background(), now); err != nil {
		t.Fatalf("清理失败: %v", err)
	}

	// 逐行核对去留 —— 条数对而删错行是这类 bug 最典型的形态
	for i, c := range codes {
		var n int64
		db.Model(&AuthCode{}).Where("code_hash = ?", fmt.Sprintf("%s-%d", tag, i)).Count(&n)
		if gone := n == 0; gone != c.purged {
			verb := map[bool]string{true: "被删了", false: "还在"}
			t.Errorf("%s %s, 期望%s", c.name, verb[gone], verb[c.purged])
		}
	}
	for i, rt := range refreshes {
		var n int64
		db.Model(&RefreshToken{}).Where("token_hash = ?", fmt.Sprintf("%s-r%d", tag, i)).Count(&n)
		if gone := n == 0; gone != rt.purged {
			verb := map[bool]string{true: "被删了", false: "还在"}
			t.Errorf("%s %s, 期望%s\n  删掉在用的 refresh = 所有用户下次刷新时被静默登出", rt.name, verb[gone], verb[rt.purged])
		}
	}
}

// TestPurgeExpired_LeavesPairwiseSubsAlone pairwise_subs 绝不能被清理。
//
// 它是 /userinfo 的反查表, 与 token 生命周期无关 ——
// 删掉等于让老用户的 userinfo 永久失效 (sub 是单向哈希, 反推不回来)。
func TestPurgeExpired_LeavesPairwiseSubsAlone(t *testing.T) {
	db := purgeTestDB(t)
	repo := NewRepository(db)

	tag := fmt.Sprintf("purge-sub-%d", time.Now().UnixNano())
	if err := repo.RecordPairwiseSub(context.Background(), tag, tag, 1); err != nil {
		t.Fatalf("登记映射失败: %v", err)
	}
	t.Cleanup(func() { db.Where("client_id = ?", tag).Delete(&PairwiseSubRecord{}) })

	// 用一个远在未来的 now, 让保留期判据对任何行都成立 —— 最激进的清理
	if _, _, err := repo.PurgeExpired(context.Background(), time.Now().Add(10*365*24*time.Hour)); err != nil {
		t.Fatalf("清理失败: %v", err)
	}

	var n int64
	db.Model(&PairwiseSubRecord{}).Where("client_id = ?", tag).Count(&n)
	if n != 1 {
		t.Error("pairwise_subs 的行被清理了 —— 老用户的 /userinfo 将永久失效")
	}
}
