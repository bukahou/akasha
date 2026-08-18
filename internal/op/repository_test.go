package op

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

// 原子消费与家族撤销是这个系统里安全含量最高的逻辑, 此前【零测试覆盖】——
// "重放真的会触发连坐撤销"一直只是读代码得出的结论。
//
// 这组必须对着真实数据库跑: 判据是"原子 UPDATE 命中几行", 那是数据库的行为,
// 不是 Go 的行为。用 mock 测等于测了个寂寞。
//
//	AKASHA_TEST_DB_DSN="$AKASHA_DB_DSN" go test ./internal/op/ -run Consume -v

// seedFixture 造一条 code + 同家族的两条 refresh, 返回明文凭证。
// familyID 就是 code 的 hash —— 与生产完全一致的家族关系。
func seedFixture(t *testing.T, db *gorm.DB, repo *Repository) (code string, refreshes []string, tag string) {
	t.Helper()
	tag = fmt.Sprintf("repo-test-%d", time.Now().UnixNano())
	code = tag + "-code"
	familyID := hashOpaque(code)

	if err := repo.InsertCode(context.Background(), &AuthCode{
		CodeHash: familyID, ClientID: tag, UserID: 1,
		RedirectURI: "https://example.test/cb", Scope: "openid",
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("插入 code 失败: %v", err)
	}
	for i := range 2 {
		rt := fmt.Sprintf("%s-refresh-%d", tag, i)
		refreshes = append(refreshes, rt)
		if err := repo.InsertRefresh(context.Background(), &RefreshToken{
			TokenHash: hashOpaque(rt), FamilyID: familyID, UserID: 1,
			ClientID: tag, Scope: "openid", ExpiresAt: time.Now().Add(24 * time.Hour),
		}); err != nil {
			t.Fatalf("插入 refresh 失败: %v", err)
		}
	}
	t.Cleanup(func() {
		db.Where("client_id = ?", tag).Delete(&AuthCode{})
		db.Where("client_id = ?", tag).Delete(&RefreshToken{})
	})
	return code, refreshes, tag
}

func countRevoked(t *testing.T, db *gorm.DB, tag string) int64 {
	t.Helper()
	var n int64
	db.Model(&RefreshToken{}).Where("client_id = ? AND revoked = 1", tag).Count(&n)
	return n
}

// TestConsumeCode_Replay ⭐ code 重放必须撤销由它签发的整条 refresh 链。
//
// RFC 6819 §5.2.1.1: 同一张一次性票被用了两次, 说明它落到了第二个人手里。
// 只拒绝这一次是不够的 —— 攻击者手上那套已经换到的 token 仍然有效。
func TestConsumeCode_Replay(t *testing.T) {
	db := purgeTestDB(t)
	repo := NewRepository(db)
	code, _, tag := seedFixture(t, db, repo)

	// 第一次: 正常消费
	ac, err := repo.ConsumeCode(context.Background(), code)
	if err != nil {
		t.Fatalf("首次消费失败: %v", err)
	}
	if ac.ClientID != tag {
		t.Errorf("取回的 code 归属不对: %s", ac.ClientID)
	}
	if n := countRevoked(t, db, tag); n != 0 {
		t.Errorf("正常消费不该撤销任何 refresh, 实际撤销了 %d 条", n)
	}

	// 第二次: 重放
	_, err = repo.ConsumeCode(context.Background(), code)
	if !errors.Is(err, ErrCodeReplayed) {
		t.Fatalf("重放返回 %v, 期望 ErrCodeReplayed —— 必须与普通失效区分开", err)
	}
	if n := countRevoked(t, db, tag); n != 2 {
		t.Errorf("重放后撤销了 %d 条 refresh, 期望 2 条（整个家族）\n"+
			"  只拒绝这一次是不够的: 攻击者手上已经换到的 token 仍然有效", n)
	}
}

// TestConsumeCode_Distinguishes 三种失败必须区分 —— 只有"已消费"是安全事件。
func TestConsumeCode_Distinguishes(t *testing.T) {
	db := purgeTestDB(t)
	repo := NewRepository(db)

	t.Run("不存在", func(t *testing.T) {
		_, err := repo.ConsumeCode(context.Background(), "never-issued")
		if !errors.Is(err, ErrCodeInvalid) {
			t.Errorf("返回 %v, 期望 ErrCodeInvalid（无意义的请求, 不是安全事件）", err)
		}
	})

	t.Run("已过期", func(t *testing.T) {
		tag := fmt.Sprintf("repo-exp-%d", time.Now().UnixNano())
		code := tag + "-code"
		if err := repo.InsertCode(context.Background(), &AuthCode{
			CodeHash: hashOpaque(code), ClientID: tag, UserID: 1,
			RedirectURI: "https://example.test/cb", Scope: "openid",
			ExpiresAt: time.Now().Add(-time.Minute), // 已过期
		}); err != nil {
			t.Fatalf("插入失败: %v", err)
		}
		t.Cleanup(func() { db.Where("client_id = ?", tag).Delete(&AuthCode{}) })

		_, err := repo.ConsumeCode(context.Background(), code)
		if !errors.Is(err, ErrCodeInvalid) {
			t.Errorf("返回 %v, 期望 ErrCodeInvalid —— 过期是迟到的正常请求, 不该当成重放", err)
		}
	})
}

// TestConsumeCode_Concurrent ⭐ 并发双兑只能有一个成功。
//
// 这正是"原子 UPDATE ... WHERE consumed=0"存在的理由。先查后改会让两个
// 请求都读到 consumed=0 并各自签出一套 token —— 一张 code 换两套。
func TestConsumeCode_Concurrent(t *testing.T) {
	db := purgeTestDB(t)
	repo := NewRepository(db)
	code, _, _ := seedFixture(t, db, repo)

	const racers = 8
	var wg sync.WaitGroup
	errs := make([]error, racers)
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = repo.ConsumeCode(context.Background(), code)
		}()
	}
	close(start)
	wg.Wait()

	var ok int
	for _, err := range errs {
		if err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Errorf("%d 个并发兑换中有 %d 个成功, 期望恰好 1 个\n"+
			"  一张 code 换出多套 token = 一次授权被用了多次", racers, ok)
	}
}

// TestConsumeRefresh_ReplayRevokesFamily ⭐ refresh 重放撤销整族。
//
// 这是最典型的泄漏形态: 攻击者窃得 refresh 抢先用掉, 合法用户随后使用被拒。
// 若只是拒绝, 系统等于"挡住了受害者、放过了攻击者", 且无人察觉。
func TestConsumeRefresh_ReplayRevokesFamily(t *testing.T) {
	db := purgeTestDB(t)
	repo := NewRepository(db)
	_, refreshes, tag := seedFixture(t, db, repo)

	// 正常滚动一次: 只吊销自己
	if _, err := repo.ConsumeRefresh(context.Background(), refreshes[0]); err != nil {
		t.Fatalf("首次刷新失败: %v", err)
	}
	if n := countRevoked(t, db, tag); n != 1 {
		t.Errorf("正常刷新后撤销了 %d 条, 期望 1 条（只有自己）", n)
	}

	// 重放同一张: 整族连坐
	_, err := repo.ConsumeRefresh(context.Background(), refreshes[0])
	if !errors.Is(err, ErrRefreshReplayed) {
		t.Fatalf("重放返回 %v, 期望 ErrRefreshReplayed", err)
	}
	if n := countRevoked(t, db, tag); n != 2 {
		t.Errorf("重放后撤销了 %d 条, 期望 2 条（整个家族）\n"+
			"  同族的另一张若还有效, 攻击者换一张接着用", n)
	}

	// 被连坐的那张此后必须不可用
	if _, err := repo.ConsumeRefresh(context.Background(), refreshes[1]); err == nil {
		t.Error("同族的另一张 refresh 在连坐撤销后仍然可用 —— 撤销没生效")
	}
}

// TestRevokeFamily_ScopedToFamily 连坐只能波及本家族。
//
// family_id 写错或 WHERE 漏条件, 后果是把无关用户一起踢下线。
func TestRevokeFamily_ScopedToFamily(t *testing.T) {
	db := purgeTestDB(t)
	repo := NewRepository(db)

	_, _, tagA := seedFixture(t, db, repo)
	codeB, _, tagB := seedFixture(t, db, repo)

	n, err := repo.RevokeFamily(context.Background(), hashOpaque(codeB))
	if err != nil {
		t.Fatalf("撤销失败: %v", err)
	}
	if n != 2 {
		t.Errorf("撤销了 %d 条, 期望 2 条", n)
	}
	if got := countRevoked(t, db, tagA); got != 0 {
		t.Errorf("另一个家族被波及: 撤销了 %d 条 —— 会把无关用户一起踢下线", got)
	}
	if got := countRevoked(t, db, tagB); got != 2 {
		t.Errorf("本家族只撤销了 %d 条, 期望 2 条", got)
	}

	// 幂等: 再撤一次应当 0 行（已撤销的不重复计数）
	if again, _ := repo.RevokeFamily(context.Background(), hashOpaque(codeB)); again != 0 {
		t.Errorf("重复撤销返回 %d 行, 期望 0 —— WHERE 漏了 revoked = 0", again)
	}
}

// TestRevokeFamily_EmptyIDIsNoop 空 family_id 绝不能变成"撤销所有 family_id 为空的行"。
func TestRevokeFamily_EmptyIDIsNoop(t *testing.T) {
	db := purgeTestDB(t)
	repo := NewRepository(db)
	_, _, tag := seedFixture(t, db, repo)

	if n, err := repo.RevokeFamily(context.Background(), ""); err != nil || n != 0 {
		t.Errorf("空 family_id 撤销了 %d 条 (err=%v), 期望 0 且无副作用", n, err)
	}
	if got := countRevoked(t, db, tag); got != 0 {
		t.Errorf("空 family_id 波及了正常家族: %d 条", got)
	}
}
