package op

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AuthCode 对应 auth_codes 表 — 事务①的断点快照。
type AuthCode struct {
	ID            int64     `gorm:"column:id;primaryKey"`
	CodeHash      string    `gorm:"column:code_hash"`
	ClientID      string    `gorm:"column:client_id"`
	UserID        int64     `gorm:"column:user_id"`
	RedirectURI   string    `gorm:"column:redirect_uri"`
	Scope         string    `gorm:"column:scope"`
	Nonce         string    `gorm:"column:nonce"`
	PKCEChallenge string    `gorm:"column:pkce_challenge"`
	ExpiresAt     time.Time `gorm:"column:expires_at"`
	Consumed      bool      `gorm:"column:consumed"`
}

func (AuthCode) TableName() string { return "auth_codes" }

// RefreshToken 对应 refresh_tokens 表。
type RefreshToken struct {
	ID        int64  `gorm:"column:id;primaryKey"`
	TokenHash string `gorm:"column:token_hash"`
	// FamilyID 令牌家族 = 签发这条链的原始 auth_code 的 code_hash。
	// 滚动刷新时由父 token 继承, 使整条链可被一次性连坐撤销。
	FamilyID string `gorm:"column:family_id"`
	UserID   int64  `gorm:"column:user_id"`
	ClientID string `gorm:"column:client_id"`
	// Scope 原始授权范围, 滚动刷新时原样继承。
	// RFC 6749 §6: 刷新出的 token 其范围不得超过原始授权。
	Scope     string    `gorm:"column:scope"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
	Revoked   bool      `gorm:"column:revoked"`
}

func (RefreshToken) TableName() string { return "refresh_tokens" }

// 两种凭证各有各的错误 —— 文案会原样进 RP 收到的 error_description,
// 复用一个变量会让 refresh 失败时报"授权码无效", 排查的人直接被带偏。
//
// Replayed 与 Invalid 分开, 是因为两者的【安全含义】不同:
// Invalid 可能只是过期或手误, Replayed 则意味着有人手里握着一份本该作废的凭证 ——
// 后者要触发连坐撤销并记安全事件日志。对外仍统一为 invalid_grant, 不告诉调用方
// 我们识别出了重放 (那等于给攻击者反馈)。
var (
	ErrCodeInvalid     = errors.New("授权码无效或已使用")
	ErrCodeReplayed    = errors.New("授权码重放")
	ErrRefreshInvalid  = errors.New("refresh token 无效或已使用")
	ErrRefreshReplayed = errors.New("refresh token 重放")
)

// Repository auth_codes / refresh_tokens 两表访问。
type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) InsertCode(ctx context.Context, ac *AuthCode) error {
	return r.db.WithContext(ctx).Create(ac).Error
}

// ConsumeCode 原子消费: UPDATE ... WHERE consumed=0 命中才算成功 (一次性, 防并发双兑)。
//
// RowsAffected==0 有三种原因, 必须区分开 —— 只有"已消费"是安全事件:
//
//	code 不存在   → 无意义的请求
//	code 已过期   → 迟到的正常请求
//	code 已消费   → ⚠️ 重放。同一张一次性票被用了两次, 说明它落到了第二个人手里
//
// 第三种触发 RFC 6819 §5.2.1.1 的要求: 撤销由这张 code 签发的全部 token。
// 只拒绝这一次是不够的 —— 攻击者手上那套已经换到的 token 仍然有效。
func (r *Repository) ConsumeCode(ctx context.Context, code string) (*AuthCode, error) {
	hash := hashOpaque(code)
	res := r.db.WithContext(ctx).Model(&AuthCode{}).
		Where("code_hash = ? AND consumed = 0 AND expires_at > ?", hash, time.Now()).
		Update("consumed", true)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		var ac AuthCode
		if err := r.db.WithContext(ctx).Where("code_hash = ?", hash).First(&ac).Error; err == nil && ac.Consumed {
			// family_id 就是这张 code 的 hash —— 由它签发的整条 refresh 链一起作废
			revoked, rerr := r.RevokeFamily(ctx, hash)
			if rerr != nil {
				return nil, rerr
			}
			slog.Warn("检测到授权码重放, 已撤销该家族全部 refresh token",
				"client_id", ac.ClientID, "user_id", ac.UserID, "revoked_count", revoked)
			return nil, ErrCodeReplayed
		}
		return nil, ErrCodeInvalid
	}
	var ac AuthCode
	if err := r.db.WithContext(ctx).Where("code_hash = ?", hash).First(&ac).Error; err != nil {
		return nil, err
	}
	return &ac, nil
}

func (r *Repository) InsertRefresh(ctx context.Context, rt *RefreshToken) error {
	return r.db.WithContext(ctx).Create(rt).Error
}

// ConsumeRefresh 滚动刷新: 旧 token 原子吊销, 成功才发新的。
//
// 与 ConsumeCode 同理, "已吊销的 token 又被使用"是重放信号 —— 而且是最典型的
// 泄漏形态: 攻击者窃得 refresh 抢先用掉, 合法用户随后使用被拒。若只是拒绝,
// 系统等于"挡住了受害者、放过了攻击者", 且无人察觉。
//
// ⚠️ 已知取舍: 客户端并发刷新或网络重试也会撞上这条判定, 导致整条链被撤销、
// 用户需要重新登录。RFC 9700 讨论过这个误报, 结论是宁可误伤 —— 无法从服务端
// 区分"重试"与"窃取", 而放过后者的代价高得多。
func (r *Repository) ConsumeRefresh(ctx context.Context, token string) (*RefreshToken, error) {
	hash := hashOpaque(token)
	res := r.db.WithContext(ctx).Model(&RefreshToken{}).
		Where("token_hash = ? AND revoked = 0 AND expires_at > ?", hash, time.Now()).
		Update("revoked", true)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		var rt RefreshToken
		if err := r.db.WithContext(ctx).Where("token_hash = ?", hash).First(&rt).Error; err == nil && rt.Revoked {
			revoked, rerr := r.RevokeFamily(ctx, rt.FamilyID)
			if rerr != nil {
				return nil, rerr
			}
			slog.Warn("检测到 refresh token 重放, 已撤销整个令牌家族",
				"client_id", rt.ClientID, "user_id", rt.UserID, "revoked_count", revoked)
			return nil, ErrRefreshReplayed
		}
		return nil, ErrRefreshInvalid
	}
	var rt RefreshToken
	if err := r.db.WithContext(ctx).Where("token_hash = ?", hash).First(&rt).Error; err != nil {
		return nil, err
	}
	return &rt, nil
}

// RevokeFamily 撤销一个令牌家族中所有仍然有效的 refresh token, 返回撤销条数。
//
// ⚠️ 撤销不到已签发的 access_token —— 它是自包含的 JWT, 下游靠公钥离线验签,
// akasha 没有机会介入。这是 JWT 型 OP 的固有限制: 泄漏后的封堵窗口等于
// access_token 的 TTL (当前 1 小时)。缩短 TTL 或引入 introspection 才能收窄,
// 两者各有代价, 当前接受这个窗口。
func (r *Repository) RevokeFamily(ctx context.Context, familyID string) (int64, error) {
	if familyID == "" {
		return 0, nil
	}
	res := r.db.WithContext(ctx).Model(&RefreshToken{}).
		Where("family_id = ? AND revoked = 0", familyID).
		Update("revoked", true)
	return res.RowsAffected, res.Error
}

// PairwiseSubRecord 对应 pairwise_subs 表 —— sub 的反查映射。
type PairwiseSubRecord struct {
	ID       int64  `gorm:"column:id;primaryKey"`
	ClientID string `gorm:"column:client_id"`
	Sub      string `gorm:"column:sub"`
	UserID   int64  `gorm:"column:user_id"`
}

func (PairwiseSubRecord) TableName() string { return "pairwise_subs" }

// RecordPairwiseSub 登记一条 sub → user 映射 (已存在则忽略)。
//
// 每次签发 token 时调用。用 INSERT IGNORE 而非"先查后插": 同一用户重复登录会
// 反复走到这里, 先查后插在并发下会撞唯一索引; 交给数据库幂等处理最省事。
func (r *Repository) RecordPairwiseSub(ctx context.Context, clientID, sub string, userID int64) error {
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&PairwiseSubRecord{ClientID: clientID, Sub: sub, UserID: userID}).Error
}

// LookupPairwiseSub 由 (client_id, sub) 反查 user_id; 查不到返回 0。
func (r *Repository) LookupPairwiseSub(ctx context.Context, clientID, sub string) (int64, error) {
	var rec PairwiseSubRecord
	err := r.db.WithContext(ctx).
		Where("client_id = ? AND sub = ?", clientID, sub).First(&rec).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return rec.UserID, nil
}

func hashOpaque(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
