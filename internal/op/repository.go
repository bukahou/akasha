package op

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"
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
	ID        int64     `gorm:"column:id;primaryKey"`
	TokenHash string    `gorm:"column:token_hash"`
	UserID    int64     `gorm:"column:user_id"`
	ClientID  string    `gorm:"column:client_id"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
	Revoked   bool      `gorm:"column:revoked"`
}

func (RefreshToken) TableName() string { return "refresh_tokens" }

var ErrCodeInvalid = errors.New("授权码无效或已使用")

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

// ConsumeCode 原子消费: UPDATE ... WHERE consumed=0 命中才算成功 (一次性, 防重放/并发双兑)。
func (r *Repository) ConsumeCode(ctx context.Context, code string) (*AuthCode, error) {
	hash := hashOpaque(code)
	res := r.db.WithContext(ctx).Model(&AuthCode{}).
		Where("code_hash = ? AND consumed = 0 AND expires_at > ?", hash, time.Now()).
		Update("consumed", true)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
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
func (r *Repository) ConsumeRefresh(ctx context.Context, token string) (*RefreshToken, error) {
	hash := hashOpaque(token)
	res := r.db.WithContext(ctx).Model(&RefreshToken{}).
		Where("token_hash = ? AND revoked = 0 AND expires_at > ?", hash, time.Now()).
		Update("revoked", true)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, ErrCodeInvalid
	}
	var rt RefreshToken
	if err := r.db.WithContext(ctx).Where("token_hash = ?", hash).First(&rt).Error; err != nil {
		return nil, err
	}
	return &rt, nil
}

func hashOpaque(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
