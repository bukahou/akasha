// Package session 中枢会话 = SSO 的载体。
// cookie 里是 256-bit 随机明文 token, 表里只存 SHA-256 (库泄漏不等于会话泄漏)。
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"gorm.io/gorm"
)

// CookieName 中枢会话 cookie 名。
const CookieName = "akasha_session"

// Session 对应 sessions 表。
type Session struct {
	ID        int64     `gorm:"column:id;primaryKey"`
	UserID    int64     `gorm:"column:user_id"`
	TokenHash string    `gorm:"column:token_hash"`
	UserAgent string    `gorm:"column:user_agent"`
	IPAddress string    `gorm:"column:ip_address"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
	Revoked   bool      `gorm:"column:revoked"`
}

func (Session) TableName() string { return "sessions" }

// Store 会话的创建/校验/吊销 + cookie 收发。
type Store struct {
	db           *gorm.DB
	ttl          time.Duration
	cookieSecure bool
}

func NewStore(db *gorm.DB, ttl time.Duration, cookieSecure bool) *Store {
	return &Store{db: db, ttl: ttl, cookieSecure: cookieSecure}
}

// Issue 建会话并把 cookie 写进响应。
func (s *Store) Issue(ctx context.Context, w http.ResponseWriter, userID int64, userAgent, ip string) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := hex.EncodeToString(raw)

	sess := &Session{
		UserID:    userID,
		TokenHash: hashToken(token),
		UserAgent: userAgent,
		IPAddress: ip,
		ExpiresAt: time.Now().Add(s.ttl),
	}
	if err := s.db.WithContext(ctx).Create(sess).Error; err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(s.ttl.Seconds()),
		HttpOnly: true,
		Secure:   s.cookieSecure,
		// Lax: 顶级跳转 (RP 302 过来的 /authorize) 会带 cookie — SSO 免登录的前提;
		// Strict 会把跨站跳转的 cookie 掐掉, SSO 直接失效
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// Resolve 从请求 cookie 解析有效会话; 无/过期/吊销返回 nil (不报错, 无会话是正常态)。
func (s *Store) Resolve(ctx context.Context, r *http.Request) (*Session, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	var sess Session
	err = s.db.WithContext(ctx).
		Where("token_hash = ? AND revoked = 0 AND expires_at > ?", hashToken(c.Value), time.Now()).
		First(&sess).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// Revoke 吊销当前请求的会话并清 cookie (登出)。
func (s *Store) Revoke(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
		if err := s.db.WithContext(ctx).Model(&Session{}).
			Where("token_hash = ?", hashToken(c.Value)).
			Update("revoked", true).Error; err != nil {
			return err
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
