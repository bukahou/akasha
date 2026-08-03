// Package client RP 注册表: 谁有资格找 akasha 要身份。
// clients 表校验 = OIDC 安全的第一道门: client_id 存在 + secret 匹配 + redirect_uri 精确白名单。
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Client 对应 clients 表。
type Client struct {
	ID           int64  `gorm:"column:id;primaryKey"`
	ClientID     string `gorm:"column:client_id"`
	SecretHash   string `gorm:"column:secret_hash"`
	Name         string `gorm:"column:name"`
	RedirectURIs string `gorm:"column:redirect_uris"` // JSON 数组字符串
}

func (Client) TableName() string { return "clients" }

var (
	ErrClientNotFound    = errors.New("client 未注册")
	ErrSecretMismatch    = errors.New("client_secret 不匹配")
	ErrRedirectURIDenied = errors.New("redirect_uri 不在白名单 (精确匹配)")
)

// Registry clients 表的查询与校验门面。
type Registry struct {
	db *gorm.DB
}

func NewRegistry(db *gorm.DB) *Registry {
	return &Registry{db: db}
}

// FindByClientID 按 client_id 取注册信息。
func (r *Registry) FindByClientID(ctx context.Context, clientID string) (*Client, error) {
	var c Client
	err := r.db.WithContext(ctx).Where("client_id = ?", clientID).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ValidateRedirectURI 白名单精确匹配 (开放重定向的唯一防线, 不做前缀/通配)。
func (r *Registry) ValidateRedirectURI(c *Client, redirectURI string) error {
	var uris []string
	if err := json.Unmarshal([]byte(c.RedirectURIs), &uris); err != nil {
		return fmt.Errorf("redirect_uris 配置解析失败: %w", err)
	}
	for _, u := range uris {
		if u == redirectURI {
			return nil
		}
	}
	return ErrRedirectURIDenied
}

// Authenticate 后信道 client 认证 (/token 用): client_id + client_secret。
func (r *Registry) Authenticate(ctx context.Context, clientID, clientSecret string) (*Client, error) {
	c, err := r.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(c.SecretHash), []byte(clientSecret)) != nil {
		return nil, ErrSecretMismatch
	}
	return c, nil
}
