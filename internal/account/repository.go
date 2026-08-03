package account

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

// Repository users + federated_identities 两表访问。
type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// ---- users ----

func (r *Repository) GetUserByID(ctx context.Context, id int64) (*User, error) {
	return r.firstUser(ctx, "id = ?", id)
}

func (r *Repository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return r.firstUser(ctx, "username = ?", username)
}

// GetUserByLoginName 密码登录键: username 或 email 均可 (登录框一个输入框两用)。
func (r *Repository) GetUserByLoginName(ctx context.Context, loginName string) (*User, error) {
	return r.firstUser(ctx, "username = ? OR email = ?", loginName, loginName)
}

func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return r.firstUser(ctx, "email = ?", email)
}

func (r *Repository) ExistsUsername(ctx context.Context, username string) (bool, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&User{}).Where("username = ?", username).Count(&n).Error
	return n > 0, err
}

// InsertUser 建号; email 为空串时 Omit 该列 → DB 默认 NULL
// (uk_email 唯一索引只豁免 NULL 不豁免 '', 两个无邮箱用户存 '' 会撞索引)。
func (r *Repository) InsertUser(ctx context.Context, u *User) error {
	tx := r.db.WithContext(ctx)
	if u.Email == "" {
		tx = tx.Omit("email")
	}
	return tx.Create(u).Error
}

func (r *Repository) firstUser(ctx context.Context, query string, args ...any) (*User, error) {
	var u User
	err := r.db.WithContext(ctx).Where(query, args...).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ---- federated_identities ----

func (r *Repository) GetIdentity(ctx context.Context, provider, subject string) (*FederatedIdentity, error) {
	var fi FederatedIdentity
	err := r.db.WithContext(ctx).
		Where("provider = ? AND subject = ?", provider, subject).
		First(&fi).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &fi, nil
}

func (r *Repository) InsertIdentity(ctx context.Context, fi *FederatedIdentity) error {
	tx := r.db.WithContext(ctx)
	if fi.Email == "" {
		tx = tx.Omit("email")
	}
	return tx.Create(fi).Error
}
