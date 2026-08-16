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

// 这里【故意没有】GetUserByEmail —— 2026-08-15 定案不做邮箱认亲后它失去了唯一用途。
// 不留作"以后可能有用": 一个现成的按邮箱查用户的方法, 就是在给恢复邮箱认亲留门。
// email 在本表是参考信息, 不是身份键。

func (r *Repository) ExistsUsername(ctx context.Context, username string) (bool, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&User{}).Where("username = ?", username).Count(&n).Error
	return n > 0, err
}

// InsertUser 建号; email 为空串时 Omit 该列 → DB 默认 NULL。
//
// email 的唯一索引已随"不认亲"定案去除 (同一个人的 Google 账号与 GitHub 账号是两个
// 独立账号但邮箱相同, 有唯一索引则第二个上游登录必然插入失败)。
// 仍然做空串→NULL 转换: 语义上"没有邮箱"就该是 NULL 而不是空串, 且 Go 的 string
// 零值是空串不是 NULL, 不显式 Omit 就会写进一堆无意义的空字符串。
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
