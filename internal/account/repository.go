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

// 这里也【故意没有】非事务的 InsertUser / InsertIdentity ——
// 建号必须走 CreateUserWithIdentity, 单独插入会重新制造孤儿 user 行。
//
// 这里【故意没有】GetUserByEmail —— 2026-08-15 定案不做邮箱认亲后它失去了唯一用途。
// 不留作"以后可能有用": 一个现成的按邮箱查用户的方法, 就是在给恢复邮箱认亲留门。
// email 在本表是参考信息, 不是身份键。

func (r *Repository) ExistsUsername(ctx context.Context, username string) (bool, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&User{}).Where("username = ?", username).Count(&n).Error
	return n > 0, err
}

// CreateUserWithIdentity 在【一个事务里】建号并建立上游身份关联。
//
// # 为什么必须是事务
//
// 曾经是两次独立调用。并发首登时两个请求都查不到 identity → 都建 user →
// 第二个建 identity 撞唯一索引失败, 而【第一个的 users 行已经落库】——
// 留下一条占着 username、却没有任何 identity 指向它的孤儿记录, 而且下次
// 同一个上游身份登录还会再建一条新的。唯一索引挡住了重复关联, 挡不住这个。
//
// 事务让这两步同生共死: identity 建不成, user 也不留。
func (r *Repository) CreateUserWithIdentity(ctx context.Context, u *User, fi *FederatedIdentity) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		userTx := tx
		if u.Email == "" {
			userTx = tx.Omit("email")
		}
		if err := userTx.Create(u).Error; err != nil {
			return err
		}
		// 主键由上一步填回, 关联行才知道该指向谁
		fi.UserID = u.ID
		idTx := tx
		if fi.Email == "" {
			idTx = tx.Omit("email")
		}
		return idTx.Create(fi).Error
	})
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
