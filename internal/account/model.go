package account

import "time"

// User 对应 users 表 — 身份权威。下游应用的 users 是业务档案, 以本表 id 为 sub。
type User struct {
	ID            int64     `gorm:"column:id;primaryKey"`
	Username      string    `gorm:"column:username"`
	Password      string    `gorm:"column:password"` // bcrypt; 联邦建号存空串 (守卫拦密码登录)
	Email         string    `gorm:"column:email"`    // 空串时 repository Omit → DB 落 NULL (uk_email 只豁免 NULL)
	EmailVerified bool      `gorm:"column:email_verified"`
	Name          string    `gorm:"column:name"`
	AvatarURL     string    `gorm:"column:avatar_url"`
	Status        string    `gorm:"column:status"` // active / banned
	CreatedAt     time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt     time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

func (User) TableName() string { return "users" }

const (
	StatusActive = "active"
	StatusBanned = "banned"
)

// FederatedIdentity 对应 federated_identities 表 — 上游身份 → users 多对一。
type FederatedIdentity struct {
	ID        int64     `gorm:"column:id;primaryKey"`
	UserID    int64     `gorm:"column:user_id"`
	Provider  string    `gorm:"column:provider"`
	Subject   string    `gorm:"column:subject"`
	Email     string    `gorm:"column:email"` // 审计用, 空串 Omit 落 NULL
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime"`
}

func (FederatedIdentity) TableName() string { return "federated_identities" }
