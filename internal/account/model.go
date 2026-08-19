package account

import "time"

// User 对应 users 表 — 身份权威。
//
// ⚠️ ID 是【表内主键，永不对外暴露】。对下游的身份标识是 pairwise sub,
// 由 op 包用 InternalID 现算 (见 op.PairwiseSub)。
// 曾经直接拿 ID 当 sub —— 那会在 akasha 重建后 AUTO_INCREMENT 归 1 时造成【串号】
// (A 用户登入 B 用户的账号), 且违反 OIDC Core §2 的 never-reassigned 要求。
type User struct {
	ID int64 `gorm:"column:id;primaryKey"`
	// InternalID 内部稳定标识 = SHA256(provider \x00 upstream_subject)。
	// 由上游身份派生而非随机: akasha 删库重建后同一个上游账号能算出同一个值,
	// 于是各下游的 pairwise sub 也不变 —— 用户重新登录即自动认回原档案。
	// 永不外泄 (泄漏 = 下游可比对出同一个人, pairwise 立即破功)。
	InternalID    string    `gorm:"column:internal_id"`
	Username      string    `gorm:"column:username"`
	Email         string    `gorm:"column:email"` // 参考信息, 非身份键; 空串时 repository Omit → DB 落 NULL
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
