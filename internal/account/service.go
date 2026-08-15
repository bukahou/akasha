// account 身份权威的业务规则: 密码验证 / 上游认亲+自动建号 / username 生成。
package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"strings"

	"github.com/bukahou/akasha/internal/account/password"
)

var (
	ErrInvalidCredentials = errors.New("用户名或密码错误")
	ErrPasswordLoginOff   = errors.New("此账号未设置密码, 请使用第三方登录")
	ErrUserBanned         = errors.New("账号已封禁")
)

// UpstreamIdentity 上游 IdP 验证后的身份断言 (federation 包产出, 本包消费)。
type UpstreamIdentity struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	AvatarURL     string
}

// Service 身份权威门面。
type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

// VerifyPassword 密码登录: loginName (username 或 email) + 明文密码 → 用户。
func (s *Service) VerifyPassword(ctx context.Context, loginName, plain string) (*User, error) {
	u, err := s.repo.GetUserByLoginName(ctx, loginName)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrInvalidCredentials
	}
	// 联邦建号的账号 password 为空串: 明确指路而不是报"密码错误"
	if u.Password == "" {
		return nil, ErrPasswordLoginOff
	}
	if err := password.Verify(plain, u.Password); err != nil {
		if errors.Is(err, password.ErrMismatch) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if u.Status == StatusBanned {
		return nil, ErrUserBanned
	}
	return u, nil
}

// ResolveUpstreamIdentity 上游身份 → akasha 账号 (所有 provider 无分支):
// ①查 (provider,subject) 命中即取用户 → ②未命中直接建号 → ③建 identity 行。
//
// # 为什么不做邮箱认亲 (2026-08-15 定案)
//
// 曾有一步"未命中但邮箱已验证 → 认亲到已有账号"。已删除, 因为它把安全责任
// 委托给了上游: 接 N 个 provider 时, 只要【其中一个】的邮箱验证有漏洞,
// 攻击者就能在那儿注册并填入受害者邮箱, 一登录即接管受害者账号
// (Sign-in-with-X 账号接管)。
//
// 现在的规则是硬的: **一个上游身份 = 一个 akasha 账号**, 永远一对一。
// 同一个人的 Google 账号与 GitHub 账号是两个互不相通的账号。
// 要合并只能靠用户主动绑定 (先证明自己是谁, 再关联), 不能靠系统猜。
//
// 副产品: 流程从四步缩到三步, 且再无"该认哪个账号"的判断分支。
func (s *Service) ResolveUpstreamIdentity(ctx context.Context, id UpstreamIdentity) (*User, error) {
	// ① 老门客: 身份已关联
	if fi, err := s.repo.GetIdentity(ctx, id.Provider, id.Subject); err != nil {
		return nil, err
	} else if fi != nil {
		u, err := s.repo.GetUserByID(ctx, fi.UserID)
		if err != nil {
			return nil, err
		}
		if u == nil {
			return nil, fmt.Errorf("身份关联指向的用户不存在: user_id=%d", fi.UserID)
		}
		if u.Status == StatusBanned {
			return nil, ErrUserBanned
		}
		return u, nil
	}

	// ② 新面孔一律建号 (不查已有账号, 不认亲)
	username, err := s.generateUsername(ctx, id)
	if err != nil {
		return nil, err
	}
	name := id.Name
	if name == "" {
		name = username
	}
	user := &User{
		InternalID:    DeriveInternalID(id.Provider, id.Subject),
		Username:      username,
		Password:      "", // 联邦账号无密码, VerifyPassword 有守卫
		Email:         id.Email,
		EmailVerified: id.EmailVerified,
		Name:          name,
		AvatarURL:     id.AvatarURL,
		Status:        StatusActive,
	}
	if err := s.repo.InsertUser(ctx, user); err != nil {
		return nil, fmt.Errorf("联邦建号失败: %w", err)
	}
	slog.Info("联邦建号", "provider", id.Provider, "user_id", user.ID, "username", username)

	// ③ 建关联: 之后永远走 ①
	fi := &FederatedIdentity{
		UserID:   user.ID,
		Provider: id.Provider,
		Subject:  id.Subject,
		Email:    id.Email,
	}
	if err := s.repo.InsertIdentity(ctx, fi); err != nil {
		return nil, fmt.Errorf("建身份关联失败: %w", err)
	}
	return user, nil
}

// DeriveInternalID 由上游身份派生内部稳定标识。
//
// 用派生而非随机 UUID, 是为了让 akasha 从零重建后仍能自动恢复:
// 同一个上游账号重新登录 → 算出同一个 internal_id → 各下游的 pairwise sub 不变
// → 用户无感地认回原有档案。随机 UUID 做不到这点 (重建即失联, 需逐个应用手动重绑)。
//
// \x00 作分隔符: provider 与 subject 都是可打印字符, 不可能含它,
// 因此 ("goog","le:1") 与 ("google",":1") 这类拼接歧义不会发生。
//
// ⚠️ 前提是上游 subject 稳定。Google / GitHub 是 public 类型 (同一账号对任何 client
// 都给同一个 subject) ✅; Apple 是 pairwise, 换 client_id 就变 —— 将来接 Apple 时
// 那条上游会丧失重建恢复能力 (其他上游不受影响)。
func DeriveInternalID(provider, upstreamSubject string) string {
	sum := sha256.Sum256([]byte(provider + "\x00" + upstreamSubject))
	return hex.EncodeToString(sum[:])
}

// generateUsername 基名(邮箱前缀/上游名) → 清洗 → 冲突加 4 位随机后缀, 重试 3 次。
// 随机而非递增: 防枚举猜账号 + 防并发抢同一后缀。
func (s *Service) generateUsername(ctx context.Context, id UpstreamIdentity) (string, error) {
	base := id.Name
	if id.Email != "" {
		base = strings.SplitN(id.Email, "@", 2)[0]
	}
	base = sanitizeUsername(base)
	if base == "" {
		base = id.Provider + "_user"
	}

	if taken, err := s.repo.ExistsUsername(ctx, base); err != nil {
		return "", err
	} else if !taken {
		return base, nil
	}
	for range 3 {
		n, err := rand.Int(rand.Reader, big.NewInt(10000))
		if err != nil {
			return "", err
		}
		candidate := fmt.Sprintf("%s_%04d", base, n.Int64())
		if taken, err := s.repo.ExistsUsername(ctx, candidate); err != nil {
			return "", err
		} else if !taken {
			return candidate, nil
		}
	}
	return "", errors.New("用户名生成冲突次数过多, 请重试登录")
}

var usernameCleaner = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

func sanitizeUsername(raw string) string {
	cleaned := usernameCleaner.ReplaceAllString(raw, "")
	if len(cleaned) > 32 {
		cleaned = cleaned[:32]
	}
	return cleaned
}
