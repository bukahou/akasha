// account 身份权威的业务规则: 密码验证 / 上游认亲+自动建号 / username 生成。
package account

import (
	"context"
	"crypto/rand"
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

// ResolveUpstreamIdentity 统一认亲流程 (所有 provider 无分支):
// ①查 (provider,sub) 命中即取用户 → ②未命中且有已验证邮箱则按邮箱认亲
// → ③认不到自动建号 → ④建 identity 行。
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

	// ② 认亲: 只信上游已验证的邮箱
	var user *User
	if id.Email != "" && id.EmailVerified {
		u, err := s.repo.GetUserByEmail(ctx, id.Email)
		if err != nil {
			return nil, err
		}
		user = u
	}

	// ③ 自动建号
	if user == nil {
		username, err := s.generateUsername(ctx, id)
		if err != nil {
			return nil, err
		}
		name := id.Name
		if name == "" {
			name = username
		}
		user = &User{
			Username:      username,
			Password:      "", // 联邦账号无密码, VerifyPassword 有守卫
			Email:         id.Email,
			EmailVerified: id.EmailVerified,
			Name:          name,
			AvatarURL:     id.AvatarURL,
			Status:        StatusActive,
		}
		if err := s.repo.InsertUser(ctx, user); err != nil {
			return nil, fmt.Errorf("联邦自动建号失败: %w", err)
		}
		slog.Info("联邦自动建号", "provider", id.Provider, "user_id", user.ID, "username", username)
	}

	if user.Status == StatusBanned {
		return nil, ErrUserBanned
	}

	// ④ 建关联: 之后永远走 ①
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
