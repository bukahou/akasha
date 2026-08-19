// account 身份权威的业务规则: 上游身份裁决 / 建号 / username 生成。
//
// 本包【没有】密码验证 —— akasha 不做本地密码认证 (2026-08-09 定案),
// 认证入口只有上游联邦。接入的应用各自保留自己的本地账号体系,
// akasha 是它们登录页上的一个额外按钮, 不是唯一入口。
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
)

var ErrUserBanned = errors.New("账号已封禁")

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
		return s.loadActiveUser(ctx, fi.UserID)
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
		Email:         id.Email,
		EmailVerified: id.EmailVerified,
		Name:          name,
		AvatarURL:     id.AvatarURL,
		Status:        StatusActive,
	}
	// ③ 建号与建关联在同一个事务里 —— 两步同生共死, 不留孤儿 user 行
	fi := &FederatedIdentity{
		Provider: id.Provider,
		Subject:  id.Subject,
		Email:    id.Email,
	}
	if err := s.repo.CreateUserWithIdentity(ctx, user, fi); err != nil {
		// 并发首登: 另一个请求抢先建好了同一个上游身份, 我们这笔撞唯一索引整体回滚。
		// 此时正确的行为是【复用它建好的那个账号】, 而不是把 500 抛给用户 ——
		// 两个请求本来就在为同一个人建号, 谁先谁后无所谓。
		//
		// 不去匹配驱动特定的错误码 (那随 MySQL/TiDB 版本漂移), 而是直接重查:
		// 关联现在存在 = 有人赢了这场竞争, 事实比错误码可靠。
		//
		// 重查【必然能查到】而不是碰运气: 撞唯一索引的一方会被数据库阻塞到
		// 先来者提交或回滚为止, 所以拿到 1062 的那一刻, 赢家的事务 (含 identity 行)
		// 已经提交完毕。实测中撞的多是 users.uk_username —— 并发请求邮箱相同,
		// 生成的用户名基名也相同 —— 同一套补偿逻辑照样成立。
		if existing, qerr := s.repo.GetIdentity(ctx, id.Provider, id.Subject); qerr == nil && existing != nil {
			slog.Info("并发首登, 复用另一请求建好的账号",
				"provider", id.Provider, "user_id", existing.UserID)
			return s.loadActiveUser(ctx, existing.UserID)
		}
		return nil, fmt.Errorf("联邦建号失败: %w", err)
	}
	slog.Info("联邦建号", "provider", id.Provider, "user_id", user.ID, "username", username)
	return user, nil
}

// loadActiveUser 取用户并校验可用性 (查不到 / 已封禁都不该继续)。
func (s *Service) loadActiveUser(ctx context.Context, userID int64) (*User, error) {
	u, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("身份关联指向的用户不存在: user_id=%d", userID)
	}
	if u.Status == StatusBanned {
		return nil, ErrUserBanned
	}
	return u, nil
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
