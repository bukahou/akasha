package op

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bukahou/akasha/internal/account"
	"github.com/bukahou/akasha/internal/keys"
)

// TTLConfig token 生命周期配置 (config 注入)。
type TTLConfig struct {
	IDToken     time.Duration
	AccessToken time.Duration
	Refresh     time.Duration
	AuthCode    time.Duration
}

// TokenSet /token 响应体。
type TokenSet struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// RFC 7636 §4.1: code_verifier 是 43-128 个字符的高熵随机串。
// 太短 = 熵不足, 截获 challenge 后可暴力反推; 太长 = 拒绝服务面。
// 字符集限定 [A-Za-z0-9-._~] 全 ASCII, 故字节数即字符数。
const (
	pkceVerifierMinLen = 43
	pkceVerifierMaxLen = 128
)

// 这三个都是"请求方的错", 必须映射成 400 invalid_grant 而非 500 —— 见 handler.token。
var (
	ErrPKCEMismatch    = errors.New("PKCE verifier 校验失败")
	ErrPKCEMalformed   = errors.New("code_verifier 长度不合规 (RFC 7636 要求 43-128 字符)")
	ErrUserUnavailable = errors.New("用户不存在或已封禁")
)

// Service OIDC 协议核心业务: code 签发/兑换 + 三 token 组装。
type Service struct {
	repo         *Repository
	keys         *keys.Manager
	account      *account.Repository
	issuer       string
	pairwiseSalt string // 只进 PairwiseSub, 永不出现在任何 token/日志里
	ttl          TTLConfig
}

func NewService(repo *Repository, km *keys.Manager, accountRepo *account.Repository, issuer, pairwiseSalt string, ttl TTLConfig) *Service {
	return &Service{repo: repo, keys: km, account: accountRepo, issuer: issuer, pairwiseSalt: pairwiseSalt, ttl: ttl}
}

// IssueCode 签发一次性授权码 (会话已确认后由 /authorize 调用)。
func (s *Service) IssueCode(ctx context.Context, req *AuthorizeRequest, userID int64) (string, error) {
	code, err := randomOpaque()
	if err != nil {
		return "", err
	}
	ac := &AuthCode{
		CodeHash:      hashOpaque(code),
		ClientID:      req.ClientID,
		UserID:        userID,
		RedirectURI:   req.RedirectURI,
		Scope:         req.Scope,
		Nonce:         req.Nonce,
		PKCEChallenge: req.CodeChallenge,
		ExpiresAt:     time.Now().Add(s.ttl.AuthCode),
	}
	if err := s.repo.InsertCode(ctx, ac); err != nil {
		return "", err
	}
	return code, nil
}

// ExchangeCode 后信道兑换: code + PKCE verifier + redirect_uri 三重校验 → 三 token。
// client 认证由 handler 先行完成 (clientID 已可信)。
func (s *Service) ExchangeCode(ctx context.Context, clientID, code, verifier, redirectURI string) (*TokenSet, error) {
	ac, err := s.repo.ConsumeCode(ctx, code)
	if err != nil {
		return nil, err
	}
	// code 归属校验: 必须是签发给这个 client、这个回调地址的
	if ac.ClientID != clientID || ac.RedirectURI != redirectURI {
		return nil, ErrCodeInvalid
	}
	// PKCE: 先验形状再验值 —— 长度不合规的 verifier 根本没资格参与比对
	if len(verifier) < pkceVerifierMinLen || len(verifier) > pkceVerifierMaxLen {
		return nil, ErrPKCEMalformed
	}
	// S256(verifier) == 签发时的 challenge
	if computeS256(verifier) != ac.PKCEChallenge {
		return nil, ErrPKCEMismatch
	}
	return s.issueTokens(ctx, ac.UserID, ac.ClientID, ac.Nonce)
}

// RefreshTokens 滚动刷新 (旧 refresh 作废, 全套新发)。
func (s *Service) RefreshTokens(ctx context.Context, clientID, refreshToken string) (*TokenSet, error) {
	rt, err := s.repo.ConsumeRefresh(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if rt.ClientID != clientID {
		return nil, ErrRefreshInvalid
	}
	return s.issueTokens(ctx, rt.UserID, rt.ClientID, "")
}

// issueTokens 逐级重签的落点: 用 akasha 私钥为该用户签发面向该 client 的三 token。
func (s *Service) issueTokens(ctx context.Context, userID int64, clientID, nonce string) (*TokenSet, error) {
	u, err := s.account.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	// 封禁用户拿旧 refresh 来刷新时会走到这里。必须是 400 invalid_grant:
	// 返 500 会让 RP 判定为"akasha 故障"而重试, 正确行为是把用户踢去重新登录。
	if u == nil || u.Status != account.StatusActive {
		return nil, ErrUserUnavailable
	}

	// internal_id 缺失说明这行是 pairwise 改造前的历史数据 —— 宁可拒绝签发,
	// 也不能退回用 u.ID 当 sub (那会让下游把不同的人认成同一个)。
	if u.InternalID == "" {
		return nil, fmt.Errorf("用户缺少 internal_id, 无法计算 pairwise sub: user_id=%d", u.ID)
	}

	now := time.Now()
	// ⚠️ 这里【绝不能】出现 u.ID 或 u.InternalID —— 下游一旦拿到跨 client 相同的标识,
	// pairwise 立刻破功 (两个应用一比对就知道是同一个人)。sub 是唯一的身份标识。
	base := jwt.MapClaims{
		"iss":                s.issuer,
		"sub":                PairwiseSub(clientID, u.InternalID, s.pairwiseSalt),
		"aud":                clientID,
		"iat":                now.Unix(),
		"email":              u.Email,
		"email_verified":     u.EmailVerified,
		"name":               u.Name,
		"preferred_username": u.Username,
	}

	idClaims := cloneClaims(base)
	idClaims["exp"] = now.Add(s.ttl.IDToken).Unix()
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	idToken, err := s.keys.SignClaims(idClaims)
	if err != nil {
		return nil, err
	}

	accessClaims := cloneClaims(base)
	accessClaims["exp"] = now.Add(s.ttl.AccessToken).Unix()
	accessToken, err := s.keys.SignClaims(accessClaims)
	if err != nil {
		return nil, err
	}

	refresh, err := randomOpaque()
	if err != nil {
		return nil, err
	}
	if err := s.repo.InsertRefresh(ctx, &RefreshToken{
		TokenHash: hashOpaque(refresh),
		UserID:    u.ID,
		ClientID:  clientID,
		ExpiresAt: now.Add(s.ttl.Refresh),
	}); err != nil {
		return nil, err
	}

	return &TokenSet{
		IDToken:      idToken,
		AccessToken:  accessToken,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.ttl.AccessToken.Seconds()),
	}, nil
}

// PairwiseSub 计算面向某个 client 的 sub (OIDC Core §8 pairwise)。
//
// # 为什么是 pairwise 而不是所有 client 共用一个 sub
//
// 三个下游应用面向完全不同的人群 (geass 是媒体消费者, atlhyper 是运维)。
// public 模式下它们看到同一个 sub, 一比对就知道"这是同一个人";
// pairwise 让每个应用拿到不同的值, 彼此无法关联 —— 即使某个应用的库泄漏,
// 也推不出该用户在其他应用的身份。
//
// # 能力边界 (别误解)
//
// 它隔离的是【下游之间】。akasha 运维者仍然能算出任意 (user, client) 的 sub ——
// 这是逻辑必然: 算不出 sub 的 OP 无法签发 token。
// 它也【挡不住越权访问】: geass 用户能不能进 atlhyper, 取决于 atlhyper 自己的
// 准入策略, 换个 sub 该进还是进得去。认证不等于授权。
//
// # 为什么用 HMAC 而非 SHA256(salt ‖ 数据)
//
// salt 在这里的角色是密钥而非数据 —— 没有它就不能伪造出合法 sub。HMAC 是密钥
// 场景的标准构造 (顺带免疫长度扩展攻击)。\x00 作分隔符: client_id 与 internal_id
// 都不含它, 避免拼接歧义。
//
// ⚠️ salt 一旦更换或丢失, 全体下游的用户关联立即永久失效且无法重算。
func PairwiseSub(clientID, internalID, salt string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(clientID + "\x00" + internalID))
	return hex.EncodeToString(mac.Sum(nil))
}

func cloneClaims(src jwt.MapClaims) jwt.MapClaims {
	dst := jwt.MapClaims{}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func computeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomOpaque() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
