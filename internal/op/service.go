package op

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
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

var ErrPKCEMismatch = errors.New("PKCE verifier 校验失败")

// Service OIDC 协议核心业务: code 签发/兑换 + 三 token 组装。
type Service struct {
	repo    *Repository
	keys    *keys.Manager
	account *account.Repository
	issuer  string
	ttl     TTLConfig
}

func NewService(repo *Repository, km *keys.Manager, accountRepo *account.Repository, issuer string, ttl TTLConfig) *Service {
	return &Service{repo: repo, keys: km, account: accountRepo, issuer: issuer, ttl: ttl}
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
	// PKCE: S256(verifier) == 签发时的 challenge
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
		return nil, ErrCodeInvalid
	}
	return s.issueTokens(ctx, rt.UserID, rt.ClientID, "")
}

// issueTokens 逐级重签的落点: 用 akasha 私钥为该用户签发面向该 client 的三 token。
func (s *Service) issueTokens(ctx context.Context, userID int64, clientID, nonce string) (*TokenSet, error) {
	u, err := s.account.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil || u.Status != account.StatusActive {
		return nil, errors.New("用户不存在或已封禁")
	}

	now := time.Now()
	base := jwt.MapClaims{
		"iss":                s.issuer,
		"sub":                jwtSub(u.ID),
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

// jwtSub sub = akasha 用户 id 的十进制字符串 (OIDC 规范 sub 是 string)。
func jwtSub(userID int64) string {
	return strconv.FormatInt(userID, 10)
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
