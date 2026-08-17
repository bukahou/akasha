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
	"log/slog"
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
	return s.issueTokens(ctx, grantFromCode(ac))
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
	return s.issueTokens(ctx, grantFromRefresh(rt))
}

// grantFromCode / grantFromRefresh 把持久化的授权记录翻译成一次签发的依据。
//
// 单独抽出来是因为【字段漏传不会报错】—— 少写一行 Scope, 编译通过、
// 运行正常, 只是刷新之后 claims 悄悄变样。这两个函数是纯的, 可以直接断言。
func grantFromCode(ac *AuthCode) tokenGrant {
	return tokenGrant{
		UserID:   ac.UserID,
		ClientID: ac.ClientID,
		Nonce:    ac.Nonce,
		// 家族起点: 这张 code 的 hash。之后每次滚动都继承它, 使整条链可被连坐撤销
		FamilyID: ac.CodeHash,
		Scope:    ac.Scope,
	}
}

func grantFromRefresh(rt *RefreshToken) tokenGrant {
	return tokenGrant{
		UserID:   rt.UserID,
		ClientID: rt.ClientID,
		// 继承家族: 滚动出的新 token 与被它取代的旧 token 同属一条链
		FamilyID: rt.FamilyID,
		// scope 同样继承 —— 否则刷新一次 claims 就变样了
		// (RFC 6749 §6: 刷新出的 token 其范围不得超过原始授权)
		Scope: rt.Scope,
		// Nonce 【刻意不继承】: 它绑定的是那一次登录交互的防重放,
		// 刷新不是新的认证事件, 带上旧 nonce 反而会让 RP 误判
	}
}

// tokenGrant 一次签发所依据的授权事实。
//
// 用结构体而非五个位置参数: 其中四个都是 string, 位置传参写错顺序编译器不会拦
// (把 nonce 传成 familyID 的后果是家族撤销静默失效 —— 不报错, 只是防线没了)。
type tokenGrant struct {
	UserID   int64
	ClientID string
	Nonce    string // 仅 code 兑换时有值; 刷新不是新的认证事件
	FamilyID string // refresh 链归属, 重放时按它连坐撤销
	Scope    string // 决定发哪些身份 claims (OIDC Core §5.4)
}

// issueTokens 逐级重签的落点: 用 akasha 私钥为该用户签发面向该 client 的三 token。
func (s *Service) issueTokens(ctx context.Context, g tokenGrant) (*TokenSet, error) {
	userID, clientID, familyID := g.UserID, g.ClientID, g.FamilyID
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
	sub := PairwiseSub(clientID, u.InternalID, s.pairwiseSalt)
	// 登记反查映射: sub 是单向哈希, /userinfo 拿到它无法反推用户。
	// 失败不阻断签发 —— 登录比 userinfo 重要, 下次签发会再补一次。
	if err := s.repo.RecordPairwiseSub(ctx, clientID, sub, u.ID); err != nil {
		slog.Error("登记 pairwise 映射失败, userinfo 将无法反查", "err", err, "client_id", clientID)
	}

	// ⚠️ 这里【绝不能】出现 u.ID 或 u.InternalID —— 下游一旦拿到跨 client 相同的标识,
	// pairwise 立刻破功 (两个应用一比对就知道是同一个人)。sub 是唯一的身份标识。
	//
	// aud 【不在】公共部分: 两张票的受众本来就不是同一个 (见各自的组装函数)。
	base := jwt.MapClaims{
		"iss": s.issuer,
		"sub": sub,
		"iat": now.Unix(),
	}

	// access_token 先签 —— id_token 的 at_hash 要拿它的字符串来算, 顺序不能反
	accessToken, err := s.keys.SignClaims(
		accessTokenClaims(base, g, s.issuer, now.Add(s.ttl.AccessToken)))
	if err != nil {
		return nil, err
	}

	idClaims := idTokenClaims(base, u, g, now, now.Add(s.ttl.IDToken))
	// at_hash 是唯一无法在纯函数里算出的 claim —— 它依赖已签好的 access_token 字符串,
	// 所以只能留在这里。其余 id_token claims 全在 idTokenClaims 内。
	// 作用: 让 RP 验证"这两张票是同一次签发的"; 缺它时 AppAuth-iOS / Nimbus
	// 等严格实现会直接判 id_token 非法。
	idClaims["at_hash"] = accessTokenHash(accessToken)

	idToken, err := s.keys.SignClaims(idClaims)
	if err != nil {
		return nil, err
	}

	refresh, err := randomOpaque()
	if err != nil {
		return nil, err
	}
	if err := s.repo.InsertRefresh(ctx, &RefreshToken{
		TokenHash: hashOpaque(refresh),
		FamilyID:  familyID,
		UserID:    u.ID,
		ClientID:  clientID,
		// scope 必须落库: refresh token 是不透明随机串, 本身携带不了任何信息。
		// 不存的话, 滚动刷新时就不知道原始授权范围了 —— 结果是首次登录按 scope
		// 分发、刷新一次退化成全发, 比不做分发更糟 (行为不一致且无人察觉)
		Scope:     g.Scope,
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

// LookupUserBySub 由 (client_id, pairwise sub) 反查用户 id; 查不到返回 0。
func (s *Service) LookupUserBySub(ctx context.Context, clientID, sub string) (int64, error) {
	return s.repo.LookupPairwiseSub(ctx, clientID, sub)
}

// UserClaims 取用户当前属性 (userinfo 用)。
// 与 id_token 不同, 这里读的是【实时】状态 —— 封禁与资料变更都会立即反映。
func (s *Service) UserClaims(ctx context.Context, userID int64) (*account.User, error) {
	return s.account.GetUserByID(ctx, userID)
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

// accessTokenClaims 组装 access_token 的 claims (RFC 9068 结构)。
//
// # 不带身份 claims (A6)
//
// 理由是暴露窗口: access_token 的 TTL 是 id_token 的 6 倍 (1h vs 10min), 且它是
// 那张"到处跑"的票 —— 发给资源服务器、可能被存进日志。把 PII 放在跑得最远、
// 活得最久的那张票上, 方向是反的。要用户资料就去调 /userinfo。
//
// 保留 scope 是因为 /userinfo 必须知道该返回哪些字段, 而 access_token 是它唯一的
// 输入。scope 不是身份信息, 放这里不违反上面那条 (RFC 9068 §2.2.3 的标准 claim)。
//
// # aud 指资源服务器, 不是 client (A6 第二部分)
//
// aud 回答的是"这张票能拿去哪里用", azp 回答的是"这张票发给了谁" ——
// 两个问题, 两个 claim。此前两者都填 client_id, 等于把"用在哪"这个问题答成了
// "谁拿着", 校验方就无从判断一张票是不是给自己的。
//
// akasha 当前唯一的资源服务器就是它自己 (/userinfo), 所以 aud = issuer。
// 将来若有独立资源服务器, 这里改成按请求的 resource 参数填, 校验方各认各的 aud。
//
// ⚠️ id_token 的 aud 【不能】这样改 —— OIDC Core §2 明确 REQUIRED 它等于 client_id。
// 两张票的 aud 从此不同, 这是对的, 不是不一致。
//
// ⚠️ 往这里加字段前先想清楚: 加进来的东西会在网络上多待 50 分钟。
func accessTokenClaims(base jwt.MapClaims, g tokenGrant, resourceAud string, exp time.Time) jwt.MapClaims {
	c := cloneClaims(base)
	c["aud"] = resourceAud
	// azp: 这张票发给了哪个 client。/userinfo 靠它 (而非 aud) 反查 pairwise 映射
	c["azp"] = g.ClientID
	c["exp"] = exp.Unix()
	c["scope"] = g.Scope
	return c
}

// idTokenClaims 组装 id_token 的 claims (at_hash 除外 —— 它依赖已签好的
// access_token 字符串, 只能由调用方补上)。
func idTokenClaims(base jwt.MapClaims, u *account.User, g tokenGrant, now, exp time.Time) jwt.MapClaims {
	c := cloneClaims(base)
	// aud = client_id: OIDC Core §2 对 id_token 的 REQUIRED 规定, 不可更改。
	// (access_token 的 aud 指资源服务器, 两者不同是刻意的 —— 见 accessTokenClaims)
	c["aud"] = g.ClientID
	c["exp"] = exp.Unix()
	// 身份 claims 按 scope 分发 (OIDC Core §5.4) —— 只申请了 openid 的 RP
	// 不该收到一堆 PII。Keycloak / Auth0 / Google 都是这个行为。
	for k, v := range identityClaims(u, g.Scope) {
		c[k] = v
	}
	// auth_time: 本次认证发生的时刻。akasha 无会话, 每次签发都紧跟一次真实的上游
	// 认证, 因此它恒等于"刚刚" —— 带 max_age 的请求 REQUIRED 此 claim。
	c["auth_time"] = now.Unix()
	// azp (authorized party): 拿到这张票的是谁。aud 单值且等于 client_id 时规范上
	// 可省, 但主流 OP 一律发送, 严格的 RP 也会读它做交叉校验。
	c["azp"] = g.ClientID
	// nonce 原样回显 —— RP 拿它跟自己发起时存的值比对, 防 id_token 重放。
	// 刷新签发时 g.Nonce 为空 (刷新不是新的认证事件), 此时不该出现这个 claim
	if g.Nonce != "" {
		c["nonce"] = g.Nonce
	}
	return c
}

// identityClaims 按 scope 挑出该发的身份 claims (OIDC Core §5.4)。
//
// # 为什么不无条件全发
//
// scope 是 RP 声明"我需要什么"的唯一手段。收下它却全发, 等于把这个机制变成
// 装饰 —— 只申请 openid 的 RP 会拿到一堆它没要、也没打算保管的 PII。
// 对第一方三应用没差别 (它们都申请全套), 但 atlhyper 要作为产品让别人接,
// 那时对面是通用 RP, 会按规范预期行事。
//
// # 未申请的 scope 为什么不报错
//
// 无法识别的 scope 一律忽略 —— OAuth 2.0 (RFC 6749 §3.3) 明说服务端 MAY 这么做,
// 报错反而会让宽松的 RP 接不上。缺 openid 是另一回事, 那在 ParseAuthorizeRequest
// 就已经拒了 (没有 openid 就不是一个 OIDC 请求)。
//
// 同一份映射也供 /userinfo 使用, 保证两个出口给出的字段集完全一致。
func identityClaims(u *account.User, scope string) map[string]any {
	claims := map[string]any{}
	if hasScope(scope, "email") {
		claims["email"] = u.Email
		claims["email_verified"] = u.EmailVerified
	}
	if hasScope(scope, "profile") {
		claims["name"] = u.Name
		claims["preferred_username"] = u.Username
		claims["picture"] = u.AvatarURL
	}
	return claims
}

func cloneClaims(src jwt.MapClaims) jwt.MapClaims {
	dst := jwt.MapClaims{}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// accessTokenHash 计算 at_hash (OIDC Core §3.1.3.6)。
//
// 算法由 id_token 的签名算法决定: RS256 用 SHA-256, 取哈希的【左半边】
// (前 128 位) 再 base64url。取左半边不是随意裁剪 —— 规范如此规定,
// RP 会按同样的规则算, 少取或多取都会导致校验失败。
func accessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
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
