// Package keys RS256 签名的物理根基: 私钥加载 / kid 指纹 / 签名门面 / 轮换。
//
// # 为什么必须是 RS256 (非对称) 而不是 HS256 (对称)
//
// 对称签名要求"签的人和验的人共享同一把密钥"。中枢时代验签方是 geass/atlhyper/…
// 每多一个下游就多一份密钥副本, 任何一个应用泄漏 = 全体可被伪造身份。
// 非对称下 akasha 独占私钥签发, 下游只拿公钥 (JWKS 公开可取) 验签 —— 下游被攻破
// 也伪造不出 token。这是"单应用自签 JWT"演进到"中枢签发"时最本质的改造点。
//
// # kid 的作用
//
// JWT header 里的 kid 告诉验签方"这张票用哪把公钥验"。没有 kid, 轮换期间
// 下游拿到 JWKS 里的多把公钥只能逐个试; 有了 kid 就是精确命中。
//
// # 轮换模型
//
// 当前私钥签新 token; signing_keys 表保存公钥历史, JWKS 输出全部未 retire 的公钥
// → 旧 token 在自然过期前始终可验。换密钥的正确姿势:
//
//	换新 PEM 重启 → 新 kid 自动入表 (新 token 用新 key 签)
//	→ 等旧 token 全部过期 (最长 = access TTL) → 手动给旧 kid 置 retired_at
//	→ 下一次 JWKS 请求起旧公钥消失
//
// 顺序反了 (先 retire 再等) 会让在途 token 集体验签失败。
//
// # 私钥的物理边界
//
// 只存在于挂载文件 (本地 PEM / 生产 K8s Secret) 与本进程内存。永不入库、
// 不打日志、不出 Manager —— 对外只暴露 SignClaims 这个签名门面, 调用方
// 拿不到私钥本身。
package keys

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

// SigningKey 对应 signing_keys 表。
// 表里**只有公钥** —— 私钥入库等于把保险箱钥匙锁进保险箱里, 一次拖库全线失守。
type SigningKey struct {
	ID        int64  `gorm:"column:id;primaryKey"`
	Kid       string `gorm:"column:kid"`
	PublicPEM string `gorm:"column:public_pem"`
}

func (SigningKey) TableName() string { return "signing_keys" }

// Manager 持有当前私钥并提供签名门面。
// 字段全小写不导出: 私钥不可能被包外代码摸到, 只能经 SignClaims 间接使用。
type Manager struct {
	kid     string
	private *rsa.PrivateKey
	db      *gorm.DB

	// ---- 验签公钥缓存 (轮换期间验旧票用) ----
	//
	// 只有【当前】私钥能签, 但要验的票可能是上一把密钥签的 —— 轮换窗口内
	// 两者并存。JWKS 早就把全集给了下游, akasha 自己反而只认当前那把,
	// 结果是"下游验得过、akasha 自己验不过": /userinfo 401、
	// id_token_hint 验签失败导致登出回跳失效。这个缓存补上那一半。
	mu          sync.RWMutex
	verifyKeys  map[string]*rsa.PublicKey
	lastRefresh time.Time
}

// verifyKeyRefreshInterval 公钥缓存的最小刷新间隔。
//
// 收到未知 kid 就查库, 会给出一个廉价的放大面: 攻击者伪造一堆随机 kid
// 即可让每个请求都打一次数据库。轮换是分钟级的事件, 1 分钟的滞后无关紧要。
const verifyKeyRefreshInterval = time.Minute

// NewManager 加载私钥 → 算 kid → 把公钥登记进 signing_keys。
//
// 必须在 op 之前构造 (main 的 ④ 早于 ⑤): JWKS 端点读的就是这里登记的表。
// 任何一步失败都返回 error 让 main 退出 —— 没有签名能力的 IdP 毫无意义。
func NewManager(privateKeyPath string, db *gorm.DB) (*Manager, error) {
	raw, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("读取签名私钥失败: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("签名私钥 PEM 解码失败")
	}

	// PKCS8 是现代默认格式 (openssl genpkey, 即 scripts/genkey.sh 产出);
	// PKCS1 是老式 openssl genrsa 的产物 —— 两种都收, 免得换台机器生成的密钥装不进来
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if k1, err1 := x509.ParsePKCS1PrivateKey(block.Bytes); err1 == nil {
			parsed = k1
		} else {
			return nil, fmt.Errorf("解析签名私钥失败: %w", err)
		}
	}
	// PKCS8 能装 RSA/ECDSA/Ed25519 等多种密钥, 断言确保拿到的确实是 RSA
	// (配了把 EC 密钥进来会在这里被拦下, 而不是等第一次签名时 panic)
	private, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("签名私钥不是 RSA 类型")
	}

	kid, publicPEM, err := fingerprint(&private.PublicKey)
	if err != nil {
		return nil, err
	}

	m := &Manager{kid: kid, private: private, db: db, verifyKeys: map[string]*rsa.PublicKey{}}
	if err := m.upsertPublicKey(context.Background(), kid, publicPEM); err != nil {
		return nil, fmt.Errorf("登记签名公钥失败: %w", err)
	}
	return m, nil
}

// Kid 当前签名密钥指纹 (启动日志打它, 排查验签问题时对照 JWT header)。
func (m *Manager) Kid() string { return m.kid }

// SignClaims 用当前私钥签发 RS256 JWT。
// 这是本包对外的唯一出口 —— claims 由调用方 (op) 组装, 本包只管盖章。
func (m *Manager) SignClaims(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.kid
	return token.SignedString(m.private)
}

// VerifyToken 验证本 Manager 签发的 JWT (内部自检用; 下游应用走 JWKS 各验各的)。
func (m *Manager) VerifyToken(tokenStr string) (jwt.MapClaims, error) {
	return m.parse(tokenStr)
}

// VerifyTokenIgnoringExpiry 验签但不检查过期。
//
// 专供 id_token_hint 使用 (OIDC RP-Initiated Logout §2): 用户点登出时手上那张
// id_token 往往已经过期 —— 它在这里的作用只是"提示这是谁、来自哪个 client",
// 不承担授权。因此签名必须验 (否则任何人都能伪造一个 hint 指定登出目标),
// 但过期必须容忍 (否则正常的登出请求会被拒)。
//
// ⚠️ 只能用于识别, 绝不可用于授权判断 —— 一张过期的 token 不代表任何有效权限。
func (m *Manager) VerifyTokenIgnoringExpiry(tokenStr string) (jwt.MapClaims, error) {
	return m.parse(tokenStr, jwt.WithoutClaimsValidation())
}

func (m *Manager) parse(tokenStr string, opts ...jwt.ParserOption) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		// 算法白名单 —— 防 alg confusion 攻击:
		// 攻击者把 header 改成 alg=HS256, 用我们**公开的**公钥当 HMAC 密钥重签,
		// 若此处不校验算法类型, 库会拿公钥去做 HMAC 验证并通过, token 随便伪造。
		// 所以永远不能"信 token 自己声明的 alg"。
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("非预期的签名算法: %v", t.Header["alg"])
		}
		// kid 决定用哪把公钥。缺 kid 时退回当前密钥 —— 本服务签发的票一律带 kid,
		// 不带的多半不是我们签的, 让它在签名校验那一步自然失败即可。
		kid, _ := t.Header["kid"].(string)
		return m.publicKeyByKid(kid)
	}, opts...)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// publicKeyByKid 按 kid 取验签公钥。
//
// 接受范围与 /jwks 输出【完全一致】(全部未 retire 的公钥) —— 两边不一致会让
// "下游验得过而 akasha 验不过"这类问题以另一种形式回来。已 retire 的密钥不再
// 参与验签: 按轮换纪律, retire 的前提就是它签的票全都过期了。
func (m *Manager) publicKeyByKid(kid string) (*rsa.PublicKey, error) {
	// 快路径: 绝大多数请求验的是刚签发的票, 不必碰缓存更不必碰数据库
	if kid == "" || kid == m.kid {
		return &m.private.PublicKey, nil
	}
	if pub := m.cachedVerifyKey(kid); pub != nil {
		return pub, nil
	}
	// 未命中可能是"刚轮换过, 缓存还没见过这把" —— 刷新一次再看
	if err := m.refreshVerifyKeys(context.Background()); err != nil {
		return nil, fmt.Errorf("刷新验签公钥失败: %w", err)
	}
	if pub := m.cachedVerifyKey(kid); pub != nil {
		return pub, nil
	}
	return nil, fmt.Errorf("未知的 kid: %s", kid)
}

func (m *Manager) cachedVerifyKey(kid string) *rsa.PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.verifyKeys[kid]
}

// refreshVerifyKeys 重载在役公钥集; 距上次刷新不足 verifyKeyRefreshInterval 时跳过。
func (m *Manager) refreshVerifyKeys(ctx context.Context) error {
	m.mu.Lock()
	if time.Since(m.lastRefresh) < verifyKeyRefreshInterval {
		m.mu.Unlock()
		return nil // 刚刷过, 这个 kid 就是不存在
	}
	m.lastRefresh = time.Now()
	m.mu.Unlock()

	if m.db == nil {
		return errors.New("未配置数据库, 无法查询历史公钥")
	}
	active, err := m.ActiveKeys(ctx)
	if err != nil {
		return err
	}
	fresh := make(map[string]*rsa.PublicKey, len(active))
	for _, k := range active {
		pub, perr := parsePublicPEM(k.PublicPEM)
		if perr != nil {
			// 单把坏掉不该拖垮其余 —— 记下来跳过
			slog.Error("在役公钥解析失败, 已跳过", "err", perr, "kid", k.Kid)
			continue
		}
		fresh[k.Kid] = pub
	}
	m.mu.Lock()
	m.verifyKeys = fresh
	m.mu.Unlock()
	return nil
}

// ActiveKeys 全部未 retire 的公钥 —— 注意是"全集"不是"当前那一把",
// 轮换期新旧公钥并存, 少给一把就会让在途的旧 token 验不过。
func (m *Manager) ActiveKeys(ctx context.Context) ([]SigningKey, error) {
	var list []SigningKey
	err := m.db.WithContext(ctx).Where("retired_at IS NULL").Find(&list).Error
	return list, err
}

// upsertPublicKey 幂等登记: kid 由公钥内容决定, 同一把密钥反复重启只写一次。
// (换了密钥 → kid 变 → 自动多一行, 这正是轮换第一步所需的行为)
func (m *Manager) upsertPublicKey(ctx context.Context, kid, publicPEM string) error {
	var existing SigningKey
	err := m.db.WithContext(ctx).Where("kid = ?", kid).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return m.db.WithContext(ctx).Create(&SigningKey{Kid: kid, PublicPEM: publicPEM}).Error
	}
	return err
}

// fingerprint 由公钥内容派生 kid (SHA-256 前 8 字节 = 16 hex) + 导出公钥 PEM。
//
// 用内容派生而不是随机数/自增: 同一把密钥在任何机器、任何次重启算出的 kid 都一致,
// 天然幂等 (upsert 靠它去重)。截断到 8 字节也够 —— kid 只需在本系统内不撞,
// 它是"索引"不是"安全属性", 伪造 kid 骗不过签名验证。
func fingerprint(pub *rsa.PublicKey) (kid string, publicPEM string, err error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", fmt.Errorf("序列化公钥失败: %w", err)
	}
	sum := sha256.Sum256(der)
	kid = hex.EncodeToString(sum[:8])
	publicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return kid, publicPEM, nil
}
