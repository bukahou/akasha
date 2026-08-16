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
	"os"

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
}

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

	m := &Manager{kid: kid, private: private, db: db}
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
		return &m.private.PublicKey, nil
	}, opts...)
	if err != nil {
		return nil, err
	}
	return claims, nil
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
