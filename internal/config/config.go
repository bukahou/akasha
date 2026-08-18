// Package config 全量环境变量配置 (caarlos0/env)。
//
// 值的来源: 本地 = 环境变量 (见 .env.example); 生产 = K8s ConfigMap + Secret。
// 纪律: 凡是凭证类 (DSN 含密码) 一律 required 无默认值 —— 本仓公开,
// 任何"图方便"的默认凭证都会随源码泄漏, 且默认值容易在生产被忘记覆盖。
package config

import (
	"time"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	// ---- 服务 ----
	Addr string `env:"AKASHA_ADDR" envDefault:":9100"`
	// Issuer 写进每张 JWT 的 iss, 也是 discovery 文档的根。
	// 协议层身份: 一旦上线不可更改 (改 = 全体已签发 token 作废)。
	Issuer string `env:"AKASHA_ISSUER" envDefault:"http://localhost:9100"`

	// ---- 存储 ----
	// 形如 user:pass@tcp(host:3306)/akasha?charset=utf8mb4&parseTime=True&loc=UTC
	// loc=UTC 而非 Local: 容器内是 UTC, 混用会让日志时间与 DB 时间对不上
	DBDSN string `env:"AKASHA_DB_DSN,required"`

	// ---- 签名 ----
	SigningKeyPath string `env:"AKASHA_SIGNING_KEY_PATH" envDefault:"./signing-key.pem"` // RSA 私钥 PEM (永不入库/入 git)

	// PairwiseSalt pairwise sub 计算的密钥 (HMAC key)。
	//
	// 无默认值且 required —— 它比 RSA 私钥更不能丢:
	// 私钥丢了重签一把即可 (旧 token 自然过期); 这个盐丢了, 所有下游算出的 sub 全变,
	// 每个应用里的用户关联【永久失效且无法重算】, 只能让全体用户重新绑定。
	// 生成: openssl rand -hex 32
	PairwiseSalt string `env:"AKASHA_PAIRWISE_SALT,required"`

	// ---- 上游联邦 (Google) ----
	// 凭证类, 无默认值。生产忘配时启动即炸, 优于"起来了但没人能登录"。
	GoogleClientID     string `env:"AKASHA_GOOGLE_CLIENT_ID,required"`
	GoogleClientSecret string `env:"AKASHA_GOOGLE_CLIENT_SECRET,required"`
	// FederationTTL 一次联邦往返的有效期 (含用户在上游输密码/过 MFA 的时间)。
	// 太短会让慢吞吞的用户白跑一趟, 太长则拉大 CSRF 攻击窗口。
	FederationTTL time.Duration `env:"AKASHA_FEDERATION_TTL" envDefault:"10m"`

	// ---- 联邦状态 cookie ----
	// akasha 无会话, 这个开关管的是【联邦往返的签名 cookie】(state/nonce/next)。
	// 生产必须 true: false 时它允许走明文 HTTP, 被中间人读到 state 即可发起登录 CSRF。
	CookieSecure bool `env:"AKASHA_COOKIE_SECURE" envDefault:"false"`

	// ---- TTL ----
	IDTokenTTL     time.Duration `env:"AKASHA_ID_TOKEN_TTL"     envDefault:"10m"`
	AccessTokenTTL time.Duration `env:"AKASHA_ACCESS_TOKEN_TTL" envDefault:"1h"`
	RefreshTTL     time.Duration `env:"AKASHA_REFRESH_TTL"      envDefault:"720h"` // 30d 滚动
	// ※ 没有会话 TTL —— akasha 不保留登录态 (2026-08-16 无会话定案),
	//   每次 authorize 都重新走一遍上游认证。
	AuthCodeTTL time.Duration `env:"AKASHA_AUTH_CODE_TTL"    envDefault:"60s"` // 一次性提货券, 短命是安全属性
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
