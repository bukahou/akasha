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
	// 形如 user:pass@tcp(host:3306)/akasha?charset=utf8mb4&parseTime=True&loc=Local
	DBDSN string `env:"AKASHA_DB_DSN,required"`

	// ---- 签名 ----
	SigningKeyPath string `env:"AKASHA_SIGNING_KEY_PATH" envDefault:"./signing-key.pem"` // RSA 私钥 PEM (永不入库/入 git)

	// ---- 会话 cookie ----
	// 生产必须 true: false 时 cookie 允许走明文 HTTP, 中枢会话可被中间人窃取 = SSO 全线失守。
	CookieSecure bool `env:"AKASHA_COOKIE_SECURE" envDefault:"false"`

	// ---- TTL ----
	IDTokenTTL     time.Duration `env:"AKASHA_ID_TOKEN_TTL"     envDefault:"10m"`
	AccessTokenTTL time.Duration `env:"AKASHA_ACCESS_TOKEN_TTL" envDefault:"1h"`
	RefreshTTL     time.Duration `env:"AKASHA_REFRESH_TTL"      envDefault:"720h"` // 30d 滚动
	SessionTTL     time.Duration `env:"AKASHA_SESSION_TTL"      envDefault:"720h"` // 中枢会话 30d
	AuthCodeTTL    time.Duration `env:"AKASHA_AUTH_CODE_TTL"    envDefault:"60s"`  // 一次性提货券, 短命是安全属性
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
