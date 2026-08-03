package keys

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// JWK RFC 7517 单条公钥。
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSet RFC 7517 公钥集 (/jwks 响应体)。
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKS 把 signing_keys 里全部在役公钥序列化成 JWKS (下游应用验签的数据源)。
func (m *Manager) JWKS(ctx context.Context) (*JWKSet, error) {
	active, err := m.ActiveKeys(ctx)
	if err != nil {
		return nil, err
	}
	set := &JWKSet{Keys: make([]JWK, 0, len(active))}
	for _, k := range active {
		pub, err := parsePublicPEM(k.PublicPEM)
		if err != nil {
			return nil, fmt.Errorf("解析在役公钥失败 kid=%s: %w", k.Kid, err)
		}
		set.Keys = append(set.Keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: k.Kid,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return set, nil
}

func parsePublicPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("公钥 PEM 解码失败")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("公钥不是 RSA 类型")
	}
	return pub, nil
}
