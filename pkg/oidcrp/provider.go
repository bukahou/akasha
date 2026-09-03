package oidcrp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// upstreamTimeout 与 provider 通信的超时 (discovery / 换票 / 取 JWKS)。
//
// 不设的话会退回 http.DefaultClient 的"永不超时" —— provider 挂起时,
// 本应用的 goroutine 会跟着一起挂住, 而这发生在用户等待的请求路径上。
const upstreamTimeout = 10 * time.Second

// provider 封装与上游 OIDC provider 的全部交互。
//
// 它是本包唯一跟外部网络说话的地方 —— 其余部分都是本地计算。
type provider struct {
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
}

// newProvider 拉取 discovery 文档并组装。
//
// 构造时就拉 discovery (而非首次登录时懒加载) 是有意的: 配置写错、网络不通、
// issuer 打错字这类问题应当在【启动时】暴露, 而不是等第一个用户来点登录。
func newProvider(ctx context.Context, cfg Config) (*provider, error) {
	client := &http.Client{Timeout: upstreamTimeout}
	ctx = oidc.ClientContext(ctx, client)

	oidcProvider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("拉取 %s 的 discovery 文档失败: %w", cfg.IssuerURL, err)
	}

	return &provider{
		client: client,
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     oidcProvider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		// verifier 校验签名 / iss / aud / exp; nonce 需要在 exchange 里另行比对
		verifier: oidcProvider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

// authCodeURL 组装授权页地址。
//
// 发出去的是 S256(verifier), verifier 本身留在签名 cookie 里。
func (p *provider) authCodeURL(fs *flowState) string {
	return p.oauth.AuthCodeURL(fs.State,
		oidc.Nonce(fs.Nonce),
		oauth2.S256ChallengeOption(fs.Verifier),
	)
}

// exchange 后信道换票: code → provider 的 token → 验 id_token → 翻译成 Identity。
//
// 这一步是服务器直连 provider, client_secret 不经过浏览器。
func (p *provider) exchange(ctx context.Context, code string, fs *flowState) (Identity, error) {
	var zero Identity
	// 回调请求自带的 ctx 里没有我们那个带超时的 client, 这里补上 ——
	// 否则换票与验签时的出站请求会退回无超时的 http.DefaultClient
	ctx = oidc.ClientContext(ctx, p.client)

	token, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(fs.Verifier))
	if err != nil {
		return zero, fmt.Errorf("兑换 code 失败: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return zero, errors.New("provider 响应中缺少 id_token")
	}

	// 验签 + iss/aud/exp。go-oidc 内部按 kid 从 provider 的 JWKS 取公钥
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return zero, fmt.Errorf("校验 id_token 失败: %w", err)
	}

	// ⭐ nonce 必须由调用方比对: verifier 不知道本次流程发出的是哪个 nonce。
	// 少了这一步, 一张从别处拿到的合法 id_token 就能拿来冒充该用户登录。
	if idToken.Nonce != fs.Nonce {
		return zero, errors.New("id_token 的 nonce 与本次流程不匹配")
	}

	var claims struct {
		Subject           string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Picture           string `json:"picture"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return zero, fmt.Errorf("解析 id_token claims 失败: %w", err)
	}
	// sub 是唯一的身份键, 缺了它这次登录没有意义
	if claims.Subject == "" {
		return zero, errors.New("id_token 缺少 sub")
	}

	return Identity{
		Subject:           claims.Subject,
		Email:             claims.Email,
		EmailVerified:     claims.EmailVerified,
		Name:              claims.Name,
		PreferredUsername: claims.PreferredUsername,
		Picture:           claims.Picture,
	}, nil
}
