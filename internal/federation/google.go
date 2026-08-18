package federation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/bukahou/akasha/internal/account"
)

// GoogleIssuer Google 的 OIDC issuer。go-oidc 会据此拉取其 discovery 文档,
// 拿到授权端点/令牌端点/JWKS 地址 —— 与下游 RP 读 akasha 的 discovery 是同一回事。
const GoogleIssuer = "https://accounts.google.com"

// upstreamTimeout 与上游通信的单次超时。
//
// oauth2 与 go-oidc 默认使用 http.DefaultClient —— 它【没有超时】。
// 上游若挂起不响应, 出站请求会一直等下去: 连接与 goroutine 都被占住,
// 而调用方 (联邦回调) 已被 server 的 WriteTimeout 切断, 无人回收。
// 一个自己有超时的 client 才能让失败快速可见。
const upstreamTimeout = 10 * time.Second

// googleProvider Google 上游实现 (标准 OIDC)。
type googleProvider struct {
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
}

// NewGoogleProvider 拉取 Google 的 discovery 文档并构造 provider。
//
// 构造时发起网络请求, 失败即返回 error 让 main 退出。这是刻意的:
// 无密码定案后联邦是 akasha 【唯一】的认证入口, 一个"能启动但登不进去"的 IdP
// 毫无意义, 不如在启动阶段就明确失败 (与 main.go 各步 fail-fast 一致)。
//
// 注意它只能验证 issuer 可达, 验证不了 clientID/clientSecret 是否正确 ——
// discovery 是公开文档, 拿错凭证也照样能拉到。凭证错误要到第一次 Exchange 才暴露。
func NewGoogleProvider(ctx context.Context, clientID, clientSecret, redirectURL string) (Provider, error) {
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("Google client 凭证为空")
	}
	httpClient := &http.Client{Timeout: upstreamTimeout}
	// ClientContext 把这个 client 塞进 ctx, go-oidc 与 oauth2 都会取用它
	// (拉 discovery、拉 JWKS、换 token 三处出站请求全都受这个超时约束)
	ctx = oidc.ClientContext(ctx, httpClient)

	oidcProvider, err := oidc.NewProvider(ctx, GoogleIssuer)
	if err != nil {
		return nil, fmt.Errorf("拉取 Google discovery 失败: %w", err)
	}
	return &googleProvider{
		client: httpClient,
		oauth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     oidcProvider.Endpoint(),
			// openid 拿 id_token; email/profile 换取邮箱与展示名。
			// 不多要 —— 请求越多权限, 用户越可能在同意页放弃。
			Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
		},
		// verifier 校验签名/issuer/audience/过期; nonce 需要在 Exchange 里另行比对
		verifier: oidcProvider.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

func (g *googleProvider) Name() string { return "google" }

// AuthCodeURL 组装 Google 授权页地址。
//
// prompt 原样透传 —— Google 支持 none / consent / select_account / login,
// 与 OIDC 的取值一致, 不需要翻译。它决定用户会不会看到账号选择器:
// 不带的话, 浏览器里登着单个 Google 账号时会【静默返回那个账号】。
func (g *googleProvider) AuthCodeURL(req AuthRequest) string {
	opts := []oauth2.AuthCodeOption{oidc.Nonce(req.Nonce)}
	if req.Prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", req.Prompt))
	}
	if req.Verifier != "" {
		// 发出去的是 S256(verifier), verifier 本身留在签名 cookie 里
		opts = append(opts, oauth2.S256ChallengeOption(req.Verifier))
	}
	return g.oauth.AuthCodeURL(req.State, opts...)
}

// Exchange 后信道换票: code → Google 的 token → 验 id_token → 翻译成统一断言。
func (g *googleProvider) Exchange(ctx context.Context, req ExchangeRequest) (account.UpstreamIdentity, error) {
	var zero account.UpstreamIdentity
	// 回调请求自带的 ctx 里没有我们那个带超时的 client, 这里补上 ——
	// 否则换 token 与验签时的出站请求会退回无超时的 http.DefaultClient
	ctx = oidc.ClientContext(ctx, g.client)

	// 这一步是服务器直连 Google, client_secret 不经过浏览器
	opts := []oauth2.AuthCodeOption{}
	if req.Verifier != "" {
		opts = append(opts, oauth2.VerifierOption(req.Verifier))
	}
	token, err := g.oauth.Exchange(ctx, req.Code, opts...)
	if err != nil {
		return zero, fmt.Errorf("向 Google 兑换 code 失败: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return zero, errors.New("Google 响应中缺少 id_token")
	}

	// 验签 + iss/aud/exp。go-oidc 内部按 kid 从 Google 的 JWKS 取公钥 ——
	// 与下游 RP 验 akasha 的 token 完全同构
	idToken, err := g.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return zero, fmt.Errorf("校验 Google id_token 失败: %w", err)
	}
	// nonce 必须由调用方比对: verifier 不知道本次流程发出的是哪个 nonce。
	// 少了这一步, 一张从别处拿到的 Google id_token 就能拿来冒充该用户登录。
	if idToken.Nonce != req.Nonce {
		return zero, errors.New("Google id_token 的 nonce 与本次流程不匹配")
	}

	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return zero, fmt.Errorf("解析 Google id_token claims 失败: %w", err)
	}
	if claims.Subject == "" {
		return zero, errors.New("Google id_token 缺少 sub")
	}

	return account.UpstreamIdentity{
		Provider: g.Name(),
		// Google 用 public subject type: 同一账号对任何 client 都是这个值, 且永不重分配。
		// akasha 的 internal_id 由它派生, 因此删库重建后仍能算出同一个身份。
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		AvatarURL:     claims.Picture,
	}, nil
}
