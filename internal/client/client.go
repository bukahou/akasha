// Package client RP 注册表: 谁有资格找 akasha 要身份。
// 注册表校验 = OIDC 安全的第一道门: client_id 存在 + secret 匹配 + redirect_uri 精确白名单。
//
// # 为什么从 clients 表改成文件 (2026-09-03 定案)
//
// clients 本质是配置不是状态: akasha 明确不做动态客户端注册 (RFC 7591 已否),
// 这份数据在运行时【没有任何合法写路径】—— 唯一的写者曾是拿着 SQL 提示符的人,
// 零审计。改为随部署挂载的 yaml 文件后: 变更走 git diff + ArgoCD diff 双重人眼,
// 内容一变 Secret 哈希后缀变 → 滚动重启生效; 手改生产库这条路被物理拆除。
//
// 坏文件在启动时被校验拦下 → 新 pod 起不来 → 旧 pod 继续服务。
// ⚠️ 这张安全网只在旧 pod 活着时有效: 滚动失败必须立即 revert, 不许留着
// Degraded 过夜 —— 否则之后任何节点故障都会让容量单调衰减。
package client

import (
	"context"
	"errors"
	"net/url"

	"golang.org/x/crypto/bcrypt"
)

// 客户端类型 (RFC 6749 §2.1)。
const (
	// TypeConfidential 服务端应用, 能安全保管 client_secret。
	TypeConfidential = "confidential"
	// TypePublic 移动 App / SPA / CLI —— 无法保管密钥:
	// App 反编译即得, SPA 的 secret 直接躺在 JS 源码里, 且全球用户共用同一份。
	// RFC 8252 的方案是不带 secret, 改由 PKCE 保护本次会话。
	TypePublic = "public"
)

// Client 一条 RP 注册记录 (来源: AKASHA_CLIENTS_FILE 指向的 yaml)。
type Client struct {
	ClientID   string `yaml:"client_id"`
	ClientType string `yaml:"client_type"`
	// SecretHash bcrypt(client_secret)。confidential 必填; public 必须为空 ——
	// public 客户端带 secret 说明写的人对类型有误解, 加载时直接拒绝。
	SecretHash string `yaml:"secret_hash"`
	Name       string `yaml:"name"`
	// RedirectURIs 回调白名单, 精确匹配 (loopback 豁免端口)。
	RedirectURIs []string `yaml:"redirect_uris"`
	// PostLogoutRedirectURIs 登出后可回跳的地址, 与 RedirectURIs 分开注册。
	// 两者语义不同: 一个接收授权码, 一个是给用户看的落地页; 混用会让
	// "能接收 code 的端点"和"能被登出流程跳到的页面"这两个权限意外等价。
	PostLogoutRedirectURIs []string `yaml:"post_logout_redirect_uris"`
}

// IsPublic 是否为公开客户端 (不要求 client_secret)。
func (c *Client) IsPublic() bool { return c.ClientType == TypePublic }

var (
	ErrClientNotFound    = errors.New("client 未注册")
	ErrSecretMismatch    = errors.New("client_secret 不匹配")
	ErrRedirectURIDenied = errors.New("redirect_uri 不在白名单")
	ErrSecretNotAllowed  = errors.New("public 客户端不应携带 client_secret")
)

// Registry 注册表的查询与校验门面。
//
// 内容在进程启动时从文件一次性加载并校验, 之后只读 —— 变更靠改文件触发
// 滚动重启, 不做运行时热更新 (ConfigMap 卷更新有 kubelet 延迟且 subPath
// 不更新, 滚动重启是零代码的标准做法)。
type Registry struct {
	byID map[string]*Client
}

// newRegistry 由已通过校验的条目构建注册表。
func newRegistry(clients []Client) *Registry {
	m := make(map[string]*Client, len(clients))
	for i := range clients {
		m[clients[i].ClientID] = &clients[i]
	}
	return &Registry{byID: m}
}

// FindByClientID 按 client_id 取注册信息。
// ctx 保留在签名里: 调用方不该关心注册表在内存还是远端, 换实现不改调用点。
func (r *Registry) FindByClientID(_ context.Context, clientID string) (*Client, error) {
	c, ok := r.byID[clientID]
	if !ok {
		return nil, ErrClientNotFound
	}
	return c, nil
}

// ValidateRedirectURI 回调白名单校验 —— 开放重定向的唯一防线。
//
// 默认精确匹配, 不做前缀或通配。唯一的例外是 loopback (见 loopbackMatches),
// 那是 RFC 8252 §7.3 的硬性要求而非放松。
func (r *Registry) ValidateRedirectURI(c *Client, redirectURI string) error {
	return matchURI(c.RedirectURIs, redirectURI)
}

// ValidatePostLogoutRedirectURI 登出回跳白名单校验。
//
// 与授权回调分开校验 —— 它们是两份独立的白名单。一个应用可能有多个授权回调
// 端点却只有一个登出落地页, 反之亦然; 更重要的是不该让"能接收授权码"顺带
// 获得"能被登出流程跳到"的能力。
func (r *Registry) ValidatePostLogoutRedirectURI(c *Client, uri string) error {
	return matchURI(c.PostLogoutRedirectURIs, uri)
}

func matchURI(uris []string, want string) error {
	for _, u := range uris {
		if u == want || loopbackMatches(u, want) {
			return nil
		}
	}
	return ErrRedirectURIDenied
}

// loopbackMatches 判定两个 loopback 回调是否视为同一个 (仅端口不同)。
//
// # 为什么必须放宽
//
// 桌面应用与 CLI 登录时会在本机起一个临时 HTTP 服务接收回调, 端口由操作系统
// 动态分配 —— 注册时根本不知道将来会是哪个端口。RFC 8252 §7.3 因此规定:
// OP 【必须】对 loopback 地址忽略端口比对。不放宽等于这类客户端无法登录。
//
// # 为什么放宽是安全的
//
// 127.0.0.1 / [::1] 只能被本机进程监听。攻击者要利用它, 前提是已经能在用户
// 机器上跑代码 —— 那时他有比劫持回调更直接的手段。
//
// 严格限制: 只认 IP 字面量 127.0.0.1 与 [::1]。"localhost" 【不】豁免, 因为它
// 要经过 DNS 解析, 可被 hosts 文件或 DNS 投毒指向别处 (RFC 8252 §8.3 明确建议
// 用 IP 字面量而非 localhost)。scheme 与路径仍须逐字相同。
func loopbackMatches(registered, given string) bool {
	ru, err := url.Parse(registered)
	if err != nil {
		return false
	}
	gu, err := url.Parse(given)
	if err != nil {
		return false
	}
	if !isLoopbackHost(ru.Hostname()) || !isLoopbackHost(gu.Hostname()) {
		return false
	}
	// 端口之外的一切必须完全一致: scheme / host / path / query
	return ru.Scheme == gu.Scheme &&
		ru.Hostname() == gu.Hostname() &&
		ru.Path == gu.Path &&
		ru.RawQuery == gu.RawQuery
}

func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1"
}

// Authenticate 后信道 client 认证 (/token 用)。
//
// confidential: 校验 client_secret。
// public:       不校验 secret —— 它拿不出也不该拿出。这不是放松认证, 而是把
//
//	"证明我是这次登录的发起者"的责任移交给 PKCE: 兑换时必须出示
//	与 authorize 阶段 challenge 对应的 verifier, 而 verifier 从未
//	离开过发起方。截获 code 的人拿不出它。
//
// 反过来, public 客户端【携带】secret 会被拒绝: 那说明调用方对自己的类型有误解,
// 静默忽略只会让这种误解一直留到生产。
func (r *Registry) Authenticate(ctx context.Context, clientID, clientSecret string) (*Client, error) {
	c, err := r.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if c.IsPublic() {
		if clientSecret != "" {
			return nil, ErrSecretNotAllowed
		}
		return c, nil
	}
	if bcrypt.CompareHashAndPassword([]byte(c.SecretHash), []byte(clientSecret)) != nil {
		return nil, ErrSecretMismatch
	}
	return c, nil
}

// Size 注册条目数 (validate 子命令的输出用)。
func (r *Registry) Size() int { return len(r.byID) }
