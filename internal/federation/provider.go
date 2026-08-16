// Package federation 上游联邦 broker —— akasha 当 Relying Party 的那一侧。
//
// # 与 op 包的镜像关系
//
//	op/          发 code 给下游, 签 token           akasha 是 Provider
//	federation/  拿 code 找上游换, 验上游的 token    akasha 是 Relying Party
//	                    ↓ 两侧同为 account 裁决身份
//
// 同一组概念 (code / nonce / PKCE / state) 在两个角色里镜像出现, 但责任相反:
// 作为 OP, state 只需原样回传, 保管是下游的事; 作为 RP, state 得自己保管、
// 自己校验 (见 state.go)。只做一侧永远碰不到这个区别。
//
// # 依赖方向
//
// federation → account (单向)。本包只负责"跟上游对话, 把结果翻译成
// account.UpstreamIdentity", 至于这个断言对应 akasha 的哪个用户、要不要建号,
// 全部由 account 裁决 —— 否则每加一个 provider 就要把建号逻辑复制一遍。
package federation

import (
	"context"
	"fmt"

	"github.com/bukahou/akasha/internal/account"
)

// Provider 一个上游 IdP。
//
// 三个方法就够, 是因为所有 provider 的差异都被关在 Exchange 里面:
// Google 走标准 OIDC (有 id_token 可验签), GitHub 走 OAuth2 + 调 /user API
// (根本没有 id_token), 内部实现天差地别, 但吐出来的都是同一个 UpstreamIdentity。
// 上层拿到的东西完全一致, 于是建号/认亲逻辑不需要任何 provider 分支。
type Provider interface {
	// Name 用于 URL 路径与 federated_identities.provider 列, 必须稳定不变 ——
	// 改了它等于把所有已建立的上游身份关联作废。
	Name() string

	// AuthCodeURL 上游的授权页地址。state 防 CSRF, nonce 防 id_token 重放。
	AuthCodeURL(state, nonce string) string

	// Exchange 用回调拿到的 code 向上游换取身份断言。
	// nonce 传入是为了校验上游 id_token 里的 nonce 与本次流程一致。
	Exchange(ctx context.Context, code, nonce string) (account.UpstreamIdentity, error)
}

// Registry provider 注册表: URL 里的 {provider} → 具体实现。
//
// 加一个上游 = 新写一个实现 Provider 的文件 + 在装配处注册一行,
// 本包其余代码与 handler 一律不动 (开闭原则的实际形状)。
type Registry struct {
	providers map[string]Provider
}

func NewRegistry(providers ...Provider) *Registry {
	m := make(map[string]Provider, len(providers))
	for _, p := range providers {
		m[p.Name()] = p
	}
	return &Registry{providers: m}
}

// Lookup 按名字取 provider; 未注册返回 error (而非 nil), 让调用方无法忘记判断。
func (r *Registry) Lookup(name string) (Provider, error) {
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("未注册的上游 provider: %q", name)
	}
	return p, nil
}

// Names 已注册的上游名列表 (登录页据此渲染按钮)。
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}
