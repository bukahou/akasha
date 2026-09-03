package client

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// clientsFile clients.yaml 的顶层结构。
type clientsFile struct {
	Clients []Client `yaml:"clients"`
}

// bcryptPattern 合法 bcrypt 哈希: $2a/$2b/$2y + 两位 cost + 53 字节 base64 变体。
//
// 校验它的真实目的不是防伪造, 而是抓一类最容易犯的错:
// 有人把【明文 secret】直接粘进了 yaml —— 明文长得不像 bcrypt, 在这里被拒,
// 就不会带着一个永远验不过的"哈希"上线, 更不会把明文留在 git 历史里。
var bcryptPattern = regexp.MustCompile(`^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$`)

// NewRegistryFromFile 加载并校验 clients.yaml, 构建只读注册表。
//
// 任何一条不合法 → 返回错误 → 调用方 (main) 启动失败。这是刻意的闸门:
// readiness 不过, 旧 pod 继续服务, 坏配置到不了线上。
func NewRegistryFromFile(path string) (*Registry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 clients 文件失败: %w", err)
	}

	var f clientsFile
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	// 拒绝未知字段: "redirect_uri" 这类字段名笔误在宽松模式下会被静默丢弃,
	// 结果是白名单为空 —— 一个拼写错误不该以"该应用无人能登录"的形式暴露。
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("clients 文件解析失败: %w", err)
	}

	if len(f.Clients) == 0 {
		return nil, fmt.Errorf("clients 文件没有任何条目 —— 空注册表意味着没有应用能登录, 若是有意为之请显式确认文件内容")
	}
	seen := make(map[string]bool, len(f.Clients))
	for i := range f.Clients {
		c := &f.Clients[i]
		if err := validateClient(c); err != nil {
			return nil, fmt.Errorf("clients[%d] (%s): %w", i, c.ClientID, err)
		}
		if seen[c.ClientID] {
			return nil, fmt.Errorf("client_id %q 重复 —— 后一条会静默覆盖前一条, 拒绝加载", c.ClientID)
		}
		seen[c.ClientID] = true
	}
	return newRegistry(f.Clients), nil
}

// validateClient 单条注册记录的完整性校验。
func validateClient(c *Client) error {
	if c.ClientID == "" {
		return fmt.Errorf("client_id 不能为空")
	}
	if c.ClientType != TypeConfidential && c.ClientType != TypePublic {
		return fmt.Errorf("client_type 必须是 %q 或 %q, 实际是 %q", TypeConfidential, TypePublic, c.ClientType)
	}
	if c.Name == "" {
		// 登录页要显示"继续前往 <name>" —— 空名会让反钓鱼提示变成空白
		return fmt.Errorf("name 不能为空")
	}
	switch {
	case c.IsPublic() && c.SecretHash != "":
		return fmt.Errorf("public 客户端不得配置 secret_hash (它无法保管 secret, 配了说明类型写错了)")
	case !c.IsPublic() && c.SecretHash == "":
		return fmt.Errorf("confidential 客户端必须配置 secret_hash")
	case !c.IsPublic() && !bcryptPattern.MatchString(c.SecretHash):
		return fmt.Errorf("secret_hash 不是合法的 bcrypt 哈希 —— 最常见的原因是把明文 secret 粘了进来; 明文须放各应用的 K8s Secret, 这里只放 bcrypt")
	}
	if len(c.RedirectURIs) == 0 {
		return fmt.Errorf("redirect_uris 至少要有一条")
	}
	for _, u := range c.RedirectURIs {
		if err := validateURI(u); err != nil {
			return fmt.Errorf("redirect_uris %q: %w", u, err)
		}
	}
	for _, u := range c.PostLogoutRedirectURIs {
		if err := validateURI(u); err != nil {
			return fmt.Errorf("post_logout_redirect_uris %q: %w", u, err)
		}
	}
	return nil
}

// validateURI 白名单条目必须是不带 fragment 的绝对 URL。
//
// 绝对: 相对路径拼不出确定的落点。
// 无 fragment: RFC 6749 §3.1.2 明文禁止 redirect_uri 携带 fragment ——
// OP 回投时要在它后面追加自己的参数, fragment 会吞掉它们。
func validateURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("无法解析: %w", err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("必须是绝对 URL (含 scheme)")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("不得携带 fragment (RFC 6749 §3.1.2)")
	}
	return nil
}
