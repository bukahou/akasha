package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// devBcrypt 测试用哈希 (bcrypt("x"), cost 10) —— 只求格式合法, 无真实意义。
const devBcrypt = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

func writeYAML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "clients.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const validYAML = `
clients:
  - client_id: app1
    client_type: confidential
    name: "应用一"
    secret_hash: "` + devBcrypt + `"
    redirect_uris:
      - https://app1.example/cb
    post_logout_redirect_uris:
      - https://app1.example/
  - client_id: cli1
    client_type: public
    name: "CLI"
    redirect_uris:
      - http://127.0.0.1:0/callback
`

func TestLoadFile_合法文件(t *testing.T) {
	r, err := NewRegistryFromFile(writeYAML(t, validYAML))
	if err != nil {
		t.Fatalf("合法文件被拒: %v", err)
	}
	c, err := r.FindByClientID(t.Context(), "app1")
	if err != nil || c.Name != "应用一" {
		t.Fatalf("app1 查找失败: %v %+v", err, c)
	}
	if err := r.ValidateRedirectURI(c, "https://app1.example/cb"); err != nil {
		t.Errorf("白名单内地址被拒: %v", err)
	}
	if err := r.ValidateRedirectURI(c, "https://evil.example/cb"); err == nil {
		t.Error("白名单外地址被放行")
	}
	if _, err := r.FindByClientID(t.Context(), "ghost"); err == nil {
		t.Error("未注册 client 被找到")
	}
}

// TestLoadFile_坏文件全家桶 每条校验规则各一个反例。
// 断言错误信息包含关键词 —— 启动失败时人靠它定位, 报错含糊等于没报。
func TestLoadFile_坏文件全家桶(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{"文件不存在时报读取错误", "", "读取"},
		{"空注册表被拒", "clients: []", "没有任何条目"},
		{"client_id 为空", `
clients:
  - client_id: ""
    client_type: public
    name: x
    redirect_uris: ["https://a.example/cb"]`, "client_id 不能为空"},
		{"client_type 非枚举", `
clients:
  - client_id: a
    client_type: internal
    name: x
    redirect_uris: ["https://a.example/cb"]`, "client_type"},
		{"name 为空", `
clients:
  - client_id: a
    client_type: public
    name: ""
    redirect_uris: ["https://a.example/cb"]`, "name 不能为空"},
		{"confidential 缺 secret_hash", `
clients:
  - client_id: a
    client_type: confidential
    name: x
    redirect_uris: ["https://a.example/cb"]`, "必须配置 secret_hash"},
		{"⭐ 明文被当成哈希粘进来", `
clients:
  - client_id: a
    client_type: confidential
    name: x
    secret_hash: "my-plaintext-secret-oops"
    redirect_uris: ["https://a.example/cb"]`, "不是合法的 bcrypt"},
		{"public 带了 secret_hash", `
clients:
  - client_id: a
    client_type: public
    name: x
    secret_hash: "` + devBcrypt + `"
    redirect_uris: ["https://a.example/cb"]`, "public 客户端不得配置"},
		{"redirect_uris 为空", `
clients:
  - client_id: a
    client_type: public
    name: x
    redirect_uris: []`, "至少要有一条"},
		{"相对路径回调", `
clients:
  - client_id: a
    client_type: public
    name: x
    redirect_uris: ["/callback"]`, "绝对 URL"},
		{"回调带 fragment", `
clients:
  - client_id: a
    client_type: public
    name: x
    redirect_uris: ["https://a.example/cb#frag"]`, "fragment"},
		{"client_id 重复", `
clients:
  - client_id: a
    client_type: public
    name: x
    redirect_uris: ["https://a.example/cb"]
  - client_id: a
    client_type: public
    name: y
    redirect_uris: ["https://b.example/cb"]`, "重复"},
		{"⭐ 字段名笔误被拒而非静默丢弃", `
clients:
  - client_id: a
    client_type: public
    name: x
    redirect_uri: ["https://a.example/cb"]`, "field"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := "/nonexistent/clients.yaml"
			if c.yaml != "" {
				path = writeYAML(t, c.yaml)
			}
			_, err := NewRegistryFromFile(path)
			if err == nil {
				t.Fatalf("坏文件被放行")
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("错误信息缺少关键词 %q:\n  %v", c.wantErr, err)
			}
		})
	}
}

// TestLoadFile_公开客户端认证语义 加载出来的 Registry 行为与旧 DB 版一致。
func TestLoadFile_公开客户端认证语义(t *testing.T) {
	r, err := NewRegistryFromFile(writeYAML(t, validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Authenticate(t.Context(), "cli1", ""); err != nil {
		t.Errorf("public 无 secret 应通过: %v", err)
	}
	if _, err := r.Authenticate(t.Context(), "cli1", "sneaky"); err == nil {
		t.Error("public 带 secret 应被拒")
	}
	if _, err := r.Authenticate(t.Context(), "app1", "wrong"); err == nil {
		t.Error("confidential 错 secret 应被拒")
	}
}
