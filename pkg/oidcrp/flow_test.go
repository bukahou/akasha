package oidcrp

import (
	"testing"
)

// TestDefaultSafeNext ⭐ 开放重定向的第一道闸。
//
// 放行一个外部 URL 的后果: 用户在【可信域名】上正常完成登录, 却被送去钓鱼站 ——
// 地址栏全程显示的是本站, 用户没有任何察觉的机会。
//
// 最容易漏的是 "//evil.com": 它以 / 开头, 长得像本站路径, 但浏览器把它当作
// 【协议相对 URL】解析成 https://evil.com。只判 HasPrefix(next, "/") 会直接放行它。
func TestDefaultSafeNext(t *testing.T) {
	allow := []string{
		"/",
		"/anime/123",
		"/search?q=x&page=2",
		"/a/b/c#frag",
	}
	deny := []string{
		"",                        // 缺失
		"https://evil.test/steal", // 绝对 URL
		"http://evil.test",        //
		"//evil.test",             // ⭐ 协议相对 URL —— 浏览器当绝对地址
		"//evil.test/path",        //
		`/\evil.test`,             // ⭐ 部分浏览器等价于 //evil.test
		"anime/123",               // 相对路径, 拼接后落点不可控
		"javascript:alert(1)",     // 伪协议
		"\\\\evil.test",           // UNC 风格
	}

	for _, s := range allow {
		if !DefaultSafeNext(s) {
			t.Errorf("%q 被拒了, 它是合法的本站路径", s)
		}
	}
	for _, s := range deny {
		if DefaultSafeNext(s) {
			t.Errorf("⚠️ %q 被放行 —— 开放重定向", s)
		}
	}
}

// TestConfigDefaults 留空的配置项必须落到安全的默认值。
//
// 尤其 Scopes: 空着不补的话请求只带 openid, 遵守规范的 provider 按 scope
// 分发 claims —— 结果是拿到一个除了 sub 什么都没有的 id_token, 建号时
// 连昵称和邮箱都没有。这种失败不会报错, 只会让新用户档案是空的。
func TestConfigDefaults(t *testing.T) {
	// 不调 New (它会去拉 discovery, 需要网络), 只验证补默认值那段逻辑。
	// 把它单独拎出来测, 是因为"忘了补默认值"不会让编译或运行失败。
	cfg := Config{}
	applyDefaults(&cfg)

	if len(cfg.Scopes) == 0 {
		t.Error("Scopes 未补默认值 —— 只带 openid 会拿到没有任何用户资料的 id_token")
	}
	if cfg.FlowTTL <= 0 {
		t.Error("FlowTTL 未补默认值 —— 0 意味着 cookie 一出生就过期")
	}
	if cfg.SafeNext == nil {
		t.Error("SafeNext 未补默认值 —— nil 会在 Start 里 panic")
	}
	if cfg.Logger == nil {
		t.Error("Logger 未补默认值")
	}
	if cfg.CookiePrefix == "" {
		t.Error("CookiePrefix 未补默认值 —— 空前缀会让 cookie 名以裸 state 开头")
	}
}
