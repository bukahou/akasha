package client

import "testing"

// TestValidateRedirectURI 回调白名单是开放重定向的唯一防线。
//
// 放宽任何一点, 攻击者就能让 akasha 把带着授权码的用户送到自己的站点 ——
// 而链接指向的是可信域名, 用户没有任何可疑之处可看。
func TestValidateRedirectURI(t *testing.T) {
	r := &Registry{}
	c := &Client{RedirectURIs: []string{"https://geass.test/auth/callback", "com.bukahou.app://cb"}}

	t.Run("精确匹配放行", func(t *testing.T) {
		for _, uri := range []string{"https://geass.test/auth/callback", "com.bukahou.app://cb"} {
			if err := r.ValidateRedirectURI(c, uri); err != nil {
				t.Errorf("已注册地址被拒: %s", uri)
			}
		}
	})

	t.Run("任何不精确的变体都拒绝", func(t *testing.T) {
		denied := map[string]string{
			"https://geass.test/auth/callback/":         "尾部多一个斜杠",
			"https://geass.test/auth/callback?x=1":      "多了查询参数",
			"https://geass.test/auth/callback2":         "路径前缀相同但不同",
			"https://geass.test/auth":                   "路径是注册值的前缀",
			"http://geass.test/auth/callback":           "协议降级为 http",
			"https://evil.test/auth/callback":           "换了域名",
			"https://geass.test.evil.com/auth/callback": "域名后缀攻击",
			"https://GEASS.test/auth/callback":          "大小写变体",
			"":                                          "空值",
		}
		for uri, why := range denied {
			if err := r.ValidateRedirectURI(c, uri); err == nil {
				t.Errorf("危险地址被放行 (%s): %s", why, uri)
			}
		}
	})

	t.Run("白名单为空时一律拒绝", func(t *testing.T) {
		empty := &Client{RedirectURIs: []string{}}
		if err := r.ValidateRedirectURI(empty, "https://geass.test/cb"); err == nil {
			t.Error("空白名单放行了地址")
		}
		none := &Client{RedirectURIs: nil}
		if err := r.ValidateRedirectURI(none, "https://geass.test/cb"); err == nil {
			t.Error("未配置白名单时放行了地址")
		}
	})
}

// TestLoopbackExemption RFC 8252 §7.3 要求对 loopback 忽略端口 ——
// 桌面应用与 CLI 的回调端口由系统动态分配, 注册时无从得知。
//
// 但这是【唯一】的放宽, 且只对 IP 字面量生效。
func TestLoopbackExemption(t *testing.T) {
	r := &Registry{}
	c := &Client{RedirectURIs: []string{"http://127.0.0.1:0/callback"}}

	t.Run("任意端口放行", func(t *testing.T) {
		for _, uri := range []string{
			"http://127.0.0.1:1/callback",
			"http://127.0.0.1:54321/callback",
			"http://127.0.0.1:65535/callback",
		} {
			if err := r.ValidateRedirectURI(c, uri); err != nil {
				t.Errorf("loopback 任意端口应放行: %s", uri)
			}
		}
	})

	t.Run("端口之外的一切仍须一致", func(t *testing.T) {
		denied := map[string]string{
			"http://127.0.0.1:8080/other":        "路径不同",
			"https://127.0.0.1:8080/callback":    "协议不同",
			"http://127.0.0.1:8080/callback?x=1": "多了查询参数",
		}
		for uri, why := range denied {
			if err := r.ValidateRedirectURI(c, uri); err == nil {
				t.Errorf("%s 却被放行: %s", why, uri)
			}
		}
	})

	// ⭐ 这条是刻意的安全取舍, 不是疏漏。
	//
	// 构造要点: 注册的与请求的【都用 localhost】, 只有端口不同 —— 这样唯一的
	// 变量就是"localhost 算不算 loopback"。若拿 127.0.0.1 的注册值去比 localhost
	// 的请求, host 字符串本就不同, 无论豁免是否放宽都会被拒, 测不出任何东西。
	t.Run("localhost 不享受端口豁免", func(t *testing.T) {
		lh := &Client{RedirectURIs: []string{"http://localhost:3000/callback"}}
		if err := r.ValidateRedirectURI(lh, "http://localhost:54321/callback"); err == nil {
			t.Error("localhost 被豁免了端口 —— 它要经 DNS 解析, 可被 hosts 文件或 DNS 投毒" +
				"指向别处; RFC 8252 §8.3 明确建议用 IP 字面量")
		}
		// 完全一致时当然仍应放行 (走的是精确匹配那条路)
		if err := r.ValidateRedirectURI(lh, "http://localhost:3000/callback"); err != nil {
			t.Errorf("精确匹配的 localhost 地址被拒: %v", err)
		}
	})

	t.Run("跨 host 写法不互认", func(t *testing.T) {
		// 127.0.0.1 与 localhost 指向同一台机器, 但字符串不同即视为不同地址
		if err := r.ValidateRedirectURI(c, "http://localhost:54321/callback"); err == nil {
			t.Error("注册 127.0.0.1 却放行了 localhost")
		}
	})

	t.Run("非 loopback 地址不豁免端口", func(t *testing.T) {
		pub := &Registry{}
		pc := &Client{RedirectURIs: []string{"https://geass.test:443/cb"}}
		if err := pub.ValidateRedirectURI(pc, "https://geass.test:8443/cb"); err == nil {
			t.Error("公网地址的端口被忽略了 —— 豁免只适用于 loopback")
		}
	})

	t.Run("IPv6 loopback 同样豁免", func(t *testing.T) {
		v6 := &Client{RedirectURIs: []string{"http://[::1]:0/callback"}}
		if err := r.ValidateRedirectURI(v6, "http://[::1]:12345/callback"); err != nil {
			t.Errorf("IPv6 loopback 应放行: %v", err)
		}
	})
}

// TestValidatePostLogoutRedirectURI 登出回跳是独立的白名单。
//
// 与授权回调分开, 是为了不让"能接收授权码"顺带获得"能被登出流程跳到"的能力。
func TestValidatePostLogoutRedirectURI(t *testing.T) {
	r := &Registry{}
	c := &Client{
		RedirectURIs:           []string{"https://geass.test/cb"},
		PostLogoutRedirectURIs: []string{"https://geass.test/bye"},
	}

	if err := r.ValidatePostLogoutRedirectURI(c, "https://geass.test/bye"); err != nil {
		t.Errorf("已注册的登出地址被拒: %v", err)
	}
	// 两份白名单不得互相串用
	if err := r.ValidatePostLogoutRedirectURI(c, "https://geass.test/cb"); err == nil {
		t.Error("授权回调地址被当作登出回跳地址放行了 —— 两份白名单不该互通")
	}
	if err := r.ValidateRedirectURI(c, "https://geass.test/bye"); err == nil {
		t.Error("登出地址被当作授权回调放行了")
	}

	empty := &Client{PostLogoutRedirectURIs: []string{}}
	if err := r.ValidatePostLogoutRedirectURI(empty, "https://geass.test/bye"); err == nil {
		t.Error("未注册登出地址的 client 放行了跳转")
	}
}

// TestIsPublic client_type 决定 /token 是否要求 secret。
func TestIsPublic(t *testing.T) {
	if (&Client{ClientType: TypePublic}).IsPublic() != true {
		t.Error("public 客户端未被识别")
	}
	if (&Client{ClientType: TypeConfidential}).IsPublic() != false {
		t.Error("confidential 客户端被误判为 public")
	}
	// 空值必须保守地按 confidential 处理 —— 默认要求 secret 比默认放行安全
	if (&Client{ClientType: ""}).IsPublic() != false {
		t.Error("client_type 为空时被当作 public —— 默认值必须是更严格的那一侧")
	}
}
