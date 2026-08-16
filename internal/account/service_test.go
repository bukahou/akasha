package account

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestDeriveInternalID internal_id 由上游身份派生, 这是"akasha 重建后自动恢复"的根据。
//
// 若改成随机值, 删库重建后同一个上游账号会算出不同的 internal_id →
// 各下游的 pairwise sub 全变 → 所有应用都把老用户当成新人。
func TestDeriveInternalID(t *testing.T) {
	// 虚构的上游 subject。保持 Google 的 21 位数字形态便于阅读, 但值本身是编的 ——
	// 本仓公开, 真实账号标识不该出现在测试里。
	const (
		provider = "google"
		subject  = "123456789012345678901"
	)

	got := DeriveInternalID(provider, subject)

	// 与独立实现比对, 锁定算法本身
	sum := sha256.Sum256([]byte(provider + "\x00" + subject))
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("internal_id = %s, 期望 SHA256(provider \\0 subject) = %s", got, want)
	}
	if len(got) != 64 {
		t.Errorf("长度 = %d, 期望 64", len(got))
	}
}

func TestDeriveInternalID_Deterministic(t *testing.T) {
	first := DeriveInternalID("google", "12345")
	for i := 0; i < 3; i++ {
		if got := DeriveInternalID("google", "12345"); got != first {
			t.Fatal("同样输入算出不同结果 —— 重建恢复能力失效")
		}
	}
}

// TestDeriveInternalID_ProviderSeparation 不同上游的同名 subject 必须是不同的人。
//
// Google 的 sub "12345" 与 GitHub 的 user id "12345" 是毫不相干的两个人。
// 若 provider 不参与计算, 他们会共用一个 akasha 账号 —— 一个人能直接登入另一个人。
func TestDeriveInternalID_ProviderSeparation(t *testing.T) {
	google := DeriveInternalID("google", "12345")
	github := DeriveInternalID("github", "12345")
	if google == github {
		t.Fatal("不同 provider 的同名 subject 算出相同 internal_id —— 跨上游串号")
	}
}

// TestDeriveInternalID_NoDelimiterAmbiguity 分隔符必须挡住拼接歧义。
//
// 若用普通字符作分隔, ("goog","le:1") 与 ("google",":1") 会拼成同一个字符串,
// 于是两个不同的上游身份映射到同一个 akasha 账号。
func TestDeriveInternalID_NoDelimiterAmbiguity(t *testing.T) {
	a := DeriveInternalID("goog", "le\x00123")
	b := DeriveInternalID("google", "123")
	if a == b {
		t.Fatal("存在拼接歧义 —— 两个不同的上游身份算出同一个 internal_id")
	}
}

// TestSanitizeUsername username 由上游数据自动生成, 必须先洗干净再用。
//
// 它会进入 URL、HTML 与日志。虽然模板层有转义, 但在生成阶段就限定字符集
// 是更省心的做法 —— 后面任何一处忘了转义都不会立刻变成漏洞。
func TestSanitizeUsername(t *testing.T) {
	tests := []struct {
		in   string
		want string
		why  string
	}{
		{"bukahou", "bukahou", "正常输入原样保留"},
		{"buka.hou", "bukahou", "点号被清掉"},
		{"buka hou", "bukahou", "空格被清掉"},
		{"buka-hou_1", "buka-hou_1", "连字符与下划线是允许字符"},
		{"张三丰", "", "非 ASCII 全部清掉"},
		{"<script>alert(1)</script>", "scriptalert1script", "HTML 标签字符被清掉"},
		{"../../etc/passwd", "etcpasswd", "路径穿越字符被清掉"},
		{"a@b.com", "abcom", "邮箱符号被清掉"},
		{"", "", "空输入"},
		{"'; DROP TABLE users--", "DROPTABLEusers--", "SQL 注入字符被清掉"},
	}

	for _, tt := range tests {
		t.Run(tt.why, func(t *testing.T) {
			if got := sanitizeUsername(tt.in); got != tt.want {
				t.Errorf("sanitizeUsername(%q) = %q, 期望 %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeUsername_Truncates(t *testing.T) {
	long := strings.Repeat("a", 100)
	got := sanitizeUsername(long)
	// users.username 是 VARCHAR(64), 生成阶段就截断以免插入时报错
	if len(got) != 32 {
		t.Errorf("长度 = %d, 期望截断到 32", len(got))
	}
}

// TestSanitizeUsername_OnlyAllowedChars 属性测试: 输出只能含允许的字符集。
func TestSanitizeUsername_OnlyAllowedChars(t *testing.T) {
	inputs := []string{
		"用户名123", "a\x00b", "a\nb", "a\tb", "%2F%2E%2E", "🎉emoji🎉",
		"a/b\\c", "a?b#c", "a&b=c", "a<b>c", "a\"b'c",
	}
	const allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	for _, in := range inputs {
		got := sanitizeUsername(in)
		for _, r := range got {
			if !strings.ContainsRune(allowed, r) {
				t.Errorf("sanitizeUsername(%q) = %q 含非法字符 %q", in, got, r)
			}
		}
	}
}
