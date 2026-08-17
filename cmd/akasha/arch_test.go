package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 依赖方向的【声明】—— 与本包 doc 注释和 CLAUDE.md 的架构图三处一致。
//
// # 为什么这个测试存在
//
// 2026-08-17 的审计复盘发现: 首轮审计把「依赖方向」判为符合项, 判据写的是
// "单向且实测无环"。无环这部分没错, 但真正该查的是【是否符合声明的架构】——
// login → op 这条计划外依赖当时已经存在, 且 CLAUDE.md 里就标着 ⚠️,
// 审计却没回头对照。
//
// 无环 ≠ 符合设计。人来查这类东西, 判据的措辞决定了会去看什么;
// 机器不会看漏, 也不会因为"上次看过了"而跳过。
//
// # 怎么维护
//
// 新增一条依赖时, 这里会红。两种正确反应:
//
//	① 这条依赖不该有 → 改代码 (比如像 federation 那样用函数注入避开)
//	② 这条依赖是设计的一部分 → 同时更新此表、main 的 doc 注释、CLAUDE.md
//
// 【不要】只改这里让测试变绿 —— 那等于把架构约束改成了架构描述。
var declaredDeps = map[string][]string{
	// 身份权威在最底层, 不知道任何人
	"account": {},

	// 以下几个是自足的基础设施, 不依赖任何内部包
	"client":  {},
	"config":  {},
	"keys":    {},
	"server":  {},
	"storage": {},

	// 协议层调所有下层
	"op": {"account", "client", "keys"},

	// 上游 broker。刻意【不】依赖 op ——
	// 它需要的 SafeLocalNext 与 CompleteAuthorize 都由 main 注入
	"federation": {"account"},

	// ⚠️ login → op 是【计划外】依赖: 为复用 op.SafeLocalNext 一个函数而产生。
	// federation 后来遇到同样需求时改用了函数注入, login 还没跟上 ——
	// 同一个问题两种解法并存。处置方案见 docs/tasks/active/polish-tasks.md,
	// 待拍板。此处如实登记现状, 不假装它不存在。
	"login": {"op"},
}

const internalPrefix = "github.com/bukahou/akasha/internal/"

func TestDependencyDirection(t *testing.T) {
	root := filepath.Join("..", "..", "internal")

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("读取 internal/ 失败: %v", err)
	}

	seen := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkg := e.Name()
		actual := internalImportsOf(t, filepath.Join(root, pkg))
		if actual == nil {
			continue // 目录里没有 Go 源码 (如 login/templates)
		}
		seen[pkg] = true

		want, declared := declaredDeps[pkg]
		if !declared {
			t.Errorf("包 %q 未在 declaredDeps 中登记 —— 新增包时必须同时声明它的依赖", pkg)
			continue
		}

		allowed := map[string]bool{}
		for _, d := range want {
			allowed[d] = true
		}
		for _, dep := range actual {
			if !allowed[dep] {
				t.Errorf("未声明的依赖: %s → %s\n"+
					"  若这条依赖是有意引入的, 需同时更新 declaredDeps、cmd/akasha/main.go 的 doc 注释、CLAUDE.md 的架构图;\n"+
					"  若是无意引入的, 考虑像 federation 那样用函数注入避开", pkg, dep)
			}
		}
		// 声明了却实际没有的依赖 —— 说明声明过时了, 同样要报
		for _, d := range want {
			if !contains(actual, d) {
				t.Errorf("声明了但实际不存在的依赖: %s → %s (声明已过时, 请清理)", pkg, d)
			}
		}
	}

	for pkg := range declaredDeps {
		if !seen[pkg] {
			t.Errorf("declaredDeps 中登记了 %q, 但 internal/ 下不存在该包 (包已删除? 请同步清理声明)", pkg)
		}
	}
}

// TestAccountIsLeaf 单独立一条: 身份权威必须是依赖图的叶子。
//
// 这是整个架构最重要的一条约束 —— account 一旦依赖别人, 就意味着"谁是用户"
// 这件事开始受协议层或传输层影响。它值得一个独立的、名字自解释的测试,
// 而不是淹没在上面那张表里。
func TestAccountIsLeaf(t *testing.T) {
	deps := internalImportsOf(t, filepath.Join("..", "..", "internal", "account"))
	if len(deps) != 0 {
		t.Errorf("account 依赖了 %v —— 身份权威必须在最底层, 不依赖任何内部包", deps)
	}
}

// internalImportsOf 解析一个包目录, 返回它 import 的内部包名 (去重排序)。
// 排除 _test.go: 测试文件为了构造场景可以 import 更多东西, 不代表生产依赖。
func internalImportsOf(t *testing.T, dir string) []string {
	t.Helper()

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("解析 %s 失败: %v", dir, err)
	}
	if len(pkgs) == 0 {
		return nil
	}

	set := map[string]bool{}
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, imp := range f.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if !strings.HasPrefix(path, internalPrefix) {
					continue
				}
				// internal/account/password → account (只看顶层包)
				rest := strings.TrimPrefix(path, internalPrefix)
				set[strings.SplitN(rest, "/", 2)[0]] = true
			}
		}
	}

	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
