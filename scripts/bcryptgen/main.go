// bcryptgen 运维小工具: 明文 → bcrypt 哈希, 用于往 clients.secret_hash 里填注册 RP 的凭证。
//
// ⚠️ 它与"用户密码"无关 —— akasha 不做本地密码认证 (2026-08-09 定案),
// users 表已无 password 列。这里的 bcrypt 只服务于 client_secret。
//
// 用法: go run ./scripts/bcryptgen <明文>
package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "用法: go run ./scripts/bcryptgen <明文>")
		os.Exit(1)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(os.Args[1]), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "生成失败:", err)
		os.Exit(1)
	}
	fmt.Println(string(hash))
}
