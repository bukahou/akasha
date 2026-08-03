// bcryptgen 运维小工具: 明文 → bcrypt 哈希 (seed client_secret / 导入用户密码用)。
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
