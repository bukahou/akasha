// Package password bcrypt 哈希/验证 (geass internal/user/password 同款平移)。
package password

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// ErrMismatch 密码不匹配 (区别于系统错误, 调用方据此返回"凭证无效")。
var ErrMismatch = errors.New("密码不匹配")

// Hash bcrypt 哈希 (默认 cost=10)。
func Hash(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Verify 校验明文与哈希; 不匹配返回 ErrMismatch。
func Verify(plain, hashed string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrMismatch
	}
	return err
}
