package oidcrp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/oauth2"
)

// # 往返期间的状态保管
//
// 上游登录是两次【互不相关】的 HTTP 请求, 中间隔着一个本应用不控制的第三方:
//
//	① GET  /start      生成 state/nonce/verifier, 跳去 provider
//	┄┄┄ 用户在 provider 那边选账号、输密码、可能过 MFA, 几十秒到几分钟 ┄┄┄
//	② GET  /callback   provider 把用户送回来
//
// provider 只会原样回传 state 这一个参数, 藏在别处的东西它一概不管。所以 ①
// 生成的四样东西必须自己想办法活到 ②:
//
//	state     防登录 CSRF —— 见下方"为什么必须绑定浏览器"
//	nonce     防 id_token 重放 (provider 把它签进 token, 回来时逐字比对)
//	verifier  PKCE 的原文。截获 code 的人拿不出它, 兑换即失败
//	next      用户原本要去的应用内路径
//
// # 为什么是签名 cookie 而不是数据库表
//
// 这段状态只活几分钟, 为它建表 + 一处过期清理不划算。签名 cookie 无状态,
// 多副本部署天然友好, 也不需要粘性会话。
//
// 代价是一次性消费只能"尽力而为": 服务端能做的只是回复一个删除指令, 用户
// 完全可以留一份副本重放。但真实攻击链上打不出伤害 —— 重放一个用过的 state,
// 对应的 code 早被 provider 消费掉了, 换不出任何东西。
//
// # 为什么必须绑定浏览器 (这条决定了不能用无状态签名 state)
//
// 登录 CSRF 的攻击形态是【反的】—— 不是攻击者登录成你, 而是把你塞进他的账号:
//
//	① 攻击者用自己的账号走完授权, 拿到回调 URL 但【不访问】
//	② 诱导受害者点击该 URL
//	③ 本应用用攻击者的 code 换到攻击者身份, 却在【受害者浏览器】里种下会话
//	④ 受害者以为在用自己的账号, 此后的操作全进了攻击者账号
//
// 挡它的关键是: 光验"这个 state 是我发过的"没有用 —— 攻击者的 state 也是
// 本应用发的、签名也是合法的。必须验"这个 state 是【这个浏览器】发起时拿到的"。
// 而"只有发起者的浏览器才有"的东西, 只能是 cookie。
//
// 推论: 任何不依赖浏览器侧存储的方案 (例如把 nonce/next 编进签名 JWT 当 state)
// 都无法区分"我自己发起的流程"和"别人发起、诱导我完成的流程" —— 无状态与
// CSRF 防护本质上不兼容。

// cookieNameStateLen state 取前几位进 cookie 名 (hex 字符, 可安全用于 cookie 名)。
//
// 每个流程一个独立 cookie: 用户同时在两个标签页登录时, 固定名字会互相覆盖,
// 先发起的那个回调时就找不到自己的状态了。
const cookieNameStateLen = 8

var (
	errStateMissing  = errors.New("登录状态 cookie 缺失或已过期")
	errStateBadSig   = errors.New("登录状态签名校验失败")
	errStateMismatch = errors.New("state 与 cookie 不匹配")
	errStateExpired  = errors.New("登录流程已超时, 请重新登录")
)

// flowState 一次登录流程需要跨越 provider 往返的全部状态。
//
// json tag 用单字母: 它会被 base64 编进 cookie, 浏览器对单个 cookie 有 4KB 上限,
// 而 next 可能是一条很长的路径。省下的每个字节都直接变成 next 的余量。
type flowState struct {
	State string `json:"s"`
	Nonce string `json:"n"`
	// Verifier PKCE code_verifier。
	//
	// ⚠️ 它【必须】与 state 存在同一个签名 cookie 里 —— PKCE 的全部价值就是
	// "只有发起这次流程的人拿得出它"。放进 URL 或任何不受保护的地方,
	// 截获 code 的人就能一并拿到, 防护直接归零。
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Exp      int64  `json:"e"`
}

// stateKeeper 用签名 cookie 保管往返状态。不导出 —— 本包对外只有 Flow 一个入口。
type stateKeeper struct {
	key          []byte
	ttl          time.Duration
	cookiePrefix string
	cookiePath   string
	cookieSecure bool
}

// newStateKeeper 构造保管器。
//
// key 由调用方给的 secret 经 HKDF 派生而非直接使用 —— 同一密钥服务于两个不同
// 密码学用途时, 对一方的分析可能削弱另一方 (调用方很可能拿它同时干别的)。
// 派生后两者数学上独立, 且 HKDF 单向: 即便 cookie 密钥泄漏也反推不回原 secret。
func newStateKeeper(secret string, ttl time.Duration, prefix, path string, secure bool) (*stateKeeper, error) {
	if secret == "" {
		return nil, errors.New("cookie 签名密钥不能为空")
	}
	key := make([]byte, 32)
	// info 串把用途写死: 将来若需要第二种用途, 换 info 即可再派生一把独立密钥
	kdf := hkdf.New(sha256.New, []byte(secret), nil, []byte("oidcrp-state-cookie-v1"))
	if _, err := kdf.Read(key); err != nil {
		return nil, fmt.Errorf("派生状态 cookie 密钥失败: %w", err)
	}
	return &stateKeeper{
		key: key, ttl: ttl,
		cookiePrefix: prefix, cookiePath: path, cookieSecure: secure,
	}, nil
}

// begin 生成一次流程的状态并写入签名 cookie。
func (k *stateKeeper) begin(w http.ResponseWriter, next string) (*flowState, error) {
	state, err := randomToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken()
	if err != nil {
		return nil, err
	}

	fs := &flowState{
		State: state,
		Nonce: nonce,
		// oauth2.GenerateVerifier 产出 RFC 7636 合规的高熵随机串 (43-128 字符)
		Verifier: oauth2.GenerateVerifier(),
		Next:     next,
		Exp:      time.Now().Add(k.ttl).Unix(),
	}
	payload, err := json.Marshal(fs)
	if err != nil {
		return nil, err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     k.cookieName(state),
		Value:    k.sign(payload),
		Path:     k.cookiePath,
		MaxAge:   int(k.ttl.Seconds()),
		HttpOnly: true,
		Secure:   k.cookieSecure,
		// Lax: 从 provider 跳回来是【跨站顶级导航 GET】, Lax 会放行。
		// Strict 会把这类跳转的 cookie 掐掉, 第三方登录直接失效。
		SameSite: http.SameSiteLaxMode,
	})
	return fs, nil
}

// finish 校验回调带回的 state 并取出保管的内容, 随后清除 cookie。
// 无论成功与否都应视为该流程已结束。
func (k *stateKeeper) finish(w http.ResponseWriter, r *http.Request, state string) (*flowState, error) {
	if state == "" {
		return nil, errStateMissing
	}
	c, err := r.Cookie(k.cookieName(state))
	if err != nil || c.Value == "" {
		return nil, errStateMissing
	}
	// 无论后续校验结果如何, cookie 都不该继续留着
	k.clear(w, state)

	payload, err := k.verify(c.Value)
	if err != nil {
		return nil, err
	}
	var fs flowState
	if err := json.Unmarshal(payload, &fs); err != nil {
		return nil, errStateBadSig
	}

	// 定长比较: state 是攻击者可控的输入, 用普通 != 会因提前返回而泄漏匹配进度
	if subtle.ConstantTimeCompare([]byte(fs.State), []byte(state)) != 1 {
		return nil, errStateMismatch
	}
	// cookie 的 MaxAge 由浏览器执行, 不能信 —— 服务端自己再判一次
	if time.Now().Unix() > fs.Exp {
		return nil, errStateExpired
	}
	return &fs, nil
}

// peek 只读取流程状态, 【不】清除 cookie、【不】校验是否过期。
//
// 存在的唯一理由: 用户在上游点取消时, 我们需要知道"他原本要回哪去"才能把他
// 送回原处 (原生客户端尤其需要 —— 送错地方就等于让 App 的登录会话悬在那里)。
// 而那条路径的设计是【不消费 state】, 让用户能直接再试一次。
//
// 仍然验签: 它决定一次重定向的目标, 不验就是开放重定向。
// 不判过期: 拿它只为知道回跳目标, 一个过期流程的目标依然是那个目标。
func (k *stateKeeper) peek(r *http.Request, state string) (*flowState, error) {
	if state == "" {
		return nil, errStateMissing
	}
	c, err := r.Cookie(k.cookieName(state))
	if err != nil || c.Value == "" {
		return nil, errStateMissing
	}
	payload, err := k.verify(c.Value)
	if err != nil {
		return nil, err
	}
	var fs flowState
	if err := json.Unmarshal(payload, &fs); err != nil {
		return nil, errStateBadSig
	}
	if subtle.ConstantTimeCompare([]byte(fs.State), []byte(state)) != 1 {
		return nil, errStateMismatch
	}
	return &fs, nil
}

// clear 让浏览器立即丢弃该流程的 cookie。
// 属性必须与写入时一致 (Path/Secure/SameSite), 否则浏览器会认作另一个 cookie 而删不掉。
func (k *stateKeeper) clear(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name: k.cookieName(state), Value: "", Path: k.cookiePath, MaxAge: -1,
		HttpOnly: true, Secure: k.cookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

// sign 输出 base64(payload).base64(hmac)。
func (k *stateKeeper) sign(payload []byte) string {
	mac := hmac.New(sha256.New, k.key)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verify 校验签名并返回原始 payload。
func (k *stateKeeper) verify(value string) ([]byte, error) {
	head, sig, ok := strings.Cut(value, ".")
	if !ok {
		return nil, errStateBadSig
	}
	payload, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return nil, errStateBadSig
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, errStateBadSig
	}
	mac := hmac.New(sha256.New, k.key)
	mac.Write(payload)
	// hmac.Equal 是定长比较 —— 防止按字节比较的耗时差异被用来逐位试探出合法签名
	if !hmac.Equal(got, mac.Sum(nil)) {
		return nil, errStateBadSig
	}
	return payload, nil
}

func (k *stateKeeper) cookieName(state string) string {
	if len(state) > cookieNameStateLen {
		state = state[:cookieNameStateLen]
	}
	return k.cookiePrefix + state
}

// randomToken 32 字节密码学随机数的 hex 形式。
// hex 而非 base64: 它要进 cookie 名, 而 base64 的 +/= 在那里不安全。
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("生成随机 token 失败: %w", err)
	}
	return hex.EncodeToString(b), nil
}
