package federation

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
)

// # 联邦往返期间的状态保管
//
// 上游登录是两次【互不相关】的 HTTP 请求, 中间隔着一个 akasha 不控制的第三方:
//
//	① GET /federation/google/start     生成 state/nonce, 跳去 Google
//	┄┄┄ 用户在 Google 那边选账号、输密码、可能过 MFA, 几十秒到几分钟 ┄┄┄
//	② GET /federation/google/callback  Google 把用户送回来
//
// Google 只会原样回传 state 这一个参数, 藏在别处的东西它一概不管。所以 ①
// 生成的三样东西必须自己想办法活到 ②:
//
//	state  防登录 CSRF —— 见下方"为什么必须绑定浏览器"
//	nonce  防上游 id_token 重放 (Google 会把它签进 token, 回来时比对)
//	next   停车的 authorize 断点 (用户原本要去哪)。密码登录靠表单隐藏字段
//	       就能穿过去, 联邦要穿过整个 Google 往返, 只能另想办法
//
// # 为什么是 cookie 而不是数据库表
//
// 这段状态只活 10 分钟, 为它建一张表 + 一处过期清理不划算 (auth_codes 与
// refresh_tokens 的清理都还欠着)。签名 cookie 无状态、K8s 多副本天然友好,
// 也与"akasha 不保留任何登录态"的整体取向一致。
//
// 代价是一次性消费只能"尽力而为": 服务端能做的只是回复一个删除指令, 用户
// 完全可以留一份副本重放。但真实攻击链上打不出伤害 —— 重放一个用过的 state,
// 对应的 Google code 早被 Google 消费掉了, 换不出任何东西。
//
// # 为什么必须绑定浏览器 (这条决定了不能用无状态签名 state)
//
// 登录 CSRF 的攻击形态是【反的】—— 不是攻击者登录成你, 而是把你塞进他的账号:
//
//	① 攻击者用自己的 Google 账号走完授权, 拿到回调 URL 但【不访问】
//	② 诱导受害者点击该 URL
//	③ akasha 用攻击者的 code 换到攻击者身份, 却在【受害者浏览器】里种下会话
//	④ 受害者以为在用自己的账号, 此后上传的内容全进了攻击者账号
//
// 挡它的关键是: 光验"这个 state 是我发过的"没有用 —— 攻击者的 state 也是
// akasha 发的、签名也是合法的。必须验"这个 state 是【这个浏览器】发起时拿到的"。
// 而"只有发起者的浏览器才有"的东西, 只能是 cookie。
//
// 推论: 任何不依赖浏览器侧存储的方案 (例如把 nonce/next 编进签名 JWT 当 state)
// 都无法区分"我自己发起的流程"和"别人发起、诱导我完成的流程" —— 无状态与
// CSRF 防护本质上不兼容。

const (
	// cookiePrefix 后面拼 state 前缀构成完整 cookie 名。
	// 每个流程一个独立 cookie: 用户同时在两个标签页登录不同应用时,
	// 固定名字会互相覆盖, 先发起的那个回调时就找不到自己的状态了。
	cookiePrefix = "akasha_fed_"
	// cookieNameStateLen state 取前几位进 cookie 名 (hex 字符, 可安全用于 cookie 名)。
	cookieNameStateLen = 8
	// cookiePath 限定作用域: 只有联邦端点会带上它, 不污染其他请求。
	cookiePath = "/federation/"
)

var (
	errStateMissing  = errors.New("联邦状态 cookie 缺失或已过期")
	errStateBadSig   = errors.New("联邦状态签名校验失败")
	errStateMismatch = errors.New("state 与 cookie 不匹配")
	errStateExpired  = errors.New("联邦流程已超时, 请重新登录")
)

// flowState 一次联邦往返期间要跨请求保管的全部内容。
// ⚠️ 这个结构会被签名后放进用户浏览器的 cookie —— 签名保证【不可篡改】,
// 但内容对用户【可读】。永远不要往里放秘密 (内部 id、token、凭证)。
// 当前三个字段对用户自己都不是秘密: state/nonce 是随机串, 其价值在于
// "只有你有"而非"没人知道内容"; next 就是用户自己刚发起的那个请求。
type flowState struct {
	State string `json:"s"`
	Nonce string `json:"n"`
	Next  string `json:"x"`
	Exp   int64  `json:"e"`
}

// StateKeeper 用签名 cookie 保管联邦往返状态。
type StateKeeper struct {
	key          []byte
	ttl          time.Duration
	cookieSecure bool
}

// NewStateKeeper 构造保管器。
//
// key 由 pairwise salt 经 HKDF 派生而非直接复用 —— 同一密钥服务于两个不同的
// 密码学用途时, 对一方的分析可能削弱另一方。派生后两者数学上独立, 且 HKDF
// 单向: 即便 cookie 密钥泄漏也反推不回 salt (那个丢了全部下游关联永久失效)。
// 派生不新增配置项, 零运维成本。
func NewStateKeeper(pairwiseSalt string, ttl time.Duration, cookieSecure bool) (*StateKeeper, error) {
	key := make([]byte, 32)
	// info 串把用途写死: 将来若需要第三种用途, 换 info 即可再派生一把独立密钥
	kdf := hkdf.New(sha256.New, []byte(pairwiseSalt), nil, []byte("akasha-federation-cookie-v1"))
	if _, err := kdf.Read(key); err != nil {
		return nil, fmt.Errorf("派生联邦 cookie 密钥失败: %w", err)
	}
	return &StateKeeper{key: key, ttl: ttl, cookieSecure: cookieSecure}, nil
}

// Begin 生成 state/nonce 并写入签名 cookie, 供 start 端点调用。
func (k *StateKeeper) Begin(w http.ResponseWriter, next string) (state, nonce string, err error) {
	if state, err = randomToken(); err != nil {
		return "", "", err
	}
	if nonce, err = randomToken(); err != nil {
		return "", "", err
	}

	payload, err := json.Marshal(flowState{
		State: state,
		Nonce: nonce,
		Next:  next,
		Exp:   time.Now().Add(k.ttl).Unix(),
	})
	if err != nil {
		return "", "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName(state),
		Value:    k.sign(payload),
		Path:     cookiePath,
		MaxAge:   int(k.ttl.Seconds()),
		HttpOnly: true,
		Secure:   k.cookieSecure,
		// Lax: 从 Google 跳回来是【跨站顶级导航 GET】, Lax 会放行。
		// Strict 会把这类跳转的 cookie 掐掉, 联邦登录直接失效。
		SameSite: http.SameSiteLaxMode,
	})
	return state, nonce, nil
}

// Finish 校验回调带回的 state 并取出保管的内容, 随后清除 cookie。
// 供 callback 端点调用; 无论成功与否都应视为该流程已结束。
func (k *StateKeeper) Finish(w http.ResponseWriter, r *http.Request, state string) (*flowState, error) {
	if state == "" {
		return nil, errStateMissing
	}
	c, err := r.Cookie(cookieName(state))
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

// clear 让浏览器立即丢弃该流程的 cookie。
// 属性必须与写入时一致 (Path/Secure/SameSite), 否则浏览器会认作另一个 cookie 而删不掉。
func (k *StateKeeper) clear(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName(state), Value: "", Path: cookiePath, MaxAge: -1,
		HttpOnly: true, Secure: k.cookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

// sign 输出 base64(payload).base64(hmac)。
func (k *StateKeeper) sign(payload []byte) string {
	mac := hmac.New(sha256.New, k.key)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verify 校验签名并返回原始 payload。
func (k *StateKeeper) verify(value string) ([]byte, error) {
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

func cookieName(state string) string {
	if len(state) > cookieNameStateLen {
		state = state[:cookieNameStateLen]
	}
	return cookiePrefix + state
}

func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
