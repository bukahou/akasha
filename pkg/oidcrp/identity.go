package oidcrp

// Identity 是本包对外吐出的【唯一】东西: 一个经过验签的上游身份断言。
//
// 字段刻意少。多一个字段就是多一份"调用方可能拿它当身份键"的风险 ——
// 而身份键只有一个, 就是 Subject。
type Identity struct {
	// Subject ⭐ 唯一的身份键。provider 保证它在该 provider 内唯一且永不重分配。
	//
	// ⚠️ 若上游是 pairwise 类型 (akasha 就是), 这个值【只对本应用有效】——
	// 同一个人在别的应用拿到的是完全不同的 Subject。所以它:
	//   - 可以写进本应用的 identities 表
	//   - 绝不可外传, 也绝不可拿去跟其他应用的标识比对 (比不出任何东西)
	Subject string

	// Email 上游说这个人的邮箱是这个。
	//
	// ⚠️ 它是【上游的说法】, 不是本应用验证过的联系方式。绝不可用于:
	// 密码找回、身份验证、按邮箱匹配已有账号 —— 那等于把安全责任委托给上游,
	// 只要任何一个上游的邮箱验证有漏洞, 本应用的账号体系就被打穿。
	// 只能用于展示与发信。
	Email string

	// EmailVerified 上游是否验证过该邮箱。同样是上游的说法, 判断依据同上。
	EmailVerified bool

	// Name 展示名 (scope=profile)。建号时可作昵称素材。
	Name string

	// PreferredUsername 上游建议的用户名 (scope=profile)。仅供参考 ——
	// 本应用的用户名唯一性由本应用自己保证, 冲突时自行加后缀。
	PreferredUsername string

	// Picture 头像 URL (scope=profile)。
	Picture string
}

// Result 交给 OnAuthenticated 的完整上下文。
//
// 用结构体而非并列参数: 将来加字段 (比如 auth_time、acr) 不必改所有调用方的签名。
type Result struct {
	// Identity 已验签的上游身份。
	Identity Identity

	// Next 发起登录时传入的、原样带回的应用内目标路径。
	//
	// 它已经过 SafeNext 校验 (在 Start 那一刻就验了, 不是这里才验) ——
	// 但调用方若要再验一次, 也不算多余: 开放重定向是那种"多验一次没坏处"的东西。
	Next string
}
