# Akasha

自研 **OpenID Connect Provider**（第一方身份联邦中枢），用 Go 实现。

为一组自有应用提供第三方登录聚合与 SSO：对下游应用扮演 IdP，对上游（Google 等）扮演联邦 broker。

> 名字取自「阿卡夏记录」——记载一切存在的档案。

## 为什么造这个

多个应用各接一遍 Google、各维护一套 OAuth 回调，是重复劳动也是风险面。
把上游联邦收敛到一个中枢后：应用只实现一次标准 OIDC RP，
新增登录方式（GitHub / Passkey / MFA）全在中枢完成，应用零改动。

同时这是一个**训练项目**：亲手实现 OIDC 协议的两侧（Provider 与 Relying Party），
而不是部署一个 Keycloak 了事。

### 边界：它是增强，不是唯一入口

akasha **不做本地密码认证**——没有注册页，没有找回密码，认证入口只有上游联邦。
接入的应用保留各自完整的本地账号体系，akasha 是它们登录页上的一个额外按钮。

因此 akasha 的用户表只承担一个职责：**跨应用的统一身份编号**。
同一个上游账号在所有应用里映射到同一个 `sub`，换上游 provider 时身份也不断。

## 状态

**核心协议链路已跑通并验证**，尚未上线。

| 里程碑 | 内容 | 状态 |
|---|---|---|
| M1 | discovery / JWKS / authorize / token | ✅ 代码完成 |
| M1.5 | 运行时验收（完整授权码流程 + 外部验签） | ✅ 通过 |
| M2 | Google 上游联邦 / userinfo / 移除临时密码登录 | 计划中 |
| M3 | 安全加固 + 部署上线 | 计划中 |
| M4 | GitHub provider / 更多应用接入 | 计划中 |

> 当前的密码登录是 M1 阶段的**临时验收入口**，M2 联邦可用后移除。

⚠️ **尚未做安全加固**（CSRF token、速率限制、安全响应头等），请勿直接用于生产。

## 设计要点

- **RS256 非对称签名**：中枢独占私钥签发，下游经 `/jwks` 取公钥各自验签——任一应用被攻破也伪造不出 token
- **强制 PKCE**：即使是机密客户端也要求 `S256`，防前信道授权码截获
- **授权码原子消费**：`UPDATE ... WHERE consumed = 0` 靠受影响行数判定，并发双兑无解
- **回调白名单精确匹配**：不做前缀或通配，堵死开放重定向
- **不透明凭证只存哈希**：会话 token / 授权码 / refresh token 入库前一律 SHA-256
- **零凭证入库**：私钥只存挂载文件，配置全走环境变量

## 架构

```
internal/
├── op/          OIDC 协议核心 (authorize / token / discovery / jwks)
├── keys/        RS256 密钥管理 + JWKS 发布 + 轮换
├── client/      RP 注册表 (谁有资格请求身份)
├── session/     中枢会话 — SSO 的载体
├── account/     用户库 = 身份权威 (联邦认亲 / 自动建号 / 统一身份编号)
├── login/       托管登录页 (服务端渲染, 无前端框架)
├── federation/  上游 broker (provider 抽象 + 各上游实现)   ← M2
├── config/      环境变量配置
└── server/      HTTP 生命周期
```

依赖方向单向：`op → keys/client/session/account`，`login → session/account/federation`，
`federation → account`，`account` 不依赖任何人。

`op` 与 `federation` 是同一套 OIDC 概念的镜像两侧：前者发授权码给下游（当 Provider），
后者拿授权码找上游换（当 Relying Party），中间同为 `account` 裁决身份。

### 一次登录的流程

```
应用 → 302 /authorize → 无会话则 302 /login → 验证身份 → 种中枢会话 cookie
    → 302 回 /authorize → 签发一次性授权码 → 302 回应用
应用后端 → POST /token (授权码 + PKCE verifier + client 凭证) → id_token / access_token / refresh_token
```

关键在于**前信道**（浏览器跳转，只传一次性授权码）与**后信道**（服务器直连，传凭证与令牌）的分离：
秘密永不踏上浏览器可见的路径。

## 快速开始

需要 Go 1.24+ 与 MySQL 8+。

```bash
# 1. 建库
mysql -u root -p < scripts/schema.sql

# 2. 生成签名密钥
./scripts/genkey.sh ./signing-key.pem

# 3. 配置
cp .env.example .env && vim .env        # 至少填 AKASHA_DB_DSN
set -a && source .env && set +a

# 4. 注册一个下游应用 (client_secret 需 bcrypt 哈希)
go run ./scripts/bcryptgen "your-client-secret"
# 把输出的哈希连同 client_id / redirect_uris 插入 clients 表

# 5. 运行
go run ./cmd/akasha
curl -s localhost:9100/.well-known/openid-configuration | jq
```

## 端点

| 端点 | 说明 |
|---|---|
| `GET /.well-known/openid-configuration` | 发现文档 |
| `GET /jwks` | 公钥集（下游验签用） |
| `GET /authorize` | 授权入口（code + PKCE） |
| `POST /token` | 令牌端点（`authorization_code` / `refresh_token`） |
| `GET/POST /login`、`POST /logout` | 托管登录页 |
| `GET /health` | 存活探针 |

## 技术选型

标准库 `net/http` + `html/template`；GORM（MySQL）；`golang-jwt/v5`；`caarlos0/env`；`log/slog`。
散件组合，不用框架全家桶。Schema 手工管理（`scripts/schema.sql` 是唯一真理源，不调用 `AutoMigrate`）。

## License

MIT
