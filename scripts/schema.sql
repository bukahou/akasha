-- Akasha schema (真理源, 手动 SQL 纪律 — 不用 migration 工具, 不调 AutoMigrate)
--
-- ※ 【没有 sessions 表】akasha 不保留登录态 (2026-08-16 定案): 每次 authorize
--   都重新走一遍上游认证。放弃 SSO, 换来应用间彻底无关联、用户随时可换上游账号、
--   以及一个无状态的服务。联邦往返期间的临时状态存在签名 cookie 里, 不落库。
-- 本地: mysql -u bukahou -p 建库后执行; 生产: TiDB Cloud 库 `akasha` (上线时经审批执行)

CREATE DATABASE IF NOT EXISTS akasha DEFAULT CHARACTER SET utf8mb4;
USE akasha;

-- 用户库 = 身份权威
--
-- id 是【表内主键, 永不对外暴露】。对下游的身份标识是 pairwise sub,
-- 由 internal_id 现算: HMAC-SHA256(salt, client_id \x00 internal_id)。
-- 曾经直接拿 id 当 sub, 那会在 akasha 重建后 AUTO_INCREMENT 归 1 时【串号】
-- (A 用户登入 B 用户的账号), 且违反 OIDC Core §2 的 never-reassigned 要求。
CREATE TABLE IF NOT EXISTS users (
  id             BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '仅表内主键, 永不对外暴露',
  internal_id    CHAR(64)     NOT NULL COMMENT 'SHA256(provider \\0 upstream_subject); pairwise sub 的输入, 永不外泄',
  username       VARCHAR(64)  NOT NULL COMMENT '展示用登录名, 联邦建号时自动生成',
  -- 【故意没有 password 列】akasha 不做本地密码认证 (2026-08-09 定案),
  -- 认证入口只有上游联邦。各接入应用保留自己的本地账号体系。
  email          VARCHAR(255) NULL     COMMENT '参考信息, 非身份键; 空时 repository Omit 落 NULL',
  email_verified TINYINT(1)   NOT NULL DEFAULT 0,
  name           VARCHAR(128) NOT NULL DEFAULT '' COMMENT '展示名, 不唯一',
  avatar_url     VARCHAR(500) NOT NULL DEFAULT '',
  status         ENUM('active','banned') NOT NULL DEFAULT 'active',
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_username (username),
  UNIQUE KEY uk_internal_id (internal_id),
  KEY idx_email (email)
  -- email 【故意不设唯一索引】: 不认亲定案后, 同一个人的 Google 账号与 GitHub 账号
  -- 是两个独立账号但邮箱相同, 唯一索引会让第二个上游登录时插入失败。
) COMMENT '身份权威; 下游各自的 users 是业务档案, 以本表派生的 pairwise sub 关联';

-- 上游联邦身份 (akasha 当 RP 时的认亲映射)
CREATE TABLE IF NOT EXISTS federated_identities (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id    BIGINT       NOT NULL,
  provider   VARCHAR(32)  NOT NULL COMMENT 'google / 未来 github',
  subject    VARCHAR(255) NOT NULL COMMENT '上游 IdP 侧用户唯一 ID',
  email      VARCHAR(255) NULL     COMMENT '关联时上游给的邮箱(审计)',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_provider_subject (provider, subject),
  KEY idx_user (user_id)
) COMMENT '上游身份 → users 多对一';

-- RP 注册表 (谁有资格找我要身份)
--
-- client_type 决定 /token 是否要求 client_secret:
--   confidential  服务端应用 (geass 后端等), 能安全保管 secret
--   public        移动 App / SPA / CLI —— 反编译或看 JS 源码即得 secret,
--                 全球用户共用一份毫无意义。RFC 8252 的方案是不带 secret,
--                 靠 PKCE 保护 (本服务已对所有客户端强制 PKCE, 安全前提齐备)
CREATE TABLE IF NOT EXISTS clients (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  client_id     VARCHAR(64)  NOT NULL COMMENT '如 geass-v3',
  client_type   ENUM('confidential','public') NOT NULL DEFAULT 'confidential',
  secret_hash   VARCHAR(255) NOT NULL DEFAULT '' COMMENT 'bcrypt(client_secret); public 客户端为空串',
  name          VARCHAR(128) NOT NULL COMMENT '展示名(登录页"继续前往 xx")',
  redirect_uris JSON         NOT NULL COMMENT '回调白名单, 精确匹配(loopback 豁免端口)',
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_client_id (client_id)
) COMMENT '下游应用注册表';

-- 授权码 (一次性提货券, 60s)
CREATE TABLE IF NOT EXISTS auth_codes (
  id             BIGINT AUTO_INCREMENT PRIMARY KEY,
  code_hash      CHAR(64)     NOT NULL COMMENT 'SHA-256(code)',
  client_id      VARCHAR(64)  NOT NULL,
  user_id        BIGINT       NOT NULL,
  redirect_uri   VARCHAR(500) NOT NULL COMMENT '兑换时必须与签发时一致',
  scope          VARCHAR(255) NOT NULL DEFAULT 'openid email profile',
  nonce          VARCHAR(255) NOT NULL DEFAULT '' COMMENT '透传进 id_token 防重放',
  pkce_challenge VARCHAR(128) NOT NULL COMMENT 'S256 challenge, 兑换时验 verifier',
  expires_at     DATETIME     NOT NULL,
  consumed       TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '原子消费, 一次性',
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_code_hash (code_hash)
) COMMENT '事务①的断点快照 (停车场)';

-- refresh token (不透明随机串, 表里存 SHA-256)
--
-- family_id = 签发这条链的原始 auth_code 的 code_hash。
-- 一次 authorize 产生的 code 换出 refresh₁, 滚动出 refresh₂、refresh₃…… 这整条链
-- 共享同一个 family_id。RFC 6819 §5.2.1.1 要求: 检测到重放时【整个家族一起撤销】——
-- 重放本身就是泄漏信号, 只拒绝这一次等于放任攻击者继续用他手上那套新 token。
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  token_hash CHAR(64)    NOT NULL,
  family_id  CHAR(64)    NOT NULL COMMENT '令牌家族 = 原始 auth_code 的 code_hash',
  user_id    BIGINT      NOT NULL,
  client_id  VARCHAR(64) NOT NULL,
  expires_at DATETIME    NOT NULL,
  revoked    TINYINT(1)  NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_token_hash (token_hash),
  KEY idx_family (family_id),
  KEY idx_user_client (user_id, client_id)
) COMMENT '30d 滚动刷新; 按 family 连坐撤销';

-- 签名公钥历史 (私钥永不入库; 旧公钥留到旧 token 全过期才 retire)
CREATE TABLE IF NOT EXISTS signing_keys (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  kid        VARCHAR(64)  NOT NULL COMMENT '公钥指纹',
  public_pem TEXT         NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  retired_at DATETIME NULL,
  UNIQUE KEY uk_kid (kid)
) COMMENT 'JWKS 数据源';
