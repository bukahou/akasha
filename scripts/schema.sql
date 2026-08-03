-- Akasha schema (真理源, 手动 SQL 纪律 — 不用 migration 工具, 不调 AutoMigrate)
-- 本地: mysql -u bukahou -p 建库后执行; 生产: TiDB Cloud 库 `akasha` (上线时经审批执行)

CREATE DATABASE IF NOT EXISTS akasha DEFAULT CHARACTER SET utf8mb4;
USE akasha;

-- 用户库 = 身份权威
CREATE TABLE IF NOT EXISTS users (
  id             BIGINT AUTO_INCREMENT PRIMARY KEY,
  username       VARCHAR(64)  NOT NULL COMMENT '登录名(密码门的键), 联邦建号时自动生成',
  password       VARCHAR(255) NOT NULL DEFAULT '' COMMENT 'bcrypt; 联邦建号存空串(守卫拦密码登录)',
  email          VARCHAR(255) NULL     COMMENT '可空(上游可能不给); 空时 repository Omit 落 NULL',
  email_verified TINYINT(1)   NOT NULL DEFAULT 0,
  name           VARCHAR(128) NOT NULL DEFAULT '' COMMENT '展示名, 不唯一',
  avatar_url     VARCHAR(500) NOT NULL DEFAULT '',
  status         ENUM('active','banned') NOT NULL DEFAULT 'active',
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_username (username),
  UNIQUE KEY uk_email (email)
) COMMENT '身份权威; 下游应用各自的 users 是业务档案, 以本表 id 为 sub';

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
CREATE TABLE IF NOT EXISTS clients (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  client_id     VARCHAR(64)  NOT NULL COMMENT '如 geass-v3',
  secret_hash   VARCHAR(255) NOT NULL COMMENT 'bcrypt(client_secret)',
  name          VARCHAR(128) NOT NULL COMMENT '展示名(登录页"继续前往 xx")',
  redirect_uris JSON         NOT NULL COMMENT '回调白名单, 精确匹配',
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_client_id (client_id)
) COMMENT '下游应用注册表';

-- 中枢会话 (SSO 的载体; cookie 里是明文 token, 表里存 SHA-256)
CREATE TABLE IF NOT EXISTS sessions (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id    BIGINT       NOT NULL,
  token_hash CHAR(64)     NOT NULL COMMENT 'SHA-256(cookie token)',
  user_agent VARCHAR(500) NOT NULL DEFAULT '',
  ip_address VARCHAR(64)  NOT NULL DEFAULT '',
  expires_at DATETIME     NOT NULL,
  revoked    TINYINT(1)   NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_token_hash (token_hash),
  KEY idx_user (user_id)
) COMMENT '中枢登录态; 吊销=revoked, "登出所有设备"按 user_id 批量';

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
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  token_hash CHAR(64)    NOT NULL,
  user_id    BIGINT      NOT NULL,
  client_id  VARCHAR(64) NOT NULL,
  expires_at DATETIME    NOT NULL,
  revoked    TINYINT(1)  NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_token_hash (token_hash),
  KEY idx_user_client (user_id, client_id)
) COMMENT '30d 滚动刷新';

-- 签名公钥历史 (私钥永不入库; 旧公钥留到旧 token 全过期才 retire)
CREATE TABLE IF NOT EXISTS signing_keys (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  kid        VARCHAR(64)  NOT NULL COMMENT '公钥指纹',
  public_pem TEXT         NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  retired_at DATETIME NULL,
  UNIQUE KEY uk_kid (kid)
) COMMENT 'JWKS 数据源';
