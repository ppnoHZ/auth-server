-- OAuth2 Authorization Server DDL (MySQL)
-- 请先手动建库并选择数据库:
--   CREATE DATABASE IF NOT EXISTS oauth2_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
--   USE oauth2_db;

-- 1. 用户表
CREATE TABLE users (
    id VARCHAR(36) NOT NULL,
    username VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    is_active BOOL DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE INDEX ix_users_username (username),
    UNIQUE INDEX ix_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. OAuth 客户端表
CREATE TABLE oauth_clients (
    id VARCHAR(36) NOT NULL,
    client_id VARCHAR(48) NOT NULL,
    client_secret_hash VARCHAR(255) NOT NULL,
    client_name VARCHAR(120) NOT NULL,
    redirect_uris TEXT NOT NULL,
    grant_types TEXT NOT NULL,
    scopes VARCHAR(500) DEFAULT '',
    owner_id VARCHAR(36) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE INDEX ix_oauth_clients_client_id (client_id),
    CONSTRAINT fk_oauth_clients_owner FOREIGN KEY (owner_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. 授权码表
CREATE TABLE authorization_codes (
    id VARCHAR(36) NOT NULL,
    code VARCHAR(48) NOT NULL,
    client_id VARCHAR(48) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    redirect_uri VARCHAR(500) NOT NULL,
    scope VARCHAR(500) DEFAULT '',
    code_challenge VARCHAR(128) DEFAULT NULL,
    code_challenge_method VARCHAR(10) DEFAULT NULL,
    state VARCHAR(128) DEFAULT NULL,
    expires_at DATETIME NOT NULL,
    used BOOL DEFAULT FALSE,
    PRIMARY KEY (id),
    UNIQUE INDEX ix_authorization_codes_code (code),
    INDEX ix_authorization_codes_client_id (client_id),
    CONSTRAINT fk_authorization_codes_user FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Token 表
CREATE TABLE oauth_tokens (
    id VARCHAR(36) NOT NULL,
    access_token VARCHAR(500) NOT NULL,
    refresh_token VARCHAR(48) DEFAULT NULL,
    token_type VARCHAR(20) DEFAULT 'bearer',
    client_id VARCHAR(48) NOT NULL,
    user_id VARCHAR(36) DEFAULT NULL,
    scope VARCHAR(500) DEFAULT '',
    expires_at DATETIME NOT NULL,
    refresh_token_expires_at DATETIME DEFAULT NULL,
    revoked BOOL DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX ix_oauth_tokens_access_token (access_token),
    UNIQUE INDEX ix_oauth_tokens_refresh_token (refresh_token),
    INDEX ix_oauth_tokens_client_id (client_id),
    CONSTRAINT fk_oauth_tokens_user FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
