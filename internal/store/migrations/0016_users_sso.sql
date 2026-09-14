-- 飞书 SSO 与多用户支持：用户、Web 会话、按用户授权主机、SSO 中间状态。
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '',
  avatar_url TEXT NOT NULL DEFAULT '',
  feishu_open_id TEXT UNIQUE,
  feishu_union_id TEXT,
  role TEXT NOT NULL CHECK(role IN ('admin','member')),
  status TEXT NOT NULL CHECK(status IN ('active','disabled')),
  source TEXT NOT NULL CHECK(source IN ('local','feishu')),
  created_at INTEGER NOT NULL,
  last_login_at INTEGER
);

-- Web 会话：cookie 里只放随机值，库内存其 SHA-256，禁用用户即时生效。
CREATE TABLE IF NOT EXISTS web_sessions (
  id_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_web_sessions_user ON web_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_web_sessions_expires ON web_sessions(expires_at);

-- member 角色的主机授权集合，admin 忽略此表。
CREATE TABLE IF NOT EXISTS user_hosts (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, host_id)
);

-- 飞书 OAuth 回调前的 state/PKCE 暂存：单次消费，10 分钟内有效。
CREATE TABLE IF NOT EXISTS sso_states (
  state TEXT PRIMARY KEY,
  code_verifier TEXT NOT NULL,
  return_to TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- 密码登录映射到内置本地管理员；不可禁用或删除，避免飞书配置故障时锁死。
INSERT OR IGNORE INTO users(id,name,role,status,source,created_at)
  VALUES(1,'本地管理员','admin','active','local',strftime('%s','now'));
