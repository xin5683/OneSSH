-- 飞书 v1 authorize 与 v3 token 端点的 PKCE 配对暂未开放（code_verifier 被 v3 以
-- 20049 拒绝），机密客户端按 v3 标准流程用 client_secret + state，sso_states 不再
-- 需要 code_verifier。表内只有 10 分钟内的临时行，直接重建，不做数据搬迁。
DROP TABLE IF EXISTS sso_states;
CREATE TABLE sso_states (
  state TEXT PRIMARY KEY,
  return_to TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
