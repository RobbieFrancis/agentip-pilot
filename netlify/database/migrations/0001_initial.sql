CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL UNIQUE,
  recovery_key TEXT NOT NULL UNIQUE,
  profile TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  last_used_at BIGINT,
  revoked_at BIGINT
);
CREATE TABLE challenges (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  payload TEXT NOT NULL,
  signer_key TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  used_by TEXT
);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  a TEXT NOT NULL,
  b TEXT NOT NULL,
  scope TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  completed_at BIGINT
);
CREATE TABLE confirmations (
  session_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  key_fingerprint TEXT NOT NULL,
  at BIGINT NOT NULL,
  PRIMARY KEY (session_id, agent_id)
);
CREATE TABLE events (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  action TEXT NOT NULL,
  at BIGINT NOT NULL
);
CREATE TABLE rate_limits (
  bucket TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  expires_at BIGINT NOT NULL
);
CREATE INDEX challenges_expiry ON challenges(expires_at);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE INDEX events_time ON events(at);
CREATE INDEX rate_limits_expiry ON rate_limits(expires_at);
