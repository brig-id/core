-- Account sessions (ADR-005 §1). The browser holds a 256-bit random token in
-- an HttpOnly cookie; the server keeps only its SHA3-256 hash. A session ends
-- at `idle_expires_at` (pushed back by each use, never past `expires_at`) or
-- at `expires_at` (fixed when the passkey ceremony opened it). Times are Unix
-- seconds. The earlier `sessions` table was never used.
DROP TABLE IF EXISTS sessions;
CREATE TABLE sessions (
    token_hash      TEXT    NOT NULL PRIMARY KEY,
    account_id      TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      INTEGER NOT NULL,
    idle_expires_at INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_account_id ON sessions(account_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- Bearer session tokens are gone, and with them their revocation list.
DROP TABLE IF EXISTS jti_blacklist;
