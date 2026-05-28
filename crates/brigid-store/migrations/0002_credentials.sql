CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id      TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data    BLOB NOT NULL
);

-- SQLite does not auto-index foreign-key columns. `fetch_credentials` reads
-- this table by `user_id` on every login, so without this index that lookup
-- degrades into a full-table scan as the deployment grows.
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id
    ON webauthn_credentials(user_id);
