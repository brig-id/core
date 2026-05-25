CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id      TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data    BLOB NOT NULL
);
