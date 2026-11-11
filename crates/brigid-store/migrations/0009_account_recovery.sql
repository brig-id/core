-- Account recovery codes (ADR-004). One row per account that ever set a code.
-- `recovery_index` is a keyed hash of the code's recovery id (like
-- `username_index`), recomputed from `recovery_id` when the master key
-- rotates; `recovery_id` and `verifier` are encrypted with the account's key.
-- The secret itself is never stored. Using a code clears the three columns
-- and records `used_at`.
CREATE TABLE IF NOT EXISTS account_recovery (
    user_id        TEXT NOT NULL PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    recovery_index TEXT UNIQUE,
    recovery_id    BLOB,
    verifier       BLOB,
    created_at     TEXT,
    used_at        TEXT
);
