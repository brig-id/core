-- Administration: the role, suspension, the links that create accounts or
-- grant the role, the sign-up policy, and the log of administrative actions
-- (model.md §7).

-- The role is on the account, never on an identity.
ALTER TABLE users ADD COLUMN admin BIGINT NOT NULL DEFAULT 0;
-- Unix seconds since when the account is suspended; NULL when it is not. A
-- suspended account opens no session and signs in to nothing; nothing of it
-- is deleted.
ALTER TABLE users ADD COLUMN suspended_at BIGINT;
-- Unix seconds of the last passkey ceremony that opened a session. Shown to
-- administrators; says nothing of where the account's identities are used.
ALTER TABLE users ADD COLUMN last_sign_in_at BIGINT;

-- Unix seconds of the latest passkey ceremony done in a session: the one
-- that opened it, or one done since to confirm an administrative change.
ALTER TABLE sessions ADD COLUMN confirmed_at BIGINT;

-- Links handed out by the server. The link holds 128 random bits; only
-- their SHA3-256 hash is here.
--   setup       creates the first account, as administrator (one use)
--   admin       grants the role to the signed-in account that opens it (one use)
--   invitation  creates ordinary accounts, as many as `uses_left`
-- `created_by` is the account of the administrator who made it, NULL for a
-- link made on the machine. It is not a foreign key: a link outlives the
-- account that made it, and names nobody once that account is gone.
CREATE TABLE links (
    id         TEXT    NOT NULL PRIMARY KEY,
    token_hash TEXT    NOT NULL UNIQUE,
    kind       TEXT    NOT NULL,
    uses_left  BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    created_by TEXT
);

-- What an administrator set for this server. One row so far: `signup`
-- (`open`, `invitation` or `closed`). Not secrets.
CREATE TABLE settings (
    name  TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);

-- The log of administrative actions. `entry` is a JSON object: the action,
-- the account that did it and the account or application it was done to.
-- Accounts are named by their identifier, never by a name: the entry of a
-- deleted account names nobody. Entries older than the retention period are
-- deleted by the server.
CREATE TABLE admin_log (
    id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at    BIGINT NOT NULL,
    entry BYTEA    NOT NULL                 -- encrypted
);
CREATE INDEX idx_admin_log_at ON admin_log(at);
