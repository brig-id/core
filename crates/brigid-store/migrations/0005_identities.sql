-- An identity is what a relying party sees; it belongs to one (private) account.
-- `name`, `did` and `description` are encrypted with the account's key, like the
-- account's own fields. `logo` is a public reference into the icon library.
CREATE TABLE IF NOT EXISTS identities (
    id          TEXT NOT NULL PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    did         BLOB NOT NULL,
    name        BLOB NOT NULL,
    logo        TEXT NOT NULL,
    description BLOB,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- Identities are listed by account on every account page.
CREATE INDEX IF NOT EXISTS idx_identities_account_id ON identities(account_id);
