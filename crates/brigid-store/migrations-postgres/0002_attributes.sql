-- Attributes: what an identity shares, what an application may ask for, and
-- what a person accepted (model.md §3 to §5).

-- The attributes of an identity: one JSON object, claim name to value
-- (`{"given_name": "Ada", "email": "ada@example.org"}`). NULL when it has
-- none. One value for all of them, so that a copy of the database does not
-- even tell which ones an identity has.
ALTER TABLE identities ADD COLUMN attributes BYTEA;  -- encrypted

-- What an application may ask for: a JSON object, claim name to `required`
-- or `optional`. Not a secret: the linking page shows it to whoever is sent
-- there.
ALTER TABLE clients ADD COLUMN attributes TEXT NOT NULL DEFAULT '{}';

-- What an identity gave an application: one row from its first sign-in
-- there, whether or not anything was asked. `decisions` is a JSON object,
-- claim name to what the person decided: the value they accepted to share
-- and when, or that they refused. Withdrawing removes the row, or one
-- decision of it.
CREATE TABLE grants (
    identity_id  TEXT    NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    client_id    TEXT    NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    decisions    BYTEA    NOT NULL,                  -- encrypted
    created_at   BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    PRIMARY KEY (identity_id, client_id)
);
-- Removed with their application.
CREATE INDEX idx_grants_client_id ON grants(client_id);
