-- Relying parties (ADR-005 §2, ADR-008): the sites that may ask this server
-- to sign people in. A confidential client has a secret, of which only the
-- SHA3-256 hash is stored (the secret has 256 random bits); a public client
-- has none. `redirect_uris` is a JSON array, compared exactly.
CREATE TABLE clients (
    client_id     TEXT    NOT NULL PRIMARY KEY,
    name          TEXT    NOT NULL,
    redirect_uris TEXT    NOT NULL,
    secret_hash   TEXT,
    created_at    INTEGER NOT NULL
);

-- The identity an account presents to a client, remembered from one sign-in
-- to the next. Changing it changes who the client sees: each identity has
-- its own identifier there.
CREATE TABLE client_identities (
    account_id  TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   TEXT    NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    identity_id TEXT    NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (account_id, client_id)
);
