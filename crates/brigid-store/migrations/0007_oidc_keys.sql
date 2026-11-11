-- OIDC token-signing keys (core#22). The current key has `retired_at` NULL;
-- retired keys keep verifying tokens until pruned after their grace period.
-- `seed` (the Ed25519 private seed) is encrypted with a key derived from the
-- master key; `kid` is public (it is in every token header and the JWKS).
CREATE TABLE IF NOT EXISTS oidc_keys (
    kid        TEXT NOT NULL PRIMARY KEY,
    seed       BLOB NOT NULL,
    created_at TEXT NOT NULL,
    retired_at TEXT
);
