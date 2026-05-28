-- JTI blacklist for OIDC token revocation.
--
-- Stores the JTI (JWT ID) and expiry timestamp of every explicitly revoked token
-- (i.e. tokens invalidated via POST /auth/logout). Entries are checked on every
-- authenticated request to prevent revoked tokens from being accepted after a
-- server restart.
--
-- Cleanup: entries with exp < unixepoch() are logically expired and can be
-- pruned periodically. The application layer prunes on insert.
CREATE TABLE IF NOT EXISTS jti_blacklist (
    jti  TEXT    PRIMARY KEY NOT NULL,
    exp  INTEGER NOT NULL
);

-- `blacklist_jti` prunes with `DELETE FROM jti_blacklist WHERE exp <= ?` on
-- every logout. Without an index on `exp`, that DELETE degrades into a
-- full-table scan and the per-logout cost grows linearly with the live
-- blacklist size; index `exp` so the TTL sweep stays bounded.
CREATE INDEX IF NOT EXISTS idx_jti_blacklist_exp
    ON jti_blacklist(exp);
