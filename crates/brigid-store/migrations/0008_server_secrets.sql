-- Secrets of the server itself, as opposed to an account's. `value` is
-- encrypted with a key derived from the master key and re-encrypted when the
-- master key is rotated. One row so far: `vsid`, the keying material of every
-- VSID (ADR-006 in the spec).
CREATE TABLE IF NOT EXISTS server_secrets (
    name  TEXT NOT NULL PRIMARY KEY,
    value BLOB NOT NULL
);
