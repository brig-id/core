-- Limits for a server open to others (grove#7): what one account, or one
-- client address, can create. The values an administrator set are settings
-- (`limit.identities_per_account`, `limit.passkeys_per_account`,
-- `limit.sign_ups_per_ip_per_day`); a limit without a row has its default.

-- How many accounts were created from one client address on one day (UTC).
-- The address is never stored: `key` is a keyed hash, under a key derived
-- from the master key, of the day and the address, so the same address gives
-- another key the next day. Rows of earlier days are deleted at the next
-- sign-up.
CREATE TABLE sign_up_counts (
    key   TEXT    NOT NULL PRIMARY KEY,
    day   BIGINT NOT NULL,              -- days since 1970-01-01, UTC
    count BIGINT NOT NULL
);
CREATE INDEX idx_sign_up_counts_day ON sign_up_counts(day);
