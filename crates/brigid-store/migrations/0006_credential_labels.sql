-- A human-readable name for a passkey ("Pixel 9", "YubiKey"), set by the user at
-- registration or later. Encrypted with the account's key; NULL when unnamed.
ALTER TABLE webauthn_credentials ADD COLUMN label BLOB;
