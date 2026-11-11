-- ADR-007: accounts and identities are identified by their UUID. Their DIDs
-- were never resolvable and are no longer an input of anything (VSIDs come
-- from the identity UUID). Only the server keeps a DID, built at runtime.
ALTER TABLE users DROP COLUMN did_web;
ALTER TABLE identities DROP COLUMN did;
