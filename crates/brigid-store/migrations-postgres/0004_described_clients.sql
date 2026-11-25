-- Clients that describe themselves (protocol.md §6): the `client_id` is the
-- HTTPS URL of a document the application publishes. The server keeps the
-- last valid document it read, so that the identities chosen for the client
-- and what people shared with it (foreign keys on `clients`) have a row to
-- point to, and so that a client stays usable while its document cannot be
-- read. `document` is NULL for a client registered on the machine; for a
-- client that describes itself it is a JSON object (`ClientDocument`). Not a
-- secret: everything in it is public.
ALTER TABLE clients ADD COLUMN document TEXT;

-- The operator's lists of clients that describe themselves, by `client_id`:
--   accepted  the only ones accepted under the policy `listed`; their logo
--             is shown
--   refused   never accepted, whatever the policy
-- The policy itself is the setting `clients` (`registered`, `open` or
-- `listed`; `open` when absent).
CREATE TABLE client_lists (
    client_id  TEXT    NOT NULL PRIMARY KEY,
    list       TEXT    NOT NULL CHECK (list IN ('accepted', 'refused')),
    created_at BIGINT NOT NULL
);
