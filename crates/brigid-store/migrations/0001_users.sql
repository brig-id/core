CREATE TABLE IF NOT EXISTS users (
    id         TEXT NOT NULL PRIMARY KEY,
    username   BLOB NOT NULL,
    server     BLOB NOT NULL,
    did_web    BLOB NOT NULL,
    created_at TEXT NOT NULL
);
