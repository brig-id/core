# Backups, limits, and several nodes

What every server edition (seedling, grove, forest) offers on its command line for these,
and what an administrator sets from the interface. `<server>` is the edition's executable:
`seedling`, `grove`, `forest`. The commands read the database like a normal run (`--config`,
`BRIGID_DATABASE__PATH`, or `BRIGID_DATABASE__URL_FILE` for PostgreSQL). Typed as root on a
SQLite database, they become the owner of the database's directory first, so that no file
of the database belongs to root.

`backup` and `restore` are for a database that is a SQLite file (seedling, grove). On
PostgreSQL they refuse and say so: the database has its own tools. What an edition made of
several nodes adds is in [Several nodes](#several-nodes-on-one-database).

## Backup

```sh
<server> backup /somewhere/brigid-2026-11-25.db
```

- Writes a consistent copy of the database while the server runs (SQLite's `VACUUM INTO`:
  one read transaction; a write of the server waits for the copy, a few milliseconds for a
  small database). The copy is checked (`PRAGMA quick_check`) before it is kept.
- The file is created with mode 0600 and never written over: name a new one each time.
- Prints the path written on standard output, messages on standard error. Exit status 2
  when refused.
- Needs no master key. The copy is encrypted under the server's master key, as the
  database is: without the key it is unreadable, and with the key anyone who holds it has
  the server. Keep the key, apart from the backups.

A backup moves a server between seedling and grove: both run the same SQLite file. Take a
backup on one, restore it on the other, under the same domain and with the same master
key.

## Restore

```sh
<server> restore /somewhere/brigid-2026-11-25.db
```

Stop the server first. The command refuses, and changes nothing:

- while the server, or another command, uses the database. A server and every command of
  this version hold a lock next to the database (`<database>.lock`, `flock`) while they
  run; `restore` takes it alone. A process that has the database open in WAL mode (an
  older server, Litestream, `sqlite3`) is seen by the write-ahead log that stays after
  `restore` closes the database. **The limit:** a process of a version before this one,
  with the database in rollback-journal mode (seedling's) and between two transactions,
  holds nothing that can be seen. Stop the server before a restore; with grove, stop
  Litestream too;
- when the file is not the database of a brig·id server, or its schema has a step this
  version does not know (a backup made by a newer version). An earlier schema is accepted:
  the next start migrates it;
- when the master key does not open it (its VSID secret and every account's name);
- when its accounts were created on another domain than this server's (`server.public_url`,
  else `server.domain`). A passkey works only on the domain that created it. Each account
  records the domain it was created on; a backup with no account says nothing of its domain,
  and is accepted.

Then it keeps the database it replaces as `<database>.before-restore-<time>` (UTC, e.g.
`brigid.db.before-restore-20261125T031500Z`), prints that path on standard output, and puts
the backup in place in one rename, with the owner and the permissions the database had.
Start the server again.

What a restore brings back is the server at the moment of the backup: accounts, passkeys,
identities, the identifier (VSID) each identity has at each application, the signing keys.
Passkeys added and accounts created since are not in it. Sessions in the backup are as they
were: those that have ended stay ended.

## Limits

What one account, or one address, can create. Each limit has a default and a maximum set
in the code; an administrator sets a value from 1 to the maximum.

| Limit | Default | Maximum | Counts |
| --- | --- | --- | --- |
| `identities_per_account` | 20 | 200 | The identities of one account |
| `passkeys_per_account` | 10 | 50 | The passkeys of one account. A passkey enrolled with the recovery code is always accepted: it is how a person gets back in |
| `sign_ups_per_ip_per_day` | 5 | 1000 | The accounts created from one client address in a day (UTC), whatever the sign-up policy, a setup link or an invitation included |

- A change applies at once, on a running server too: every request reads the value. No
  restart. `<server> limits set` works with the server stopped or running.
- An account above a lowered limit keeps what it has, and adds nothing until it is below it.
- A test suite that creates many accounts from one address (127.0.0.1) raises the daily
  count first: `<server> limits set sign_ups_per_ip_per_day 1000`.
- The client address is the one the rate limits use: the TCP peer, or the first address of
  `X-Forwarded-For` when `security.trust_forwarded_for` is set. An IPv6 address counts as
  itself, not by its prefix.
- No address is stored. A sign-up is counted under a keyed hash of the day and the address
  (the key is derived from the master key), so the same address gives another key the next
  day; the counts of earlier days are deleted at the next sign-up. A rotation of the master
  key starts the day's counts afresh.

From the machine:

```sh
<server> limits                              # name<TAB>value<TAB>default<TAB>max, one per line
<server> limits set identities_per_account 30
```

From the interface, an administrator's session (a change also needs a passkey ceremony at
most five minutes old, and is written to the log of administrative actions as `limit.set`):

```text
GET /admin/limits
→ 200 {"limits":[{"name":"identities_per_account","value":20,"default":20,"max":200},
                 {"name":"passkeys_per_account","value":10,"default":10,"max":50},
                 {"name":"sign_ups_per_ip_per_day","value":5,"default":5,"max":1000}]}

PUT /admin/limits  {"identities_per_account":30}      (any of them)
→ 200, the same as GET
→ 400 {"error":"invalid_limit","code":"invalid_limit","limit":"…","max":200,"message":"…"}
      for an unknown name (no "max") or a value that is not a whole number from 1 to the
      maximum. Nothing is set then.
```

A creation refused by a limit answers, with the error the interface already reads:

```text
409 {"error":"this server allows at most 20 identities per account",
     "code":"limit_reached","limit":"identities_per_account","value":20}
```

`409` for `identities_per_account` (`POST /account/identities`) and `passkeys_per_account`
(`POST /auth/passkeys/add/begin`, checked again at `…/finish`); `429` for
`sign_ups_per_ip_per_day` (`POST /auth/register/begin`, counted at `…/finish`).

## Several nodes on one database

An edition made of several nodes (forest; `brigid_server::run_node`, spec `forest.md`)
serves one PostgreSQL database from processes that stand in for one another. Its settings,
besides those of every edition:

| Setting | Meaning |
| --- | --- |
| `database.url_file` (`BRIGID_DATABASE__URL_FILE`) | A file holding the address of the database, `postgres://role:password@host/database`. `database.url` gives it directly |
| `database.allow_unverified` | Accept an address whose `sslmode` does not verify the database's certificate. Without it only `verify-full` (the default when the address names none) and `verify-ca` are accepted; `sslrootcert=<file>` names an authority of your own |
| `database.max_connections` | The most connections one process opens (default 10) |
| `server.shutdown_delay_seconds` | How long a node told to stop keeps answering, not ready, before it closes (default 5) |

### `init`

```sh
<server> init [--grant <role>] [--logged-pending]
```

Run once before the nodes start, and before each update, as a database role that owns the
schema. It takes a lock (a second `init` waits), creates or updates the schema and the two
tables of what the nodes share, creates the secret of the identifiers and the first signing
key if they are missing, and records which nodes may serve on the schema. On a server with
no administrator it prints the setup link on standard output. A second run changes nothing.

- `--grant <role>`: the role the nodes connect as may read and write rows, and nothing
  else. Nodes never change the schema.
- `--logged-pending`: `pending` is an ordinary table instead of an unlogged one, for a
  PostgreSQL service without unlogged tables.

**A node creates nothing.** Started before `init`, it waits a minute for it, saying what is
missing, then ends. While it runs, `GET /ready` answers 503 with the reason when the schema
is not one its version serves on, when the database does not answer, and from the moment
the process is told to stop.

### Updates

`init` of the new version first, then the nodes one by one. A schema step must leave the
nodes of the release before working; when one cannot, `SERVES_NODES_FROM`
(`brigid-store/src/nodes.rs`) is raised with it, older nodes stop being ready as soon as
`init` has run, and the release's notes say that the update interrupts.

### Signing keys

`<server> rotate-oidc-key` needs no restart: every node reads the keys again every minute,
publishes the new one at once, and signs with it five minutes after its creation. Keys past
their grace period are removed by the nodes.

### The master key

`rotate-key` re-encrypts every row in one transaction: stop every node first. A node that
ran meanwhile wrote under the old key.

### `import`

```sh
<server> import /somewhere/backup.db [--any-domain]
```

Copies a backup of a seedling or a grove (the file its `backup` wrote) into this server's
database: accounts, passkeys, identities, sites, settings, sessions, the secret of the
identifiers and the signing keys. After `init`, on a server that has no account, under the
**same master key** and the **same domain** as the server the backup comes from.

- Rows are copied as they are, in one transaction: nothing is decrypted, and an import that
  fails changes nothing. What `init` had created (a secret, a key) is replaced by the
  backup's: no account existed, so nothing had been given out under them.
- Identifiers that sites hold, tokens and passkeys stay valid. Sign-ins in progress on the
  old server start again.
- A backup made by an earlier version is brought to this version's schema on a private
  copy in the temporary directory; the file itself is never written.
- A backup whose accounts were created on another domain is refused (passkeys are bound to
  the domain) unless `--any-domain`.
- The certificate a single node obtained for itself (ACME) is not copied.

Then stop the old server: two servers must not answer for one domain. To change the master
key, rotate it after the import.
