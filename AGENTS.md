# AGENTS.md — brig·id `core`

This repository contains the **business logic crates** for brig·id,
organized as a Cargo workspace under `crates/`.

## Language

**All content must be in English** — code, comments, doc-comments, commit messages,
issues, pull requests. No exceptions.

## Scope

| Crate | Purpose |
| --- | --- |
| `brigid-store` | Zero-trust storage, on SQLite or PostgreSQL (all data encrypted before INSERT) |
| `brigid-identity` | `RootId` (the account's hidden username), VSID computation, recovery codes, identity labels |
| `brigid-webauthn` | Passkey registration and authentication flows |
| `brigid-oidc` | ID token issuance (EdDSA), PKCE, JWKS, `.well-known/openid-configuration` |
| `brigid-api` | Axum HTTP server — all routes |
| `brigid-server` | What every server edition runs: configuration, operator commands, startup (one node, or one of several), the embedded interface, metrics |
| `brigid-ui-embed` | Build-time helper: embeds the built interface in an edition's executable |

## Roadmap & planning

TODOs, backlog ideas, and phase/release status for this repo are tracked as cards in
[brig-id Project 1](https://github.com/orgs/brig-id/projects/1), not in local files.

## Hard security constraints

- **Zero-trust storage** — every sensitive field must be encrypted via `brigid-crypto`
  before being written to the database. A raw SQL dump must never expose readable secrets.
- **One store, two databases** (spec `forest.md` §3) — every statement of `brigid-store`
  is written once and runs on SQLite and on PostgreSQL. So, in a statement: parameters
  are `$1, $2…`; columns are `TEXT`, `INTEGER` (read as `i64`) or `BLOB`; a truth value is
  `CASE WHEN … THEN 1 ELSE 0 END` read as `i64`, never a boolean; no function only one of
  them has (two-argument `MIN`/`MAX`, `IFNULL`, `unixepoch`…). A new migration goes in
  `migrations/` **and** in `migrations-postgres/`, the second being the first with `BLOB`
  → `BYTEA` and `INTEGER` → `BIGINT`: a test compares them. Tests take their database
  from `brigid_store::testing::url()`, never from a literal address, and run on both:
  `BRIGID_TEST_POSTGRES=postgres://… cargo nextest run --workspace --all-features`.
- **VSID invariants** (enforced in `brigid-identity`):
  - `sub` in OIDC tokens = VSID, never username, alias, or raw DID.
  - VSID must never be derived from an alias.
  - VSID must never be derived from a virtual identity.
  - Same `(did_root, client_id, salt)` → same VSID; different `client_id` → different VSID.
- **No OpenSSL** — use `rustls` everywhere; TLS 1.3 minimum. **Single
  documented exception, until webauthn-rs 0.6:** `webauthn-rs-core` 0.5 uses
  OpenSSL not only for attestation chains but to verify **every passkey
  assertion signature** and for its SHA-256 (`docs/dependencies.md`). Our own
  code adds none: TLS, KEM, DSA, KDF and our signatures stay on rustls /
  RustCrypto. webauthn-rs 0.6 moves to RustCrypto; the upgrade waits for a
  release of `crypto-glue` built on `rsa` 0.10.
- **No secrets in logs** — `tracing` spans must never capture key material, credentials, or tokens.
- **No `unwrap()` on error paths** — typed errors via `thiserror`.
- **WebAuthn** — RP ID must be strict (no wildcard); signature counter must be verified.
- **Administration** — what an administrator can reach stops at the account: no `/admin`
  response holds an identity, a label, an attribute or a grant, and none gives access back
  to an account. The log of administrative actions names accounts by identifier only and
  is deleted after its retention period. Operational log lines carry no account identifier.
- **OIDC** — Authorization Code flow only, PKCE `S256` for every client, EdDSA only; a
  relying party receives a VSID. The labels of an identity (name, logo, description) never
  leave the server. An attribute (`brigid-identity/src/attributes.rs`) reaches a relying
  party only if its registration lets it ask, the request asks, and the person accepted the
  value the identity has now (`standing` in `brigid-api/src/routes/authorize.rs`).
- **What lives minutes** (`brigid-api/src/shared.rs`) — passkey ceremonies in progress,
  pending requests, codes and the assertions of clients already used are kept behind the
  `Shared` trait, with an expiry and a cap, and taken once. `Memory` keeps them in the
  process: enough for one node. `Stored` keeps them in the database (`brigid-store`'s
  `kept.rs`: an unlogged table on PostgreSQL, hashed identifiers, encrypted values), for
  an edition made of several nodes (spec `forest.md` §2–§3). Never keep such state
  anywhere else.
- **Several nodes** (`brigid-server/src/nodes.rs`, `brigid-store/src/nodes.rs`,
  `docs/operations.md`) — an edition made of several nodes calls `run_node`. A node
  **creates nothing**: no schema step, no secret, no key, no setup link (`init` does, under
  a lock). It keeps nothing in memory that another node needs, reads the signing keys again
  every minute and signs with a key only once it was published five minutes
  (`nodes::signing_key`). Whatever a single node does at its start must be asked here: can
  two nodes do it together? A new schema step must leave the nodes of the release before
  working, or raise `SERVES_NODES_FROM` (a test asks at each step). `import` copies rows
  as they are: a new table needs nothing, a column type outside `TEXT`/`INTEGER`/`BLOB`
  is refused.
- **Sites that describe themselves** (`brigid-api/src/described.rs`) — the server fetches
  a document at a URL anyone chooses: keep every rule of the module (https and a domain
  name, the resolver that drops special-use addresses, no redirect, no proxy, 5 KiB, 10 s,
  errors never cached). Such a site has no secret: `private_key_jwt` (EdDSA or ES256, `jti`
  once) or PKCE alone. The linking page shows its host, never only its declared name.
- **CSP header** — `brigid-api` must emit a strict `Content-Security-Policy`
  (`default-src 'self'`, no `unsafe-inline`).
- **Limits** (`brigid_store::Limit`, `docs/operations.md`) — identities and passkeys per
  account, sign-ups per client address and day: a default and a maximum in the code, the
  value in `settings`, set from `/admin/limits` or `<server> limits`. Enforced where the
  row is written (one statement, or the sign-up's transaction), never only before. Sign-ups
  are counted under a keyed hash of the day and the address (`sign_up_counts`): never store
  an address.
- **Backups** (`brigid-server/src/backup.rs`, `docs/operations.md`) — `backup` copies the
  database while the server runs (`VACUUM INTO`); `restore` refuses while anything holds
  `<database>.lock` or keeps the database open in WAL mode, and checks the backup's schema,
  master key and domain before it replaces the database in one rename. Every process that
  opens the database holds that lock shared (`lock.rs`).
- **Rate limiting** — per client IP via `tower-governor`: the WebAuthn ceremonies
  (register, login, add-passkey finish) 20 req/min in bursts of 5; the routes that need a
  session 60 req/min in bursts of 30.

## Architecture quick-reference

```text
POST /auth/register/begin  → WebAuthn CreationChallenge
POST /auth/register/finish → store encrypted credential
POST /auth/login/begin     → WebAuthn RequestChallenge
POST /auth/login/finish    → account session (HttpOnly cookie), no token

POST /account/recovery-code            → the recovery code; until it exists, identities and applications answer 403
POST /account/delete/begin, /finish    → a passkey ceremony of its own, then the account and all about it are gone

GET  /admin/accounts, /admin/applications, /admin/sign-up, /admin/limits, /admin/log → an administrator's session
POST|PUT|DELETE /admin/…               → also a passkey ceremony at most 5 minutes old (/auth/confirm/begin|finish), logged
POST /admin/claim                      → the role, for a link made on the machine

GET  /authorize                        → relying party's request, held; 303 to the UI page /continue/
GET  /auth/authorize/{request}         → what the page shows (site name, identities, attributes asked)
POST /auth/authorize/{request}/approve → code for the chosen identity and the attributes accepted (also /deny, /silent)
POST /token                            → ID token (sub = VSID, accepted attributes), EdDSA

GET    /account/identities/{id}/applications                               → what the identity gave each application
DELETE /account/identities/{id}/applications/{client}[/attributes/{name}]  → withdraw it

GET /.well-known/openid-configuration
GET /.well-known/jwks.json
```

## Key crates

- `sqlx` (`any` over sqlite; postgres behind the feature `postgres`) — `brigid-store`
- `webauthn-rs` — `brigid-webauthn`
- `jsonwebtoken` (EdDSA, v9+) — `brigid-oidc`
- `axum` + `tower-http` + `tower-governor` — `brigid-api`
- `brigid-crypto` (git dep from `brig-id/crypto`)

## Commit conventions

Format: `type(scope): <emoji> description`

| Type | Emoji | When |
| --- | --- | --- |
| `feat` | ✨ | New feature |
| `fix` | 🐛 (🔒️ for security) | Bug fix, security fix or hardening |
| `docs` | 📝 | Documentation only |
| `chore` | 🔧 | Maintenance, config |
| `test` | ✅ | Tests |
| `refactor` | ♻️ | Restructuring, no behaviour change |
| `perf` | ⚡️ | Performance |
| `style` | 🎨 | Formatting only |
| `ci` | 👷 | CI/CD |
| `build` | 📦 | Build system, dependencies |
| `revert` | ⏪ | Reverts a previous commit |

### Allowed scopes

| Scope | Maps to |
| --- | --- |
| `store` | `crates/brigid-store` |
| `identity` | `crates/brigid-identity` |
| `webauthn` | `crates/brigid-webauthn` |
| `oidc` | `crates/brigid-oidc` |
| `api` | `crates/brigid-api` |
| `server` | `crates/brigid-server`, `crates/brigid-ui-embed` |
| `workspace` | Root `Cargo.toml`, workspace-level changes |
| `ci` | `.github/workflows/` |
| `deps` | Dependency bumps |

**Do not use a scope outside this list.** If a new crate is added, update this table,
`.vscode/settings.json`, and `.github/workflows/conventional-commits.yml`.

```text
feat(api): ✨ add delete passkey endpoint
fix(store): 🐛 prevent cross-user credential deletion
test(webauthn): ✅ add softpasskey registration roundtrip
chore(deps): 📦 bump uuid from 1.23.1 to 1.23.2
ci(ci): 👷 add conventional commit check
```

## Releases

The core has no release of its own: no version to bump, no tag, no `CHANGELOG.md`. The
servers follow it at a commit of `main` (their `Cargo.lock`), and a server's release
notes list what changed here since the release before, from the commit subjects. So:

- one pull request per change. A change that needs another repository too (crypto, a
  server, the interface) is a pull request there as well, **on a branch of the same
  name**: the `integration` job (brig-id/.github, `integration.yml`) builds the servers
  with this change and those branches and runs their suites, before anything is merged.
  They are merged from crypto down to the servers;
- the commit type says whether a person running a server would notice: `feat`, `fix`,
  `perf` and `revert` are listed in the server's release notes and are a reason for a
  release; `build`, `ci`, `chore`, `docs`, `test` and `refactor` are not. A `!` or a
  `BREAKING CHANGE:` footer is announced first;
- the commit subject is the line people read in those notes: write it for them;
- the core follows crypto the same way: `branch = "main"` in `Cargo.toml`, the commit in
  `Cargo.lock`, moved with `cargo update -p brigid-crypto` by the pull request that
  needs it;
- `brigid release` (brig-id/cli) shows what the servers do not follow yet.

## Commands

```bash
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo audit
cargo deny check
cargo llvm-cov --workspace --summary-only
```
