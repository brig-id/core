# AGENTS.md — brig·id `core`

This repository contains the **business logic crates** for brig·id,
organized as a Cargo workspace under `crates/`.

## Language

**All content must be in English** — code, comments, doc-comments, commit messages,
issues, pull requests. No exceptions.

## Scope

| Crate | Purpose |
| --- | --- |
| `brigid-store` | Zero-trust SQLite storage (all data encrypted before INSERT) |
| `brigid-identity` | `RootId` (the account's hidden username), VSID computation, recovery codes, identity labels |
| `brigid-webauthn` | Passkey registration and authentication flows |
| `brigid-oidc` | ID token issuance (EdDSA), PKCE, JWKS, `.well-known/openid-configuration` |
| `brigid-api` | Axum HTTP server — all routes |
| `brigid-server` | What every server edition runs: configuration, operator commands, startup, the embedded interface, metrics |
| `brigid-ui-embed` | Build-time helper: embeds the built interface in an edition's executable |

## Roadmap & planning

TODOs, backlog ideas, and phase/release status for this repo are tracked as cards in
[brig-id Project 1](https://github.com/orgs/brig-id/projects/1), not in local files.

## Hard security constraints

- **Zero-trust storage** — every sensitive field must be encrypted via `brigid-crypto`
  before being written to SQLite. A raw SQL dump must never expose readable secrets.
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
  value the identity has now (`standing` in `brigid-api/src/routes/authorize.rs`). Pending
  requests and codes are held in memory with a TTL and a cap.
- **Sites that describe themselves** (`brigid-api/src/described.rs`) — the server fetches
  a document at a URL anyone chooses: keep every rule of the module (https and a domain
  name, the resolver that drops special-use addresses, no redirect, no proxy, 5 KiB, 10 s,
  errors never cached). Such a site has no secret: `private_key_jwt` (EdDSA or ES256, `jti`
  once) or PKCE alone. The linking page shows its host, never only its declared name.
- **CSP header** — `brigid-api` must emit a strict `Content-Security-Policy`
  (`default-src 'self'`, no `unsafe-inline`).
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

GET  /admin/accounts, /admin/applications, /admin/sign-up, /admin/log → an administrator's session
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

- `sqlx` (sqlite, runtime-tokio-rustls) — `brigid-store`
- `webauthn-rs` — `brigid-webauthn`
- `jsonwebtoken` (EdDSA, v9+) — `brigid-oidc`
- `axum` + `tower-http` + `tower-governor` — `brigid-api`
- `brigid-crypto` (git dep from `brig-id/crypto`)

## Commit conventions

Format: `type(scope): <emoji> description`

| Type | Emoji | When |
| --- | --- | --- |
| `feat` | ✨ | New feature |
| `fix` | 🐛 | Bug fix |
| `docs` | 📝 | Documentation only |
| `chore` | 🔧 | Maintenance, config |
| `test` | ✅ | Tests |
| `refactor` | ♻️ | Restructuring, no behaviour change |
| `perf` | ⚡️ | Performance |
| `style` | 🎨 | Formatting only |
| `ci` | 👷 | CI/CD |
| `security` | 🔒 | Security fix or hardening |
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
| `release` | A release pull request (release-please) |

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

Nobody tags by hand. `.github/workflows/release.yml` (release-please, through the
shared workflow of brig-id/.github) keeps a release pull request up to date: the next
version of every crate of the workspace (they share it, from the commit types since the
last release) and its `CHANGELOG.md` entry. **Merging that pull request is the
release**: the tag `vX.Y.Z` and the GitHub Release follow, and Renovate proposes the new
tag to the servers, which pin the core by `tag`. So:

- the commit type decides the version: `feat` is a minor, `fix` a patch, a `!` or a
  `BREAKING CHANGE:` footer a minor too while the version is 0.x;
- the commit subject is the changelog line: write it for someone reading the release;
- a new release of brig-id/crypto comes from Renovate as `feat(deps)` or `fix(deps)`,
  and so makes a release of the core;
- do not edit `CHANGELOG.md`, `.release-please-manifest.json` or the crates' versions
  by hand.

## Commands

```bash
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo audit
cargo deny check
cargo llvm-cov --workspace --summary-only
```
