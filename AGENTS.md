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
| `brigid-did` | DID:web and DID:peer resolution + `.well-known/did.json` handler |
| `brigid-identity` | `RootId`, `PrivateAlias`, `IdentifierKind`, VSID computation |
| `brigid-webauthn` | Passkey registration and authentication flows |
| `brigid-oidc` | ID Token issuance, JWKS, `.well-known/openid-configuration` |
| `brigid-api` | Axum HTTP server — all routes |

## Current phases

See `/workspaces/.dev/phases/` for the v2 plan:

| File | Phase | Status |
| --- | --- | --- |
| `phase-1.md` | API finalization (`DELETE /auth/passkeys`, `user_id` in `LoginResponse`) | ⬜ |
| `phase-2.md` | Qwik UI (`brig-id/web`) | ⬜ |
| `phase-3.md` | Integration & E2E (`server-leaf`) | ⬜ |
| `phase-4.md` | Release v0.1.0 | ⬜ |

## Hard security constraints

- **Zero-trust storage** — every sensitive field must be encrypted via `brigid-crypto`
  before being written to SQLite. A raw SQL dump must never expose readable secrets.
- **VSID invariants** (enforced in `brigid-identity`):
  - `sub` in OIDC tokens = VSID, never username, alias, or raw DID.
  - VSID must never be derived from an alias.
  - VSID must never be derived from a virtual identity.
  - Same `(did_root, client_id, salt)` → same VSID; different `client_id` → different VSID.
- **No OpenSSL** — use `rustls` everywhere; TLS 1.3 minimum. **Single
  documented exception:** `webauthn-rs`'s attestation CA chain validator
  (`webauthn-attestation-ca`) pulls in `openssl-sys` transitively. The
  exception is scoped strictly to attestation chain verification — TLS,
  KEM, DSA, KDF and signature flows must stay on rustls / RustCrypto.
  `server-leaf/Dockerfile` documents the link-time consequences.
- **No secrets in logs** — `tracing` spans must never capture key material, credentials, or tokens.
- **No `unwrap()` on error paths** — typed errors via `thiserror`.
- **WebAuthn** — RP ID must be strict (no wildcard); signature counter must be verified.
- **OIDC** — `jti` store must have TTL = token `exp`; never grow unbounded.
- **CSP header** — `brigid-api` must emit a strict `Content-Security-Policy`
  (`default-src 'self'`, no `unsafe-inline`).
- **Rate limiting** — all `/auth/*` routes: 20 req/min per IP via `tower-governor`.

## Architecture quick-reference

```text
POST /auth/register/begin  → WebAuthn CreationChallenge
POST /auth/register/finish → store encrypted credential
POST /auth/login/begin     → WebAuthn RequestChallenge
POST /auth/login/finish    → ID Token (sub = VSID)

GET /.well-known/openid-configuration
GET /.well-known/jwks.json
GET /.well-known/did.json
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
| `did` | `crates/brigid-did` |
| `identity` | `crates/brigid-identity` |
| `webauthn` | `crates/brigid-webauthn` |
| `oidc` | `crates/brigid-oidc` |
| `api` | `crates/brigid-api` |
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

## Commands

```bash
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo audit
cargo deny check
cargo llvm-cov --workspace --summary-only
```
