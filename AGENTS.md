# AGENTS.md — brig·id `core`

This repository contains the **business logic crates** for brig·id,
organized as a Cargo workspace under `crates/`.

## Language

**All content must be in English** — code, comments, doc-comments, commit messages,
issues, pull requests. No exceptions.

## Scope

| Crate | Phase | Purpose |
|---|---|---|
| `brigid-store` | 2 | Zero-trust SQLite storage (all data encrypted before INSERT) |
| `brigid-did` | 2 | DID:web and DID:peer resolution + `.well-known/did.json` handler |
| `brigid-identity` | 3 | `RootId`, `PrivateAlias`, `IdentifierKind`, VSID computation |
| `brigid-webauthn` | 4 | Passkey registration and authentication flows |
| `brigid-oidc` | 5 | ID Token issuance, JWKS, `.well-known/openid-configuration` |
| `brigid-api` | 6 | Axum HTTP server — all routes |
| `brigid-ui` | 6 | Leptos SSR frontend (login page, passkey management) |

## Current phases

**Phases 2–6** — see `/workspaces/.dev/phases/` for checklists.

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
  (`default-src 'self'`, no `unsafe-inline`, nonce-based for Leptos hydration scripts).
- **Rate limiting** — all `/auth/*` routes: 20 req/min per IP via `tower-governor`.

## Architecture quick-reference

```
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
- `leptos` + `leptos_axum` — `brigid-ui`
- `brigid-crypto` (git dep from `brig-id/crypto`)

## Commit conventions

Follow the org-wide convention defined in `brig-id/.github/AGENTS.md` —
**Conventional Commits + gitmoji**, format `type(scope): <emoji> description`.

### Allowed scopes for this repo

| Scope | Maps to |
| --- | --- |
| `store` | `crates/brigid-store` |
| `did` | `crates/brigid-did` |
| `identity` | `crates/brigid-identity` |
| `webauthn` | `crates/brigid-webauthn` |
| `oidc` | `crates/brigid-oidc` |
| `api` | `crates/brigid-api` |
| `ui` | `crates/brigid-ui` |
| `workspace` | Root `Cargo.toml`, workspace-level changes |
| `ci` | `.github/workflows/` |
| `deps` | Dependency bumps (`Cargo.lock`, `Cargo.toml` version pins) |

**Do not use a scope outside this list.** If a new crate is added, update:

1. This table
2. `.vscode/settings.json` → `conventionalCommits.scopes`
3. `.github/workflows/conventional-commits.yml` → `scopes` input

### Examples

```text
feat(api): ✨ add delete passkey endpoint
fix(store): 🐛 prevent cross-user credential deletion
test(webauthn): ✅ add softpasskey registration roundtrip
chore(deps): 📦 bump uuid from 1.23.1 to 1.23.2
ci(ci): 👷 add conventional commit PR check
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
