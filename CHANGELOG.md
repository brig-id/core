# Changelog

All notable changes to the `brig-id/core` crates (`brigid-store`,
`brigid-did`, `brigid-identity`, `brigid-webauthn`, `brigid-oidc`,
`brigid-api`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `AppState::with_signup_open(false)` closes the creation of accounts
  (`/auth/register/begin` answers 403); `GET /auth/server` tells the interface.
- Relying parties can sign people in (ADR-005 §2, ADR-008): registered
  clients, confidential (a secret, stored hashed) or public; `/authorize`
  (Authorization Code, PKCE `S256` mandatory for every client) hands the
  request to the interface page `/continue/`; `/auth/authorize/{request}` and
  its `approve`, `deny` and `silent` let the person choose the identity, which
  is remembered per client; `/token` returns an ID token signed with EdDSA
  whose only statement about the person is `sub`, the VSID of the chosen
  identity for that client. `/.well-known/openid-configuration` is served
  again.
- `brigid-store` — `EncryptedStore::vsid_secret`: the keying material of the
  VSIDs is stored (table `server_secrets`, encrypted) instead of derived from
  the master key at each start. `rotate_master_key` re-encrypts it, so a
  master key rotation no longer changes every VSID. A database that already
  holds accounts keeps the value it was using; a new one gets random bytes.

### Changed

- **Licence: AGPL-3.0-or-later** (was LGPL-3.0-or-later). Versions already
  released keep the licence they were published under.
- Identity logos are Phosphor references, `icon:ph:<name>`. Migration `0013`
  converts the 45 references of the earlier library once; the templates use the
  new names and any other form is refused.
- Removed: the server's DID document (`/.well-known/did.json`, crate
  `brigid-did`), which repeated the key the JWKS publishes, and the unused
  `PrivateAlias`, `IdentifierKind` and `parse_identifier`.
- `brigid-oidc` issues ID tokens and no longer validates them: `validate_token`,
  `decode_token`, `decode_token_with_keys` and `JtiStore` are removed (nothing
  called them since account sessions moved to a cookie). `Claims` loses
  `server` and `alias_type` and gains `auth_time` and `nonce`.
- helpers4 replaces local copies of generic code: `Authorization: Bearer`
  parsing (`brigid-api`), hostname and slug validation (`brigid-identity`),
  the Unix clock (`brigid-oidc`, `brigid-store`). Visible differences: the
  `Bearer` scheme is matched case-insensitively and a token with characters
  outside RFC 6750's set is refused; the server part of a username can no
  longer be an IP address; an icon name cannot start or end with a hyphen.

### Fixed

- `brigid-api` — `POST /auth/register/begin` refuses a username on another
  server (`alice@elsewhere.example`): an account's domain is this server's.
  The `server` claim of every token now comes from the server's own
  configuration instead of the stored account.
- `brigid-api` — an internal error logs its cause; the log line used to carry
  only the fixed "internal server error" text sent to the client.
- `brigid-api` — CORS allows `PATCH`, used by the passkey and identity routes.
- `brigid-api` — the account routes (session, passkeys, identities) have their
  own rate limit, 60 requests per minute in bursts of 30. They shared the
  20-per-minute, burst-of-5 quota of the WebAuthn ceremonies, so signing up
  and signing in left none for the first account page ("Request failed
  (429)").

## [0.1.0] - 2026-09-04

First tagged release, alongside `crypto`, `server-leaf`, and `app`.

### Added

- `brigid-store` — zero-trust SQLite storage: every sensitive field
  (username, server, `did:web`, WebAuthn credential data) is encrypted with
  `brigid-crypto` before it reaches the database, using a per-user key
  derived from the master key. A deterministic, master-key-derived
  `username_index` supports lookups without decrypting every row.
- `brigid-store` — `EncryptedStore::rotate_master_key`: re-encrypts every
  row under a new master key inside a single transaction (full rollback on
  any failure), used by `server-leaf`'s `rotate-key` CLI.
- `brigid-did` — `did:web` and `did:peer` resolution.
- `brigid-identity` — `RootId` parsing and VSID (Virtual Stable Identifier)
  computation: a pairwise, per-relying-party identifier derived from
  `(did_root, client_id, salt)`, never stored, always recomputed.
- `brigid-webauthn` — passkey registration and authentication ceremonies on
  top of `webauthn-rs`.
- `brigid-oidc` — JWT issuance and validation, an in-process + durable
  `JtiStore` for logout/replay revocation, and an OIDC signing key derived
  from the master key at startup (never stored).
- `brigid-api` — the Axum HTTP router: `/auth/*`, `/.well-known/*`
  discovery endpoints, `/health`, `/ready`; per-IP rate limiting on
  `/auth/*` via `tower-governor`; CORS with an explicit origin allowlist;
  security headers (`X-Content-Type-Options`, `X-Frame-Options`,
  `Strict-Transport-Security`, `Content-Security-Policy`) applied to every
  response.
- 3 fuzz targets (`fuzz_parse_identifier`, `fuzz_did_web_resolve`,
  `fuzz_jwt_validate`), wired into a nightly fuzz CI workflow.

### Changed

- The UI moved out of this repo: an early Leptos SSR crate (`brigid-ui`)
  was replaced by the standalone `brig-id/web` repo (Qwik, static-site
  generated), served by `server-leaf` as static files rather than rendered
  by `brigid-api`.

### Fixed

- Registration race: duplicate-username handling now goes through a
  database `UNIQUE` constraint instead of a check-then-insert that raced
  under concurrent registration.
- WebAuthn signature-counter desync (a sign of possible credential cloning)
  now surfaces as an error instead of being silently accepted.
- `x-forwarded-for`-based rate-limit keying is gated behind an explicit
  "trust this header" flag, closing a header-forgery bypass of the
  per-IP rate limit.
- VSID computation routed through the same HKDF domain-separation
  convention as every other derived key, after an earlier version derived
  it slightly differently.
- The one unjustified `unwrap()` found during the phase-4 security audit
  (`brigid-api`'s rate-limiter config builder) now carries an `expect()`
  explaining why it cannot fail.

### Security

- `sub` (the OIDC subject claim) is always the VSID, never a raw DID,
  username, or alias — verified by a dedicated test
  (`vsid_never_derived_from_alias`) and called out explicitly in
  `spec/audit-checklist.md`.
- Logged-out tokens are revoked in both an in-process cache and a durable
  SQLite table, so revocation survives a service restart.
- `cargo deny`'s only permitted `openssl-sys` presence is a transitive,
  attestation-parsing dependency of `webauthn-rs-core` — never used for TLS.
