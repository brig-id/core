# Changelog

All notable changes to the `brig-id/core` crates (`brigid-store`,
`brigid-did`, `brigid-identity`, `brigid-webauthn`, `brigid-oidc`,
`brigid-api`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **Who may sign up is a policy kept in the database** (core#88): `open`,
  `invitation` (the default) or `closed`. `AppState::with_signup_open` and
  the `signup_open` field are gone; `EncryptedStore::set_signup_policy` sets
  it, and so does an administrator. `GET /auth/server` returns `policy` next
  to `sign_up`. A server that nobody opened takes accounts by link only.
- `POST /auth/register/begin` takes a `link` (a setup link or an invitation);
  `EncryptedStore::register_user_with_credential` takes it in place of the
  identities it no longer creates, and spends it with the account.
- Refusals the interface acts on carry a `code` next to their sentence
  (`confirmation_required`, `suspended`, `invitation_required`,
  `link_invalid`, `signup_closed`, `recovery_code_required`).
- The operator's log no longer carries an account identifier when a recovery
  code is used.

### Added

- **Administration** (core#88). The role is on the account
  (`users.admin`). The first administrator is made with a one-time setup link
  on a server without account (`brigid_api::setup_link`), or, on a server that
  has accounts, with a link that grants the role to the signed-in account that
  opens it (`brigid_api::administrator_link`, `POST /admin/claim`). `/admin/…`
  lists accounts (generated username, dates, passkey count, recovery code
  present), suspends, deletes, grants and withdraws the role, registers
  applications, sets the sign-up policy and makes invitations. Reading needs
  an administrator; every change also needs a passkey ceremony done in the
  session at most five minutes ago (`/auth/confirm/begin|finish`), and is
  logged. No administration response holds an identity, a label, an
  attribute or where an identity is used.
- **Suspension**: a suspended account has no session, opens none, recovers
  nothing and gets no token; nothing of it is deleted.
- **Invitations**: links that create ordinary accounts, as many as their
  maker says (1 to 100), for 1 to 90 days (7 by default), revocable.
- **The last administrator** keeps the role and the account: withdrawing,
  suspending or deleting is refused, from the administration and from the
  account's own page.
- **The log of administrative actions** is encrypted, names accounts by
  their identifier only (names are looked up when it is read, so an entry
  about a deleted account names nobody), and entries older than
  `AppState::admin_log_retention` (twelve months by default) are deleted.
- Schema script `0003_administration.sql`.

### Security

- The Content Security Policy of API responses (JSON and redirects) is
  `default-src 'none'`, with nothing framed, based or submitted. It still
  allowed a photo service the interface stopped using.

### Changed

- **Registration creates no identity** (core#98). `GET
  /account/identity-templates` lists the starters first and marks them
  (`starter`); the onboarding proposes them and the browser creates the ones
  the person keeps. An account that signs in with no identity is no longer
  given three.
- **An account without a recovery code is still in its onboarding** (core#98):
  identities, their applications and the answer to an authorization request
  are refused (`403`, "a recovery code is required first") until `POST
  /account/recovery-code` has run. `GET /auth/session` says so
  (`recovery_code`), and so does `GET /auth/authorize/{request}`
  (`needs_recovery_code`). A code can be replaced, not removed.

### Added

- **A person can delete their account** (core#98): `POST
  /account/delete/begin` and `/finish`, a passkey ceremony begun for that
  purpose and for the session's account. A ceremony begun to sign in cannot
  delete, and the other way round. `EncryptedStore::delete_account` removes
  the account, its passkeys, recovery code, sessions, identities, and what
  was recorded about the applications they signed in to.
- Attributes (core#91). An identity carries optional attributes
  (`given_name`, `family_name`, `preferred_username`, `email`, `locale`,
  `zoneinfo`), set through `/account/identities`. A registered client lists
  the ones it may ask for and which it requires
  (`EncryptedStore::set_client_attributes`); the `profile` and `email` scopes
  ask for them, and are refused (`invalid_scope`) to a client registered for
  none. `/auth/authorize/{request}` tells the page what is asked and what was
  already decided; `approve` takes the attributes the person accepts: an
  optional one refused continues, a required one refused is a 409. Decisions
  are recorded per identity and per client with the accepted values, so a
  changed value is asked again, and `prompt=none` answers `consent_required`
  until everything asked is decided. The ID token carries the accepted
  attributes; `email_verified` is always `false`.
  `/account/identities/{id}/applications` lists what an identity gave each
  application and withdraws it. Schema script `0002_attributes.sql`.
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
- **The database schema is one script**, `0001_schema.sql`: the twelve steps
  that led to it are folded into their result (same tables, columns, keys and
  indexes). **A database created by an earlier version cannot be opened**: no
  server held anything to keep, and each starts again from an empty one.
- The VSID secret is always 32 random bytes drawn at a database's first start.
  `EncryptedStore::vsid_secret` takes no argument, and `derive_vsid_salt` is
  gone: no database is left whose identifiers came from the master key.
- Identity logos are Phosphor references, `icon:ph:<name>`: the templates use
  the new names and any other form is refused when a logo is written. Nothing
  stored is converted: no server holds identities to keep yet. An identity that
  still carries an earlier reference shows the default icon until its logo is
  chosen again.
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
