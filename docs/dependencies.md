# What the server is made of

A measured look at the dependencies of the server (`brigid-server`, as seedling and grove
run it), for the audit: what code it carries, in which language, and what can go. Measured
on 2026-11-21, core at `2de644e` (seedling 0.8.0, grove 0.1.0).

## In numbers

| | Before | After this change |
| --- | --- | --- |
| Crates linked into the server (`cargo tree -e normal`, `brigid-server`) | 454 | 449 |
| Libraries of cryptography in C or assembly | 3: aws-lc, ring, OpenSSL | 2: aws-lc, OpenSSL |
| Release binary (grove, x86_64 glibc, interface embedded) | 18 355 992 bytes | 18 347 512 bytes |
| The same, symbols stripped | 15 710 760 bytes | 15 703 688 bytes |

Removing ring saves 8 KB of binary: the linker already left out the code nothing called.
What it saves is elsewhere: one less library in C and assembly to vet, to follow for
advisories and to build for every target. Stripping symbols would save 2.6 MB (14 %).

## Cryptography

| Library | Language | Brought by | Used for |
| --- | --- | --- | --- |
| RustCrypto (`ed25519-dalek`, `p256`, `sha2`, `sha3`, `aes-gcm`, `hkdf`…) | Rust | `brigid-crypto`, `jsonwebtoken` (`rust_crypto`) | Our own cryptography: storage encryption, key derivation, ID tokens, client assertions |
| aws-lc (`aws-lc-rs`, `aws-lc-sys`) | C and assembly | `rustls` (`axum-server`, `reqwest`, `instant-acme`) | TLS: the server's own certificate when it serves HTTPS itself (with the ACME account and the certificate's key, `rcgen`), and reading the documents of sites |
| OpenSSL (`openssl`, `openssl-sys`; vendored in the static binary) | C | `webauthn-rs-core` 0.5 | **Every passkey sign-in** (verifying the assertion's signature, `COSEKey::verify_signature`), SHA-256 inside webauthn-rs, and attestation chains (never asked for) |
| ring | C and assembly | `sqlx` (`runtime-tokio-rustls`) | **Nothing**: sqlx only needs TLS for network databases; SQLite has none. Removed here |

### Correction

`AGENTS.md` and `deny.toml` said OpenSSL served attestation chains only, "never signature
flows". That was wrong: in webauthn-rs 0.5, `webauthn-rs-core/src/crypto.rs` verifies every
authentication signature with OpenSSL. Both now say so.

### Removing OpenSSL

**webauthn-rs 0.6** (0.6.2, October 2026) replaces OpenSSL with `crypto-glue`, a facade over
RustCrypto (`p256`, `p384`, `rsa`, `sha2`, `x509-cert`…). With it, the passkey checks run on
the same RustCrypto as our own code, and OpenSSL leaves the binary.

**Blocked, upstream, for now:** `crypto-glue` 0.2.2 asks `rsa` 0.10 with a `sha2` feature
that only its release candidates had; `jsonwebtoken` 12 asks `rsa` 0.10.0 final. Cargo can
hold one 0.10 only, so the two cannot resolve together. `crypto-glue` fixed it on its main
branch (kanidm/crypto-glue#49, `rsa = "0.10.0"`), not released yet (#52). When it is:

1. `webauthn-rs`, `webauthn-rs-proto`, `webauthn-authenticator-rs` (tests) to 0.6;
2. adapt `brigid-webauthn` to the 0.6 API, run the integration tests (the soft passkey
   covers registration and authentication end to end);
3. drop the `openssl` vendored dependency of the static builds (seedling, grove) and the
   `openssl-sys` exception of `deny.toml`.

The alternative, verifying assertions ourselves with RustCrypto, is a few hundred lines of
sensitive code (COSE keys, the signed data, the counter): not worth it while a maintained
library is about to do it.

### Two TLS libraries would be one

aws-lc stays: rustls needs a provider, and the pure-Rust one (`rustls-rustcrypto`) is not
production-ready. After the webauthn upgrade the binary carries two stacks with clear roles:
**RustCrypto for everything brig·id decides, aws-lc for TLS only**. aws-lc is FIPS-validated
and maintained by AWS; it is also what `axum-server` defaults to.

## The rest

| Item | Finding | Decision |
| --- | --- | --- |
| `reqwest` | Only `rustls` (aws-lc), no proxy, no default features: reads site documents | Keep |
| `tokio` `full` | The workspace asks every feature; the server uses `rt-multi-thread`, `macros`, `net`, `time`, `signal`, `sync`, `fs` | Narrow later: little code saved, `full` costs compile time more than binary |
| Allocator | The static binary uses musl's allocator, slow under concurrent load | Measure first (a load test of sign-ins, glibc vs musl vs mimalloc); a server for a family does not need it |
| `strip = "debuginfo"` | Symbols stay in the release binary: 2.6 MB of 18.4 | Keep them: a panic then names its function, which an operator can report |
| `lto = "thin"` | `fat` is slower to build, smaller by a few percent | Not worth the CI time today |
| `libsqlite3-sys` | C, SQLite itself, bundled | Keep: the database |

## How to measure again

```sh
cargo tree -e normal -p brigid-server --prefix none | sort -u | wc -l
cargo tree -e normal -i ring              # nothing, after this change
cargo tree -e normal -i openssl-sys       # webauthn-rs-core, until 0.6
cargo tree -e normal -p brigid-server --prefix none | sort -u | grep -- '-sys '
```
