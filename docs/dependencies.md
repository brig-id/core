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
| RustCrypto again, through `crypto-glue` (`p256`, `p384`, `p521`, `rsa`, `sha2`, `x509-cert`…) | Rust | `webauthn-rs-core` 0.6 | **Every passkey sign-in** (verifying the assertion's signature), SHA-256 inside webauthn-rs, and attestation chains (never asked for) |
| OpenSSL | C | `webauthn-rs-core` 0.5 | **Gone** with webauthn-rs 0.6 (2026-11-27): it did the line above |
| ring | C and assembly | `sqlx` (`runtime-tokio-rustls`) | **Nothing**: sqlx only needs TLS for network databases; SQLite has none. Removed here |

### Correction

`AGENTS.md` and `deny.toml` said OpenSSL served attestation chains only, "never signature
flows". That was wrong: in webauthn-rs 0.5, `webauthn-rs-core/src/crypto.rs` verifies every
authentication signature with OpenSSL. Both now say so.

### OpenSSL is removed

webauthn-rs 0.5 verified every passkey assertion with OpenSSL. **webauthn-rs 0.6** does it
with `crypto-glue`, a facade over RustCrypto: the passkey checks now run on the same
RustCrypto as our own code, and OpenSSL left the binary on 2026-11-27 (core#120).

- It waited for `crypto-glue` 0.2.3 (2026-11-26): 0.2.2 asked `rsa` 0.10 with a feature
  only its release candidates had, which could not resolve next to `jsonwebtoken` 12.
- What changed in our code: a discoverable sign-in is verified against the one passkey the
  response names (`finish_discoverable_authentication_v2`), which must be one of the
  account's, instead of handing every passkey of the account to the library. The tests
  drive a software passkey through registration, sign-in and discoverable sign-in.
- The price: 38 more crates in the server (453 to 491), all Rust, most of them RustCrypto
  algorithms webauthn-rs can meet in a passkey (P-384, P-521, RSA) and that brig·id never
  asks for. One library in C less to vet, to follow for advisories and to build for every
  target; the static builds no longer compile OpenSSL from source.
- Left to do in the servers: drop their `openssl` (vendored) dependency of the static
  builds, and move their tests' software passkey to 0.6.

### Two TLS libraries would be one

aws-lc stays: rustls needs a provider, and the pure-Rust one (`rustls-rustcrypto`) is not
production-ready. The binary carries two stacks with clear roles:
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
| `sqlx` `any` | The store speaks to its database through the driver's database-agnostic mode, so that its statements are written once for SQLite and PostgreSQL | Keep: it is what makes the store one implementation (spec `forest.md` §3). No crate added |
| `sqlx` `postgres` (feature `postgres`) | The PostgreSQL driver: `sqlx-postgres`, and for the SCRAM sign-in to the database `md-5`, `stringprep`, three `unicode-*` crates, `rand`, `chacha20`, `tinyvec`, `byteorder`, `whoami`. TLS to the database is rustls on aws-lc, already there: one crate more, `webpki-roots` | **Off by default.** seedling and grove are built without it and carry none of these twelve crates; only an edition on PostgreSQL turns it on |

## How to measure again

```sh
cargo tree -e normal -p brigid-server --prefix none | sort -u | wc -l
cargo tree -e normal -i ring              # nothing, after this change
cargo tree -e normal -i openssl-sys       # nothing, since webauthn-rs 0.6
cargo tree -e normal -p brigid-server --prefix none | sort -u | grep -- '-sys '
```
