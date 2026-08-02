#![no_main]
// Fuzz target: feed arbitrary strings into `validate_token` as the raw JWT.
// Must NEVER panic regardless of input — this is the first thing that
// touches a client-supplied bearer token on every authenticated request.
//
// The signing key is fixed and generated once (real ed25519 keygen isn't
// free, and it doesn't need to vary — we're fuzzing the parser/validator,
// not the key material). A fresh `JtiStore` per iteration keeps replay
// state from leaking across iterations and affecting reproducibility.
use brigid_oidc::{JtiStore, OidcSigningKey, validate_token};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static KEY: OnceLock<OidcSigningKey> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    if let Ok(jwt) = std::str::from_utf8(data) {
        let key = KEY.get_or_init(OidcSigningKey::generate);
        let mut jti_store = JtiStore::new();
        let _ = validate_token(
            jwt,
            "https://example.com",
            "test-client",
            key,
            &mut jti_store,
        );
    }
});
