#![no_main]
// Fuzz target: arbitrary text as the PKCE values of a relying party
// (ADR-008). `code_challenge` arrives unauthenticated at /authorize and
// `code_verifier` at /token: neither check may panic, and a verifier is
// accepted only for a challenge of the valid shape.
use brigid_oidc::pkce::{is_valid_challenge, verify_s256};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let (verifier, challenge) = s.split_once('\n').unwrap_or((s, s));
        if verify_s256(verifier, challenge) {
            assert!(is_valid_challenge(challenge));
            assert!((43..=128).contains(&verifier.len()));
        }
    }
});
