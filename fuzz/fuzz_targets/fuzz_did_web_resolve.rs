#![no_main]
// Fuzz target: feed arbitrary strings into `did_web_to_url` — the pure,
// synchronous parsing step that turns a `did:web:...` string into the HTTPS
// URL `resolve_did_web` would fetch. Fuzzing `resolve_did_web` itself would
// mean making real network requests per iteration, which is neither
// hermetic nor deterministic; the parsing logic (percent-decoding,
// colon-splitting, URL construction) is what can actually panic on
// malformed input, and it's exercised here without any I/O.
//
// Must NEVER panic regardless of input — this parses a `Did` that ultimately
// comes from an untrusted `username@server` identifier at registration time.
use brigid_did::{Did, did_web_to_url};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let did = Did::new(s);
        let _ = did_web_to_url(&did);
    }
});
