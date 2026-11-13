#![no_main]
// Fuzz target: feed arbitrary strings into `RootId::parse`.
// The function must NEVER panic regardless of input — malformed identifiers
// must be rejected with an `Err`, not a panic (this is parsed directly from
// untrusted client-supplied usernames during registration).
//
// Raw `&[u8]` + manual UTF-8 conversion rather than `fuzz_target!(|data: &str|)`
// to avoid pulling in the `arbitrary` crate just for its `&str` impl.
use brigid_identity::RootId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = RootId::parse(s);
    }
});
