#![no_main]
// Fuzz target: arbitrary text as a typed recovery code (ADR-004). It arrives
// unauthenticated at /auth/recovery/begin, so `RecoveryCode::parse` must never
// panic, and a code it accepts must survive its own display form.
use brigid_identity::RecoveryCode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(code) = RecoveryCode::parse(s) {
            let again = RecoveryCode::parse(&code.display()).expect("display form parses");
            assert_eq!(again.recovery_id, code.recovery_id);
            assert_eq!(*again.secret, *code.secret);
            let _ = code.matches(&[0u8; 32]);
        }
    }
});
