/// A private alias: an opaque handle that contains at least one `_` and no `@`.
///
/// This type is defined in phase 3 but not yet surfaced in the public API (v0.0.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateAlias(pub(crate) String);

impl PrivateAlias {
    /// Returns `true` iff `s` is a valid private alias: non-empty, contains `_`, no `@`.
    pub fn is_valid(s: &str) -> bool {
        !s.is_empty() && s.contains('_') && !s.contains('@')
    }

    /// Constructs a `PrivateAlias` if `s` satisfies `is_valid`, otherwise `None`.
    pub fn new(s: &str) -> Option<Self> {
        if Self::is_valid(s) {
            Some(Self(s.to_string()))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_alias() {
        assert!(PrivateAlias::is_valid("x8Fj_29K"));
    }

    #[test]
    fn no_underscore_is_invalid() {
        assert!(!PrivateAlias::is_valid("noUnderscore"));
    }

    #[test]
    fn empty_is_invalid() {
        assert!(!PrivateAlias::is_valid(""));
    }

    #[test]
    fn at_sign_makes_invalid() {
        assert!(!PrivateAlias::is_valid("alias@domain_test"));
    }

    #[test]
    fn new_returns_some_for_valid() {
        let a = PrivateAlias::new("valid_alias").unwrap();
        assert_eq!(a.as_str(), "valid_alias");
    }

    #[test]
    fn new_returns_none_for_invalid() {
        assert!(PrivateAlias::new("nounderscore").is_none());
    }
}
