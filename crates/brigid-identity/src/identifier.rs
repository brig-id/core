use crate::alias::PrivateAlias;
use crate::error::{Error, Result};
use crate::root_id::RootId;

/// The kind of identifier detected from user input.
#[derive(Debug)]
pub enum IdentifierKind {
    /// A validated public root identity (`username@server`).
    RootPublic(RootId),
    /// A private alias (contains `_`, no `@`).
    PrivateAlias(PrivateAlias),
}

/// Detect and parse user-supplied input as either a `RootPublic` or `PrivateAlias`.
///
/// - `@` present → `RootPublic(RootId)` (validated)
/// - `_` present without `@` → `PrivateAlias`
/// - neither → `Err(InvalidIdentifier)`
pub fn parse_identifier(input: &str) -> Result<IdentifierKind> {
    if input.contains('@') {
        let root = RootId::parse(input)?;
        return Ok(IdentifierKind::RootPublic(root));
    }
    if input.contains('_') {
        // SAFETY: `contains('_')` is true and `@` is absent → `is_valid` is guaranteed.
        let alias = PrivateAlias::new(input).expect(
            "invariant violated: alias contains '_' without '@' but is_valid returned false",
        );
        return Ok(IdentifierKind::PrivateAlias(alias));
    }
    Err(Error::InvalidIdentifier(format!(
        "cannot determine identifier kind for '{input}'"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_sign_yields_root_public() {
        let kind = parse_identifier("berenger@brig.id").unwrap();
        assert!(matches!(kind, IdentifierKind::RootPublic(_)));
    }

    #[test]
    fn underscore_yields_private_alias() {
        let kind = parse_identifier("x8Fj_29K").unwrap();
        assert!(matches!(kind, IdentifierKind::PrivateAlias(_)));
    }

    #[test]
    fn neither_is_error() {
        assert!(parse_identifier("something").is_err());
    }

    #[test]
    fn invalid_root_id_propagates_error() {
        // `@` present but username is empty → parse fails
        assert!(parse_identifier("@brig.id").is_err());
    }
}
