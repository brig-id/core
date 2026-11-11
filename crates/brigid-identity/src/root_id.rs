use std::fmt;

use crate::error::{Error, Result};

/// Validated public identity of the form `username@server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootId {
    pub username: String,
    pub server: String,
}

impl RootId {
    /// Parse and validate a `username@server` string.
    pub fn parse(input: &str) -> Result<Self> {
        let at = input
            .find('@')
            .ok_or_else(|| Error::InvalidIdentifier(format!("missing '@' in '{input}'")))?;
        let username = &input[..at];
        let server = &input[at + 1..];
        validate_username(username)?;
        validate_server(server)?;
        // DNS hostnames are case-insensitive (RFC 4343). Canonicalise the
        // server component to lowercase before storing so that
        // `alice@Example.com` and `alice@example.com` produce the same
        // `username_index`, DID:web URL, and persisted `RootId`. Without
        // this, two clients addressing the same host could mint distinct
        // root identities for what is, by DNS, the same authority.
        Ok(Self {
            username: username.to_string(),
            server: server.to_ascii_lowercase(),
        })
    }
}

impl fmt::Display for RootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.username, self.server)
    }
}

fn validate_username(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::InvalidIdentifier("username is empty".into()));
    }
    if s.len() < 3 || s.len() > 64 {
        return Err(Error::InvalidIdentifier(format!(
            "username length {} out of range [3, 64]",
            s.len()
        )));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::InvalidIdentifier(format!(
            "invalid character in username '{s}'"
        )));
    }
    if s.chars().all(|c| c == '_') {
        return Err(Error::InvalidIdentifier(
            "username cannot consist only of underscores".into(),
        ));
    }
    Ok(())
}

/// A DNS hostname (RFC 1123 syntax), without a trailing dot: the server part
/// is compared and stored as written, so `example.com.` must not pass for a
/// second spelling of `example.com`.
fn validate_server(s: &str) -> Result<()> {
    if s.ends_with('.') {
        return Err(Error::InvalidIdentifier(format!(
            "server '{s}' ends with a dot"
        )));
    }
    helpers4::net::is_valid_hostname(s)
        .map_err(|e| Error::InvalidIdentifier(format!("invalid server '{s}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_root_id() {
        let id = RootId::parse("berenger@brig.id").unwrap();
        assert_eq!(id.username, "berenger");
        assert_eq!(id.server, "brig.id");
        assert_eq!(id.to_string(), "berenger@brig.id");
    }

    #[test]
    fn missing_at_sign() {
        assert!(RootId::parse("berenger").is_err());
    }

    #[test]
    fn empty_username() {
        assert!(RootId::parse("@brig.id").is_err());
    }

    #[test]
    fn username_too_short() {
        assert!(RootId::parse("ab@brig.id").is_err());
    }

    #[test]
    fn username_too_long() {
        let long = "a".repeat(65);
        assert!(RootId::parse(&format!("{long}@brig.id")).is_err());
    }

    #[test]
    fn username_invalid_char() {
        assert!(RootId::parse("inv!alid@brig.id").is_err());
    }

    #[test]
    fn username_only_underscores() {
        assert!(RootId::parse("___@brig.id").is_err());
    }

    #[test]
    fn server_empty() {
        assert!(RootId::parse("alice@").is_err());
    }

    #[test]
    fn server_empty_label() {
        assert!(RootId::parse("alice@brig..id").is_err());
    }

    #[test]
    fn server_invalid_char() {
        assert!(RootId::parse("alice@brig!id").is_err());
    }

    #[test]
    fn server_label_starts_with_hyphen() {
        assert!(RootId::parse("alice@-brig.id").is_err());
    }

    #[test]
    fn server_label_ends_with_hyphen() {
        assert!(RootId::parse("alice@brig-.id").is_err());
    }

    #[test]
    fn server_with_trailing_dot_is_rejected() {
        assert!(RootId::parse("alice@brig.id.").is_err());
    }

    #[test]
    fn server_that_is_an_ip_address_is_rejected() {
        assert!(RootId::parse("alice@192.168.0.1").is_err());
    }

    #[test]
    fn server_is_lowercased() {
        let id = RootId::parse("alice@Example.COM").unwrap();
        assert_eq!(id.server, "example.com");
        // Case variants must map to the same canonical RootId.
        let other = RootId::parse("alice@EXAMPLE.com").unwrap();
        assert_eq!(id, other);
    }

    #[test]
    fn server_label_too_long() {
        // Single label of 64 octets — exceeds the RFC 1035 §2.3.4 limit of 63.
        let label = "a".repeat(64);
        assert!(RootId::parse(&format!("alice@{label}.id")).is_err());
    }

    #[test]
    fn server_label_at_max_length_ok() {
        // Boundary: a 63-octet label must be accepted.
        let label = "a".repeat(63);
        assert!(RootId::parse(&format!("alice@{label}.id")).is_ok());
    }

    #[test]
    fn server_hostname_too_long() {
        // Build a hostname whose total length exceeds 253 octets while keeping
        // each label under 63. 5 labels of 60 chars + 4 dots = 304 octets.
        let label = "a".repeat(60);
        let host = std::iter::repeat_n(label.as_str(), 5)
            .collect::<Vec<_>>()
            .join(".");
        assert!(host.len() > 253);
        assert!(RootId::parse(&format!("alice@{host}")).is_err());
    }
}
