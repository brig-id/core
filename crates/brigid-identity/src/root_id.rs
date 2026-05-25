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
        Ok(Self {
            username: username.to_string(),
            server: server.to_string(),
        })
    }

    /// Returns `did:web:server:u:username`.
    pub fn to_did_web(&self) -> String {
        format!("did:web:{}:u:{}", self.server, self.username)
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

fn validate_server(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::InvalidIdentifier("server is empty".into()));
    }
    for label in s.split('.') {
        if label.is_empty() {
            return Err(Error::InvalidIdentifier(format!(
                "empty label in server '{s}'"
            )));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::InvalidIdentifier(format!(
                "invalid character in server '{s}'"
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::InvalidIdentifier(format!(
                "label starts or ends with hyphen in '{s}'"
            )));
        }
    }
    Ok(())
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
        assert_eq!(id.to_did_web(), "did:web:brig.id:u:berenger");
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
}
