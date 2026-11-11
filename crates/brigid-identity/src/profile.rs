//! Display fields of an **identity** (what a relying party sees).
//!
//! An identity belongs to a private account and is identified by its UUID
//! (ADR-007): renaming it never changes the VSID derived from that id.

use crate::{Error, Result};

/// Longest display name, in characters.
pub const NAME_MAX_CHARS: usize = 64;
/// Longest description, in characters.
pub const DESCRIPTION_MAX_CHARS: usize = 500;

fn invalid<T>(msg: &str) -> Result<T> {
    Err(Error::InvalidProfile(msg.to_string()))
}

/// Validates a display name: trimmed, 1 to [`NAME_MAX_CHARS`] characters, no
/// control characters. Returns the trimmed name.
///
/// A display name is not a login name and is not unique.
pub fn validate_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return invalid("name is required");
    }
    if name.chars().count() > NAME_MAX_CHARS {
        return invalid("name is too long");
    }
    if name.chars().any(char::is_control) {
        return invalid("name contains control characters");
    }
    Ok(name.to_string())
}

/// Validates an optional description: trimmed, empty means none, at most
/// [`DESCRIPTION_MAX_CHARS`] characters, newlines allowed, other control
/// characters rejected.
pub fn validate_description(description: &str) -> Result<Option<String>> {
    let description = description.trim();
    if description.is_empty() {
        return Ok(None);
    }
    if description.chars().count() > DESCRIPTION_MAX_CHARS {
        return invalid("description is too long");
    }
    if description.chars().any(|c| c.is_control() && c != '\n') {
        return invalid("description contains control characters");
    }
    Ok(Some(description.to_string()))
}

fn is_slug(s: &str, max: usize) -> bool {
    s.len() <= max && helpers4::validate::is_slug(s)
}

/// Validates a logo reference. Only `icon:<style>:<name>` is accepted (an icon
/// of the predefined library, e.g. `icon:solid:user-astronaut`). The library
/// itself lives in the app; the server only checks the shape. `upload:<id>` is
/// reserved for a later release and rejected for now.
pub fn validate_logo(logo: &str) -> Result<()> {
    let Some(rest) = logo.strip_prefix("icon:") else {
        return invalid("logo must be an icon reference (icon:<style>:<name>)");
    };
    match rest.split_once(':') {
        Some((style, name)) if is_slug(style, 32) && is_slug(name, 64) => Ok(()),
        _ => invalid("malformed icon reference (icon:<style>:<name>)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_trimmed_and_required() {
        assert_eq!(validate_name("  Pro  ").unwrap(), "Pro");
        assert!(validate_name("   ").is_err());
        assert!(validate_name("a\nb").is_err());
        assert!(validate_name(&"x".repeat(NAME_MAX_CHARS)).is_ok());
        assert!(validate_name(&"x".repeat(NAME_MAX_CHARS + 1)).is_err());
        // Counted in characters, not bytes.
        assert!(validate_name(&"é".repeat(NAME_MAX_CHARS)).is_ok());
    }

    #[test]
    fn description_is_optional() {
        assert_eq!(validate_description("  ").unwrap(), None);
        assert_eq!(
            validate_description("line 1\nline 2").unwrap(),
            Some("line 1\nline 2".to_string())
        );
        assert!(validate_description("bad\u{7}").is_err());
        assert!(validate_description(&"x".repeat(DESCRIPTION_MAX_CHARS + 1)).is_err());
    }

    #[test]
    fn logo_accepts_only_icon_references() {
        assert!(validate_logo("icon:solid:user-astronaut").is_ok());
        assert!(validate_logo("icon:brands:github").is_ok());
        for bad in [
            "",
            "icon:",
            "icon:solid",
            "icon:solid:",
            "icon::name",
            "icon:Solid:name",
            "icon:solid:na me",
            "icon:solid:a:b",
            "upload:123",
            "https://example.com/x.png",
        ] {
            assert!(validate_logo(bad).is_err(), "{bad} must be rejected");
        }
    }
}
