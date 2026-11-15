//! Attributes of an **identity**: what a person puts on it in order to share
//! it with applications.
//!
//! An attribute is not a label. The name, the icon and the description of an
//! identity are for the person and never leave the server; an attribute goes
//! to an application once the person has accepted to share it, as the OpenID
//! Connect claim of the same name.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Longest value of an attribute, in characters, whichever it is.
pub const ATTRIBUTE_MAX_CHARS: usize = 254;

/// One attribute. The order is the order they are shown in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribute {
    GivenName,
    FamilyName,
    PreferredUsername,
    Email,
    Locale,
    Zoneinfo,
}

/// Whether an application that may ask for an attribute needs it to work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Need {
    /// The person may refuse it and still sign in.
    Optional,
    /// Without it the sign-in stops.
    Required,
}

/// The OpenID Connect scope an application asks an attribute through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Profile,
    Email,
}

impl Scope {
    /// The scope named `value`, if it is one that carries attributes.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "profile" => Some(Self::Profile),
            "email" => Some(Self::Email),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Email => "email",
        }
    }
}

impl Attribute {
    /// Every attribute, in the order they are shown in.
    pub const ALL: [Self; 6] = [
        Self::GivenName,
        Self::FamilyName,
        Self::PreferredUsername,
        Self::Email,
        Self::Locale,
        Self::Zoneinfo,
    ];

    /// The name of the claim that carries it.
    pub fn claim(self) -> &'static str {
        match self {
            Self::GivenName => "given_name",
            Self::FamilyName => "family_name",
            Self::PreferredUsername => "preferred_username",
            Self::Email => "email",
            Self::Locale => "locale",
            Self::Zoneinfo => "zoneinfo",
        }
    }

    /// The attribute carried by the claim `name`.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.claim() == name)
    }

    /// The scope that asks for it.
    pub fn scope(self) -> Scope {
        match self {
            Self::Email => Scope::Email,
            _ => Scope::Profile,
        }
    }

    /// Validates a value for this attribute and returns it trimmed.
    ///
    /// The checks are about shape: the server does not know whether a first
    /// name is the person's, and an address is not shown to exist.
    pub fn validate(self, value: &str) -> Result<String> {
        let value = value.trim();
        let invalid = |what: &str| Err(Error::InvalidProfile(format!("{}: {what}", self.claim())));
        if value.is_empty() {
            return invalid("a value is required");
        }
        if value.chars().count() > ATTRIBUTE_MAX_CHARS {
            return invalid("the value is too long");
        }
        if value.chars().any(char::is_control) {
            return invalid("the value contains control characters");
        }
        let well_formed = match self {
            Self::GivenName | Self::FamilyName => value.chars().count() <= 100,
            Self::PreferredUsername => {
                value.chars().count() <= 64 && !value.chars().any(char::is_whitespace)
            }
            Self::Email => is_email(value),
            Self::Locale => is_language_tag(value),
            Self::Zoneinfo => is_time_zone(value),
        };
        if !well_formed {
            return invalid(match self {
                Self::GivenName | Self::FamilyName => "the value is too long",
                Self::PreferredUsername => "at most 64 characters, without spaces",
                Self::Email => "not an e-mail address",
                Self::Locale => "not a language tag (for example fr or en-GB)",
                Self::Zoneinfo => "not a time zone name (for example Europe/Paris)",
            });
        }
        Ok(value.to_owned())
    }
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.claim())
    }
}

/// The attributes of one identity. An attribute that is absent has no value:
/// there is no empty one.
pub type Attributes = BTreeMap<Attribute, String>;

/// Validates every value of `attributes`; the result holds the trimmed ones.
pub fn validate_attributes(attributes: &Attributes) -> Result<Attributes> {
    attributes
        .iter()
        .map(|(attribute, value)| Ok((*attribute, attribute.validate(value)?)))
        .collect()
}

/// `local@domain`, one `@`, a domain with a dot and no space anywhere: enough
/// to refuse a typing mistake, not a proof that the address exists.
fn is_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !domain.contains('@')
        && !value.chars().any(char::is_whitespace)
        && domain.split('.').count() >= 2
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_alphanumeric() || c == '-')
        })
}

/// The shape of a BCP 47 tag: a language of two or three letters, then
/// subtags of one to eight letters or digits (`fr`, `en-GB`, `zh-Hant-TW`).
fn is_language_tag(value: &str) -> bool {
    let mut subtags = value.split('-');
    let language = subtags.next().unwrap_or("");
    (2..=3).contains(&language.len())
        && language.chars().all(|c| c.is_ascii_alphabetic())
        && subtags
            .all(|s| (1..=8).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// The shape of a name of the IANA time zone database (`Europe/Paris`,
/// `America/Argentina/Buenos_Aires`, `UTC`).
fn is_time_zone(value: &str) -> bool {
    value.len() <= 64
        && value.split('/').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_and_scopes() {
        for attribute in Attribute::ALL {
            assert_eq!(Attribute::parse(attribute.claim()), Some(attribute));
        }
        assert_eq!(Attribute::parse("name"), None);
        assert_eq!(Attribute::parse("sub"), None);
        assert_eq!(Attribute::Email.scope(), Scope::Email);
        assert_eq!(Attribute::GivenName.scope(), Scope::Profile);
        assert_eq!(Scope::parse("profile"), Some(Scope::Profile));
        assert_eq!(Scope::parse("openid"), None);
    }

    /// The name used in storage and in the API is the claim's.
    #[test]
    fn the_serialised_name_is_the_claim() {
        for attribute in Attribute::ALL {
            let json = serde_json::to_string(&attribute).unwrap();
            assert_eq!(json, format!("\"{}\"", attribute.claim()));
        }
    }

    #[test]
    fn values_are_trimmed_and_checked() {
        assert_eq!(Attribute::GivenName.validate("  Ada ").unwrap(), "Ada");
        assert!(Attribute::GivenName.validate("   ").is_err());
        assert!(Attribute::GivenName.validate("a\nb").is_err());
        assert!(Attribute::FamilyName.validate(&"x".repeat(101)).is_err());

        assert!(Attribute::PreferredUsername.validate("ada_l").is_ok());
        assert!(Attribute::PreferredUsername.validate("ada l").is_err());
        assert!(
            Attribute::PreferredUsername
                .validate(&"x".repeat(65))
                .is_err()
        );
    }

    #[test]
    fn email_shape() {
        for ok in ["ada@example.org", "a.b+tag@sub.example.co", "é@exämple.fr"] {
            assert!(Attribute::Email.validate(ok).is_ok(), "{ok}");
        }
        for bad in [
            "ada",
            "@example.org",
            "ada@",
            "ada@localhost",
            "ada@@example.org",
            "ada@exa mple.org",
            "ada@.org",
            "ada@-example.org",
            "ada@example..org",
        ] {
            assert!(Attribute::Email.validate(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn locale_and_time_zone_shapes() {
        for ok in ["fr", "en-GB", "zh-Hant-TW", "gsw"] {
            assert!(Attribute::Locale.validate(ok).is_ok(), "{ok}");
        }
        for bad in ["f", "french", "fr_FR", "fr-", "fr-toolongsubtag"] {
            assert!(Attribute::Locale.validate(bad).is_err(), "{bad}");
        }
        for ok in [
            "Europe/Paris",
            "UTC",
            "America/Argentina/Buenos_Aires",
            "Etc/GMT+1",
        ] {
            assert!(Attribute::Zoneinfo.validate(ok).is_ok(), "{ok}");
        }
        for bad in ["Europe/", "/Paris", "Europe Paris", "Europe//Paris"] {
            assert!(Attribute::Zoneinfo.validate(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_map_is_validated_as_a_whole() {
        let mut attributes = Attributes::new();
        attributes.insert(Attribute::GivenName, " Ada ".into());
        attributes.insert(Attribute::Email, "ada@example.org".into());
        let checked = validate_attributes(&attributes).unwrap();
        assert_eq!(checked[&Attribute::GivenName], "Ada");

        attributes.insert(Attribute::Locale, "nope!".into());
        assert!(validate_attributes(&attributes).is_err());
    }
}
