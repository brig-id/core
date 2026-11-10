//! Identity templates: starting points that pre-fill an identity's display
//! fields. Everything stays editable afterwards; nothing remembers which
//! template an identity came from.

/// A template's defaults. `logo` is an `icon:<style>:<name>` reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityTemplate {
    /// Stable key, used by the API (`"work"`, `"family"`, …).
    pub key: &'static str,
    pub name: &'static str,
    pub logo: &'static str,
    pub description: &'static str,
}

/// Every template, in display order.
pub const TEMPLATES: &[IdentityTemplate] = &[
    IdentityTemplate {
        key: "personal",
        name: "Personal",
        logo: "icon:solid:user",
        description: "Kept strictly for yourself.",
    },
    IdentityTemplate {
        key: "work",
        name: "Work",
        logo: "icon:solid:briefcase",
        description: "Work accounts and tools.",
    },
    IdentityTemplate {
        key: "developer",
        name: "Developer",
        logo: "icon:solid:code",
        description: "Developer tooling.",
    },
    IdentityTemplate {
        key: "creative",
        name: "Creative",
        logo: "icon:solid:palette",
        description: "Creative tools and communities.",
    },
    IdentityTemplate {
        key: "family",
        name: "Family",
        logo: "icon:solid:people-roof",
        description: "Shared within a restricted circle.",
    },
    IdentityTemplate {
        key: "public",
        name: "Public",
        logo: "icon:solid:globe",
        description: "Visible to everyone.",
    },
    IdentityTemplate {
        key: "isolated",
        name: "Isolated",
        logo: "icon:solid:user-secret",
        description: "Unlinked from everything else.",
    },
];

/// The identities every new account starts with, in creation order.
pub const DEFAULT_TEMPLATE_KEYS: &[&str] = &["public", "personal", "work"];

/// Looks a template up by key.
pub fn template(key: &str) -> Option<&'static IdentityTemplate> {
    TEMPLATES.iter().find(|t| t.key == key)
}

/// The templates of [`DEFAULT_TEMPLATE_KEYS`].
pub fn default_templates() -> impl Iterator<Item = &'static IdentityTemplate> {
    DEFAULT_TEMPLATE_KEYS
        .iter()
        .map(|k| template(k).expect("every default key names a template"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{validate_description, validate_logo, validate_name};

    #[test]
    fn every_template_passes_validation() {
        for t in TEMPLATES {
            validate_name(t.name).unwrap();
            validate_logo(t.logo).unwrap();
            assert!(validate_description(t.description).unwrap().is_some());
        }
    }

    #[test]
    fn keys_are_unique_and_defaults_exist() {
        for (i, a) in TEMPLATES.iter().enumerate() {
            assert!(TEMPLATES[i + 1..].iter().all(|b| b.key != a.key));
        }
        assert_eq!(default_templates().count(), DEFAULT_TEMPLATE_KEYS.len());
        assert!(template("nope").is_none());
    }
}
