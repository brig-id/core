//! Identity templates: starting points that pre-fill an identity's display
//! fields. Everything stays editable afterwards; nothing remembers which
//! template an identity came from.

/// A template's defaults: an archetype, in the interface. `logo` is an
/// `icon:ph:<name>` reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityTemplate {
    /// The group it is shown in: `everyday`, `work`, `leisure`, `online`.
    pub group: &'static str,
    /// Stable key, used by the API (`"work"`, `"family"`, …).
    pub key: &'static str,
    pub name: &'static str,
    pub logo: &'static str,
    pub description: &'static str,
}

/// The groups, in display order.
pub const GROUPS: &[&str] = &["everyday", "work", "leisure", "online"];

/// Every template, in display order. Each has its own logo, so that the
/// interface can tell which ones an account already uses.
pub const TEMPLATES: &[IdentityTemplate] = &[
    IdentityTemplate {
        group: "everyday",
        key: "public",
        name: "Public",
        logo: "icon:ph:globe-hemisphere-west",
        description: "For everyone you come across online.",
    },
    IdentityTemplate {
        group: "everyday",
        key: "personal",
        name: "Personal",
        logo: "icon:ph:user",
        description: "Yours alone: not even aunt Monique gets in.",
    },
    IdentityTemplate {
        group: "everyday",
        key: "family",
        name: "Family",
        logo: "icon:ph:house-line",
        description: "Family life: the school, the doctor, the group photos.",
    },
    IdentityTemplate {
        group: "everyday",
        key: "friends",
        name: "Friends",
        logo: "icon:ph:users-three",
        description: "Plans, games and group chats with friends.",
    },
    IdentityTemplate {
        group: "everyday",
        key: "shopping",
        name: "Shopping",
        logo: "icon:ph:shopping-cart",
        description: "Online shops and deliveries, nothing more.",
    },
    IdentityTemplate {
        group: "work",
        key: "work",
        name: "Work",
        logo: "icon:ph:briefcase",
        description: "All the work stuff: serious, no fun.",
    },
    IdentityTemplate {
        group: "work",
        key: "freelance",
        name: "Freelance",
        logo: "icon:ph:laptop",
        description: "Clients, quotes and invoices.",
    },
    IdentityTemplate {
        group: "work",
        key: "job-search",
        name: "Job search",
        logo: "icon:ph:rocket-launch",
        description: "Job boards and applications, ready for the interview.",
    },
    IdentityTemplate {
        group: "work",
        key: "student",
        name: "Student",
        logo: "icon:ph:graduation-cap",
        description: "Courses, campus and exam season.",
    },
    IdentityTemplate {
        group: "work",
        key: "volunteering",
        name: "Volunteering",
        logo: "icon:ph:heart",
        description: "The associations and causes you give time to.",
    },
    IdentityTemplate {
        group: "leisure",
        key: "gaming",
        name: "Gaming",
        logo: "icon:ph:game-controller",
        description: "Lobbies, clans and late nights.",
    },
    IdentityTemplate {
        group: "leisure",
        key: "music",
        name: "Music",
        logo: "icon:ph:music-notes",
        description: "Playlists, concerts and the band.",
    },
    IdentityTemplate {
        group: "leisure",
        key: "sport",
        name: "Sport",
        logo: "icon:ph:soccer-ball",
        description: "Training, the club and race results.",
    },
    IdentityTemplate {
        group: "leisure",
        key: "travel",
        name: "Travel",
        logo: "icon:ph:airplane-tilt",
        description: "Tickets, bookings and the next trip.",
    },
    IdentityTemplate {
        group: "leisure",
        key: "reading",
        name: "Reading",
        logo: "icon:ph:book-open",
        description: "Books, libraries and reading lists.",
    },
    IdentityTemplate {
        group: "leisure",
        key: "creative",
        name: "Creative",
        logo: "icon:ph:palette",
        description: "Sketches, projects and creative circles.",
    },
    IdentityTemplate {
        group: "online",
        key: "developer",
        name: "Developer",
        logo: "icon:ph:code",
        description: "Code, forges and package registries.",
    },
    IdentityTemplate {
        group: "online",
        key: "social",
        name: "Social",
        logo: "icon:ph:mask-happy",
        description: "Social networks, with the face you choose.",
    },
    IdentityTemplate {
        group: "online",
        key: "forums",
        name: "Forums",
        logo: "icon:ph:feather",
        description: "Forums and comment threads, under a pen name.",
    },
    IdentityTemplate {
        group: "online",
        key: "isolated",
        name: "Isolated",
        logo: "icon:ph:detective",
        description: "Detective mode: tied to nothing else.",
    },
    IdentityTemplate {
        group: "online",
        key: "testing",
        name: "Testing",
        logo: "icon:ph:flask",
        description: "Sign-ups to try something out, then forget.",
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
    fn logos_are_distinct_and_groups_known() {
        for (i, a) in TEMPLATES.iter().enumerate() {
            assert!(
                TEMPLATES[i + 1..].iter().all(|b| b.logo != a.logo),
                "{}",
                a.key
            );
            assert!(GROUPS.contains(&a.group), "{}", a.key);
        }
        assert!(TEMPLATES.len() >= 20);
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
