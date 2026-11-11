//! Generated account usernames ([ADR-003] in the spec): the username is an
//! internal sign-in handle the user never types, so the server picks one.
//!
//! `<adjective>-<animal>-<4 digits>`: readable when it must be read (support,
//! logs), about 37 million combinations, and valid for [`crate::RootId`].
//!
//! [ADR-003]: https://github.com/brig-id/spec/blob/main/decisions/003-usernames-and-quick-signup.md

const ADJECTIVES: [&str; 64] = [
    "amber", "brave", "bright", "calm", "clever", "cosy", "crisp", "curious", "dapper", "deft",
    "eager", "early", "fair", "fancy", "fond", "frank", "gentle", "glad", "golden", "grand",
    "happy", "hardy", "honest", "humble", "jolly", "keen", "kind", "lively", "lucky", "merry",
    "mellow", "mighty", "modest", "neat", "nimble", "noble", "plucky", "polite", "proud", "quick",
    "quiet", "rapid", "ready", "rosy", "rustic", "sharp", "shiny", "silent", "sleek", "smart",
    "snug", "solid", "spry", "steady", "sturdy", "sunny", "swift", "tidy", "true", "vivid", "warm",
    "wise", "witty", "zesty",
];

const ANIMALS: [&str; 64] = [
    "badger", "bat", "bear", "beaver", "bison", "crane", "crow", "deer", "dolphin", "dove",
    "eagle", "elk", "falcon", "ferret", "finch", "fox", "gecko", "goose", "hare", "hawk", "heron",
    "ibex", "jay", "koala", "lark", "lemur", "lion", "llama", "lynx", "marten", "mink", "mole",
    "moose", "newt", "otter", "owl", "panda", "parrot", "pelican", "puffin", "quail", "rabbit",
    "raven", "robin", "seal", "shrew", "sparrow", "squid", "stoat", "swan", "tapir", "tiger",
    "toad", "trout", "turtle", "viper", "vole", "walrus", "weasel", "whale", "wolf", "wombat",
    "wren", "yak",
];

/// A new random username, e.g. `swift-otter-4821`.
pub fn generate_username() -> Result<String, helpers4::random::EntropyError> {
    let r = helpers4::random::random_bytes(4)?;
    let adjective = ADJECTIVES[usize::from(r[0] & 63)];
    let animal = ANIMALS[usize::from(r[1] & 63)];
    let number = 1000 + u16::from_be_bytes([r[2], r[3]]) % 9000;
    Ok(format!("{adjective}-{animal}-{number}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_usernames_are_valid_handles() {
        for _ in 0..200 {
            let name = generate_username().unwrap();
            crate::RootId::parse(&format!("{name}@example.com"))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(name.split('-').count(), 3, "{name}");
        }
    }

    #[test]
    fn the_word_lists_have_no_duplicates() {
        let mut a = ADJECTIVES.to_vec();
        a.sort_unstable();
        a.dedup();
        assert_eq!(a.len(), 64);
        let mut b = ANIMALS.to_vec();
        b.sort_unstable();
        b.dedup();
        assert_eq!(b.len(), 64);
    }
}
