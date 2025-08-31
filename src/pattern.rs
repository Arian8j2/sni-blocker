use anyhow::ensure;
use std::str::FromStr;

const WILD_CARD_CHAR: char = '*';

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Pattern {
    Exact(String),
    Suffix(String),
    Prefix(String),
    Contain(String),
}

impl Pattern {
    pub fn compile(pattern_str: &str) -> anyhow::Result<Self> {
        let pattern = if pattern_str.contains(WILD_CARD_CHAR) {
            let wildcard_char_count = pattern_str
                .chars()
                .filter(|char| *char == WILD_CARD_CHAR)
                .count();
            let chars = pattern_str.chars().collect::<Vec<_>>();
            let first_char_is_wildcard = *chars.first().unwrap() == WILD_CARD_CHAR;
            let last_char_is_wildcard = chars
                .last()
                .is_some_and(|last_char| *last_char == WILD_CARD_CHAR);
            ensure!(
                (wildcard_char_count == 1 && (first_char_is_wildcard || last_char_is_wildcard))
                    || (wildcard_char_count == 2
                        && (first_char_is_wildcard && last_char_is_wildcard)),
                "wildcard character can only be used as first and last character"
            );

            let without_wild_card = pattern_str.replace('*', "");
            if wildcard_char_count == 1 {
                if first_char_is_wildcard {
                    Self::Suffix(without_wild_card)
                } else {
                    Self::Prefix(without_wild_card)
                }
            } else {
                Self::Contain(without_wild_card)
            }
        } else {
            Self::Exact(pattern_str.to_owned())
        };
        Ok(pattern)
    }

    pub fn is_match(&self, haystack: &str) -> bool {
        match self {
            Self::Exact(pattern) => haystack == pattern,
            Self::Suffix(pattern) => haystack.ends_with(pattern),
            Self::Prefix(pattern) => haystack.starts_with(pattern),
            Self::Contain(pattern) => haystack.contains(pattern),
        }
    }
}

impl FromStr for Pattern {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::compile(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_compile() {
        assert_eq!(
            Pattern::compile("www.google.com").unwrap(),
            Pattern::Exact("www.google.com".to_owned())
        );
        assert_eq!(
            Pattern::compile("*.google.com").unwrap(),
            Pattern::Suffix(".google.com".to_owned())
        );
        assert_eq!(
            Pattern::compile("www.google.*").unwrap(),
            Pattern::Prefix("www.google.".to_owned())
        );
        assert_eq!(
            Pattern::compile("*google*").unwrap(),
            Pattern::Contain("google".to_owned())
        );

        assert!(Pattern::compile("*goo*gle*").is_err());
        assert!(Pattern::compile("*goo*gle").is_err());
        assert!(Pattern::compile("www.*.com").is_err());
    }

    #[test]
    fn test_pattern_match() {
        assert!(Pattern::compile("www.google.com")
            .unwrap()
            .is_match("www.google.com"));

        assert!(Pattern::compile("www.google.*")
            .unwrap()
            .is_match("www.google.de"));
        assert!(!Pattern::compile("www.google.*")
            .unwrap()
            .is_match("google.com"));
        assert!(Pattern::compile("*.google.com")
            .unwrap()
            .is_match("cdn.google.com"));

        assert!(Pattern::compile("*google*").unwrap().is_match("google.com"));
        assert!(Pattern::compile("*google*")
            .unwrap()
            .is_match("www.google.de"));
        assert!(Pattern::compile("*google*")
            .unwrap()
            .is_match("idkgoogledg.com"));
    }
}
