//! Context IDs are canonical UUIDv7 identifiers, never capabilities.
use std::{fmt, str::FromStr};
use uuid::{Uuid, Variant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidId;
impl fmt::Display for InvalidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a canonical lowercase UUIDv7")
    }
}
impl std::error::Error for InvalidId {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContextId(Uuid);
impl ContextId {
    pub fn generate() -> Self {
        Self(Uuid::now_v7())
    }
}
impl fmt::Display for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for ContextId {
    type Err = InvalidId;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 36 {
            return Err(InvalidId);
        }
        let uuid = Uuid::parse_str(value).map_err(|_| InvalidId)?;
        if uuid.get_variant() != Variant::RFC4122
            || uuid.get_version_num() != 7
            || uuid.to_string() != value
        {
            return Err(InvalidId);
        }
        Ok(Self(uuid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_ids_are_distinct_canonical_v7() {
        let first = ContextId::generate();
        assert_eq!(first.to_string().parse(), Ok(first));
        assert_ne!(first, ContextId::generate());
        assert_eq!(first.0.get_version_num(), 7);
    }
    #[test]
    fn reject_every_noncanonical_or_wrong_version_form() {
        let valid = "aabbccdd-1234-7567-89ab-0123456789ab";
        assert!(valid.parse::<ContextId>().is_ok());
        for invalid in [
            String::new(),
            valid.to_uppercase(),
            valid.replace('-', ""),
            format!("{{{valid}}}"),
            format!("urn:uuid:{valid}"),
            valid.replace("7567", "4567"),
            valid.replace("89ab", "09ab"),
            "00000000-0000-0000-0000-000000000000".into(),
            "x".repeat(4096),
        ] {
            assert_eq!(invalid.parse::<ContextId>(), Err(InvalidId));
        }
    }
}
