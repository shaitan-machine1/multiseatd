//! Opaque v2 identifiers. Possessing an identifier grants no authority.

use std::{fmt, str::FromStr};
use uuid::{Uuid, Variant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidId;

impl fmt::Display for InvalidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a canonical UUIDv4")
    }
}

impl std::error::Error for InvalidId {}

macro_rules! identifier {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Generate an ID, not an authentication token.
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = InvalidId;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if value.len() != 36 {
                    return Err(InvalidId);
                }
                let uuid = Uuid::parse_str(value).map_err(|_| InvalidId)?;
                if uuid.get_variant() != Variant::RFC4122
                    || uuid.get_version_num() != 4
                    || uuid.to_string() != value
                {
                    return Err(InvalidId);
                }
                Ok(Self(uuid))
            }
        }
    };
}

identifier!(ContextId);
identifier!(ConnectionId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identifiers_round_trip_without_becoming_interchangeable_types() {
        let context = ContextId::generate();
        let connection = ConnectionId::generate();
        assert_eq!(context.to_string().parse(), Ok(context));
        assert_eq!(connection.to_string().parse(), Ok(connection));
        assert_ne!(context.to_string(), connection.to_string());
    }

    #[test]
    fn reject_noncanonical_wrong_version_and_non_rfc_identifiers() {
        let valid = "aabbccdd-1234-4567-89ab-0123456789ab";
        assert!(valid.parse::<ContextId>().is_ok());
        for invalid in [
            String::new(),
            valid.to_uppercase(),
            valid.replace('-', ""),
            format!("{{{valid}}}"),
            format!("urn:uuid:{valid}"),
            valid.replace("4567", "7567"),
            valid.replace("89ab", "09ab"),
            "00000000-0000-0000-0000-000000000000".into(),
            "x".repeat(4096),
        ] {
            assert_eq!(invalid.parse::<ContextId>(), Err(InvalidId));
            assert_eq!(invalid.parse::<ConnectionId>(), Err(InvalidId));
        }
    }
}
