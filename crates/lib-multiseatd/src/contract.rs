//! Context protocol contract, shared without daemon or executor dependencies.

pub const BUS_NAME: &str = "org.decoupling.multiseatd2";
pub const OBJECT_PATH: &str = "/org/decoupling/multiseatd2";
pub const INTERFACE_NAME: &str = "org.decoupling.multiseatd2.Manager";
pub const INTROSPECTION: &str = include_str!("../dbus/org.decoupling.multiseatd2.Manager.xml");

pub type SeatRow = (String, u32, bool, String, String, String, String);
pub type ContextRow = (
    String,
    String,
    String,
    Vec<u32>,
    Vec<String>,
    bool,
    bool,
    String,
);
pub type ConnectionRow = (String, String, String, String, String);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    InvalidArgument,
    AccessDenied,
    UnknownSeat,
    UnknownContext,
    UnknownConnection,
    ContextRemoving,
    ResourceConflict,
    LimitExceeded,
    TransitionPending,
    CleanupPending,
    BackendFailure,
}

impl ErrorKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidArgument => "org.decoupling.multiseatd2.Error.InvalidArgument",
            Self::AccessDenied => "org.decoupling.multiseatd2.Error.AccessDenied",
            Self::UnknownSeat => "org.decoupling.multiseatd2.Error.UnknownSeat",
            Self::UnknownContext => "org.decoupling.multiseatd2.Error.UnknownContext",
            Self::UnknownConnection => "org.decoupling.multiseatd2.Error.UnknownConnection",
            Self::ContextRemoving => "org.decoupling.multiseatd2.Error.ContextRemoving",
            Self::ResourceConflict => "org.decoupling.multiseatd2.Error.ResourceConflict",
            Self::LimitExceeded => "org.decoupling.multiseatd2.Error.LimitExceeded",
            Self::TransitionPending => "org.decoupling.multiseatd2.Error.TransitionPending",
            Self::CleanupPending => "org.decoupling.multiseatd2.Error.CleanupPending",
            Self::BackendFailure => "org.decoupling.multiseatd2.Error.BackendFailure",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbus::arg::Arg;

    #[test]
    fn context_contract_has_exact_status_and_descriptor_signatures() {
        for (actual, expected) in [
            (Vec::<SeatRow>::signature().to_string(), "a(subssss)"),
            (Vec::<ContextRow>::signature().to_string(), "a(sssauasbbs)"),
            (Vec::<ConnectionRow>::signature().to_string(), "a(sssss)"),
            (dbus::arg::OwnedFd::signature().to_string(), "h"),
        ] {
            assert_eq!(actual, expected);
            assert!(INTROSPECTION.contains(&format!("type=\"{expected}\"")));
        }
        assert!(INTROSPECTION.contains(INTERFACE_NAME));
        assert!(!INTROSPECTION.contains("CreateClient"));
        assert!(!INTROSPECTION.contains("options"));
    }
}
