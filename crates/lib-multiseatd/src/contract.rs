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
    fn per_seat_target_contract_has_only_context_information() {
        // Freeze the target before switching the daemon/client together. The
        // currently running global v2 implementation still uses INTROSPECTION.
        let target = include_str!("../dbus/org.SGLogin.Multiseatd1.Manager.xml");
        type ContextWire = (
            String,
            Vec<u32>,
            Vec<u32>,
            bool,
            bool,
            String,
            bool,
            bool,
            Vec<String>,
        );
        assert_eq!(ContextWire::signature().to_string(), "(sauaubbsbbas)");
        assert_eq!(
            Vec::<ContextWire>::signature().to_string(),
            "a(sauaubbsbbas)"
        );
        assert!(target.contains("org.SGLogin.Multiseatd1.Manager"));
        let methods = [
            "CreateContext",
            "ActivateContext",
            "DeactivateContext",
            "RemoveContext",
            "GrantACL",
            "RevokeACL",
            "CreateConnection",
            "GetContext",
            "GetSeatMetadata",
            "ActivateContextById",
            "DeactivateContextById",
            "RemoveContextById",
            "ListContexts",
            "WaitUntilDeviceDisowned",
        ];
        assert_eq!(target.matches("<method name=").count(), methods.len());
        for method in methods {
            assert!(target.contains(&format!("<method name=\"{method}\">")));
        }
        for removed in [
            "RemoveConnection",
            "ListConnections",
            "GetSeatState",
            "ListSeats",
            "GrantAccess",
            "RevokeAccess",
        ] {
            assert!(!target.contains(&format!("<method name=\"{removed}\"")));
        }
        assert!(target.contains("name=\"syspath\" type=\"s\" direction=\"in\""));
        assert!(target.contains("name=\"handle\" type=\"u\" direction=\"out\""));
        assert_eq!(target.matches("<signal name=").count(), 1);
    }

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
