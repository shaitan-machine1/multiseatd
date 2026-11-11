//! The identical per-seat wire contract used by both daemon builds.
use crate::ContextId;
use dbus::Signature;
use dbus::arg::{Append, Arg, ArgType, Get, Iter, IterAppend};
use std::fmt;

pub const BUS_PREFIX: &str = "org.SGLogin.Multiseatd1.Seat_";
pub const OBJECT_PATH: &str = "/org/SGLogin/Multiseatd1";
pub const INTERFACE_NAME: &str = "org.SGLogin.Multiseatd1.Manager";
pub const INTROSPECTION: &str = include_str!("../dbus/org.SGLogin.Multiseatd1.Manager.xml");
pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const METHODS: [&str; 14] = [
    "CreateContext",
    "ActivateContext",
    "DeactivateContext",
    "RemoveContext",
    "AddAclGrant",
    "RemoveAclGrant",
    "CreateConnection",
    "GetContext",
    "GetSeatMetadata",
    "RemoveContextById",
    "ListContexts",
    "MoveToForeground",
    "RemoveUnassignedDevices",
    "AddAssignedDevices",
];

pub fn bus_name(seat: &str) -> Result<String, InvalidSeat> {
    if !seat.starts_with("seat")
        || seat.len() > 63
        || !seat
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(InvalidSeat);
    }
    let mut name = String::from(BUS_PREFIX);
    for byte in seat.bytes() {
        if byte.is_ascii_alphanumeric() {
            name.push(char::from(byte));
        } else {
            use fmt::Write;
            write!(name, "_{byte:02x}").expect("writing a String");
        }
    }
    Ok(name)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSeat;
impl fmt::Display for InvalidSeat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a seat-prefixed ASCII name of at most 63 bytes")
    }
}
impl std::error::Error for InvalidSeat {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextInfo {
    pub id: ContextId,
    pub vt: u32,
    pub desired_uids: Vec<u32>,
    pub connection_handles: Vec<u32>,
    pub active: bool,
    pub foreground: bool,
    pub effective: bool,
}
type ContextWire = (String, u32, Vec<u32>, Vec<u32>, bool, bool, bool);
impl Arg for ContextInfo {
    const ARG_TYPE: ArgType = ArgType::Struct;
    fn signature() -> Signature<'static> {
        ContextWire::signature()
    }
}
impl Append for ContextInfo {
    fn append_by_ref(&self, i: &mut IterAppend<'_>) {
        (
            self.id.to_string(),
            self.vt,
            &self.desired_uids,
            &self.connection_handles,
            self.active,
            self.foreground,
            self.effective,
        )
            .append_by_ref(i);
    }
}
impl<'a> Get<'a> for ContextInfo {
    fn get(i: &mut Iter<'a>) -> Option<Self> {
        let (id, vt, desired_uids, connection_handles, active, foreground, effective) =
            ContextWire::get(i)?;
        if vt > 63
            || !sorted_unique(&desired_uids, 64)
            || !sorted_unique(&connection_handles, 64)
            || connection_handles.iter().any(|&h| h > i32::MAX as u32)
            || (vt == 0 && foreground)
            || (effective && !active)
        {
            return None;
        }
        Some(Self {
            id: id.parse().ok()?,
            vt,
            desired_uids,
            connection_handles,
            active,
            foreground,
            effective,
        })
    }
}
fn sorted_unique(values: &[u32], limit: usize) -> bool {
    values.len() <= limit && values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    InvalidArgument,
    NotAuthorized,
    NotFound,
    NotReady,
    Busy,
    LimitExceeded,
    Pending,
    Stopping,
    DeviceRemovalFailed,
    DeviceAdditionFailed,
    VTActivationFailed,
    CriticalFailure,
}
impl ErrorKind {
    pub const ALL: [Self; 12] = [
        Self::InvalidArgument,
        Self::NotAuthorized,
        Self::NotFound,
        Self::NotReady,
        Self::Busy,
        Self::LimitExceeded,
        Self::Pending,
        Self::Stopping,
        Self::DeviceRemovalFailed,
        Self::DeviceAdditionFailed,
        Self::VTActivationFailed,
        Self::CriticalFailure,
    ];
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidArgument => "org.SGLogin.Multiseatd1.Error.InvalidArgument",
            Self::NotAuthorized => "org.SGLogin.Multiseatd1.Error.NotAuthorized",
            Self::NotFound => "org.SGLogin.Multiseatd1.Error.NotFound",
            Self::NotReady => "org.SGLogin.Multiseatd1.Error.NotReady",
            Self::Busy => "org.SGLogin.Multiseatd1.Error.Busy",
            Self::LimitExceeded => "org.SGLogin.Multiseatd1.Error.LimitExceeded",
            Self::Pending => "org.SGLogin.Multiseatd1.Error.Pending",
            Self::Stopping => "org.SGLogin.Multiseatd1.Error.Stopping",
            Self::DeviceRemovalFailed => "org.SGLogin.Multiseatd1.Error.DeviceRemovalFailed",
            Self::DeviceAdditionFailed => "org.SGLogin.Multiseatd1.Error.DeviceAdditionFailed",
            Self::VTActivationFailed => "org.SGLogin.Multiseatd1.Error.VTActivationFailed",
            Self::CriticalFailure => "org.SGLogin.Multiseatd1.Error.CriticalFailure",
        }
    }
    pub fn error(self, message: &str) -> dbus::Error {
        dbus::Error::new_custom(self.name(), message)
    }
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_common_surface_and_seven_field_record() {
        assert_eq!(ContextInfo::signature().to_string(), "(suauaubbb)");
        assert_eq!(Vec::<ContextInfo>::signature().to_string(), "a(suauaubbb)");
        assert_eq!(INTROSPECTION.matches("<method name=").count(), 14);
        for name in METHODS {
            assert!(INTROSPECTION.contains(&format!("name=\"{name}\"")));
        }
        assert_eq!(INTROSPECTION.matches("<signal name=").count(), 1);
        for removed in [
            "GrantACL",
            "RevokeACL",
            "WaitUntilDeviceDisowned",
            "ActivateContextById",
            "DeactivateContextById",
            "ListConnections",
            "ListSeats",
        ] {
            assert!(!INTROSPECTION.contains(&format!("name=\"{removed}\"")));
        }
        assert!(INTROSPECTION.contains("name=\"vt\" type=\"u\" direction=\"in\""));
        assert_eq!(ErrorKind::ALL.len(), 12);
        for kind in ErrorKind::ALL {
            assert_eq!(ErrorKind::from_name(kind.name()), Some(kind));
        }
    }
    #[test]
    fn seat_encoding_is_injective_case_sensitive_and_bounded() {
        for (seat, encoded) in [
            ("seat0", "seat0"),
            ("seat-usb_2", "seat_2dusb_5f2"),
            ("seat_2d", "seat_5f2d"),
            ("seatABC", "seatABC"),
            ("seat", "seat"),
        ] {
            assert_eq!(bus_name(seat).unwrap(), format!("{BUS_PREFIX}{encoded}"));
        }
        for bad in [
            "",
            "other",
            "seat.a",
            "seat/0",
            "seaté",
            &format!("seat{}", "a".repeat(60)),
        ] {
            assert!(bus_name(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn record_roundtrip_and_invalid_wire_rejection() {
        let info = ContextInfo {
            id: ContextId::generate(),
            vt: 7,
            desired_uids: vec![1000],
            connection_handles: vec![5, 7],
            active: true,
            foreground: true,
            effective: true,
        };
        let message = dbus::Message::new_signal(OBJECT_PATH, INTERFACE_NAME, "Fixture")
            .unwrap()
            .append1(info.clone());
        assert_eq!(message.read1::<ContextInfo>().unwrap(), info);
        let malformed = (
            info.id.to_string(),
            7u32,
            vec![1000u32, 1000],
            vec![5u32],
            true,
            true,
            true,
        );
        let message = dbus::Message::new_signal(OBJECT_PATH, INTERFACE_NAME, "Fixture")
            .unwrap()
            .append1(malformed);
        assert!(message.read1::<ContextInfo>().is_err());
    }
}
