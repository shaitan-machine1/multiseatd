//! Synchronous capability-based multiseatd v2 client. No executor or worker thread.
pub mod contract;
mod id;
pub mod launch;
pub use contract::{
    BUS_NAME, ConnectionRow, ContextRow, ErrorKind, INTERFACE_NAME, INTROSPECTION, OBJECT_PATH,
    SeatRow,
};
pub use id::{ConnectionId, ContextId, InvalidId};

use dbus::blocking::{Connection, Proxy};
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::time::Duration;

#[derive(Debug)]
pub struct Context {
    pub id: ContextId,
    authority: OwnedFd,
}
impl AsFd for Context {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.authority.as_fd()
    }
}
impl Context {
    pub fn into_authority(self) -> OwnedFd {
        self.authority
    }
}
#[derive(Debug)]
pub struct SeatConnection {
    pub id: ConnectionId,
    descriptor: OwnedFd,
}
impl AsFd for SeatConnection {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}
impl SeatConnection {
    pub fn into_fd(self) -> OwnedFd {
        self.descriptor
    }
}

pub struct Client {
    connection: Connection,
    timeout: Duration,
}
impl Client {
    pub fn system(timeout: Duration) -> Result<Self, dbus::Error> {
        Ok(Self {
            connection: Connection::new_system()?,
            timeout,
        })
    }
    pub fn session(timeout: Duration) -> Result<Self, dbus::Error> {
        Ok(Self {
            connection: Connection::new_session()?,
            timeout,
        })
    }
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
    fn proxy(&self) -> Proxy<'_, &Connection> {
        self.connection
            .with_proxy(BUS_NAME, OBJECT_PATH, self.timeout)
    }
    pub fn create_context(&self, seat: &str) -> Result<Context, dbus::Error> {
        let (fd, id): (dbus::arg::OwnedFd, String) =
            self.proxy()
                .method_call(INTERFACE_NAME, "CreateContext", (seat,))?;
        Ok(Context {
            id: parse(&id)?,
            authority: received(fd)?,
        })
    }
    pub fn activate_context(&self, authority: BorrowedFd<'_>) -> Result<(), dbus::Error> {
        self.authority_call("ActivateContext", authority)
    }
    pub fn deactivate_context(&self, authority: BorrowedFd<'_>) -> Result<(), dbus::Error> {
        self.authority_call("DeactivateContext", authority)
    }
    pub fn remove_context(&self, authority: BorrowedFd<'_>) -> Result<(), dbus::Error> {
        self.authority_call("RemoveContext", authority)
    }
    fn authority_call(&self, method: &str, authority: BorrowedFd<'_>) -> Result<(), dbus::Error> {
        self.proxy()
            .method_call(INTERFACE_NAME, method, (argument(authority)?,))
    }
    pub fn grant_access(&self, authority: BorrowedFd<'_>, uid: u32) -> Result<(), dbus::Error> {
        self.proxy()
            .method_call(INTERFACE_NAME, "GrantAccess", (argument(authority)?, uid))
    }
    pub fn revoke_access(&self, authority: BorrowedFd<'_>, uid: u32) -> Result<(), dbus::Error> {
        self.proxy()
            .method_call(INTERFACE_NAME, "RevokeAccess", (argument(authority)?, uid))
    }
    pub fn create_connection(
        &self,
        authority: BorrowedFd<'_>,
    ) -> Result<SeatConnection, dbus::Error> {
        let (fd, id): (dbus::arg::OwnedFd, String) = self.proxy().method_call(
            INTERFACE_NAME,
            "CreateConnection",
            (argument(authority)?,),
        )?;
        Ok(SeatConnection {
            id: parse(&id)?,
            descriptor: received(fd)?,
        })
    }
    pub fn remove_connection(
        &self,
        authority: BorrowedFd<'_>,
        id: ConnectionId,
    ) -> Result<(), dbus::Error> {
        self.proxy().method_call(
            INTERFACE_NAME,
            "RemoveConnection",
            (argument(authority)?, id.to_string()),
        )
    }
    /// Only this context's seat name/VT metadata, never another context's IDs.
    pub fn seat_metadata(&self, authority: BorrowedFd<'_>) -> Result<(String, u32), dbus::Error> {
        self.proxy()
            .method_call(INTERFACE_NAME, "GetSeatMetadata", (argument(authority)?,))
    }
    pub fn get_context(&self, authority: BorrowedFd<'_>) -> Result<ContextRow, dbus::Error> {
        let (row,): (ContextRow,) =
            self.proxy()
                .method_call(INTERFACE_NAME, "GetContext", (argument(authority)?,))?;
        Ok(row)
    }
    pub fn activate_context_by_id(&self, id: ContextId) -> Result<(), dbus::Error> {
        self.id_call("ActivateContextById", &id.to_string())
    }
    pub fn deactivate_context_by_id(&self, id: ContextId) -> Result<(), dbus::Error> {
        self.id_call("DeactivateContextById", &id.to_string())
    }
    pub fn remove_context_by_id(&self, id: ContextId) -> Result<(), dbus::Error> {
        self.id_call("RemoveContextById", &id.to_string())
    }
    pub fn remove_connection_by_id(&self, id: ConnectionId) -> Result<(), dbus::Error> {
        self.id_call("RemoveConnectionById", &id.to_string())
    }
    fn id_call(&self, method: &str, id: &str) -> Result<(), dbus::Error> {
        self.proxy().method_call(INTERFACE_NAME, method, (id,))
    }
    pub fn list_seats(&self) -> Result<Vec<SeatRow>, dbus::Error> {
        let (rows,): (Vec<SeatRow>,) = self.proxy().method_call(INTERFACE_NAME, "ListSeats", ())?;
        Ok(rows)
    }
    pub fn list_contexts(&self) -> Result<Vec<ContextRow>, dbus::Error> {
        let (rows,): (Vec<ContextRow>,) =
            self.proxy()
                .method_call(INTERFACE_NAME, "ListContexts", ())?;
        Ok(rows)
    }
    pub fn list_connections(&self) -> Result<Vec<ConnectionRow>, dbus::Error> {
        let (rows,): (Vec<ConnectionRow>,) =
            self.proxy()
                .method_call(INTERFACE_NAME, "ListConnections", ())?;
        Ok(rows)
    }
    pub fn owner(&self) -> Result<String, dbus::Error> {
        let (owner,): (String,) = self
            .connection
            .with_proxy(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                self.timeout,
            )
            .method_call("org.freedesktop.DBus", "GetNameOwner", (BUS_NAME,))?;
        Ok(owner)
    }
    /// Install before querying inventory. Drive callbacks explicitly with process;
    /// restart invalidates this owner-specific subscription and all old handles.
    pub fn subscribe(
        &self,
        mut callback: impl FnMut(u64) + Send + 'static,
    ) -> Result<dbus::channel::Token, dbus::Error> {
        let owner = self.owner()?;
        let rule = dbus::message::MatchRule::new_signal(INTERFACE_NAME, "StateChanged")
            .with_path(OBJECT_PATH)
            .with_sender(owner);
        let token = self
            .connection
            .add_match(rule, move |(revision,): (u64,), _, _| {
                callback(revision);
                true
            })?;
        // Authenticate/register this unique root peer for private signal delivery.
        if let Err(error) = self.list_seats() {
            let _ = self.connection.remove_match(token);
            return Err(error);
        }
        Ok(token)
    }
    pub fn process(&self, timeout: Duration) -> Result<bool, dbus::Error> {
        self.connection.process(timeout)
    }
}
fn parse<T: std::str::FromStr<Err = InvalidId>>(text: &str) -> Result<T, dbus::Error> {
    text.parse()
        .map_err(|error| dbus::Error::new_failed(&format!("invalid daemon ID: {error}")))
}
fn argument(fd: BorrowedFd<'_>) -> Result<dbus::arg::OwnedFd, dbus::Error> {
    let duplicate = duplicate(fd).map_err(|error| dbus::Error::new_failed(&error.to_string()))?;
    Ok(unsafe { dbus::arg::OwnedFd::from_raw_fd(duplicate.into_raw_fd()) })
}
fn duplicate(fd: BorrowedFd<'_>) -> std::io::Result<OwnedFd> {
    use std::os::fd::AsRawFd;
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}
fn received(fd: dbus::arg::OwnedFd) -> Result<OwnedFd, dbus::Error> {
    let received = unsafe { OwnedFd::from_raw_fd(fd.into_raw_fd()) };
    duplicate(received.as_fd()).map_err(|error| dbus::Error::new_failed(&error.to_string()))
}
