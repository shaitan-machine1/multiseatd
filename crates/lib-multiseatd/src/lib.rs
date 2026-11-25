//! Explicitly routed synchronous clients. No executor, background thread or autostart.
pub mod contract;
mod id;
pub mod launch;
mod refresh;
pub use contract::{
    ContextInfo, DEFAULT_TIMEOUT, ErrorKind, INTERFACE_NAME, INTROSPECTION, OBJECT_PATH, bus_name,
};
pub use id::{ContextId, InvalidId};
pub use refresh::{
    RefreshError, RefreshStage, SeatFailure, refresh_devices, refresh_devices_with_timeout,
};

use dbus::arg::{AppendAll, ReadAll};
use dbus::blocking::{BlockingSender, Connection};
use std::cell::Cell;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::time::{Duration, Instant};

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
    pub handle: u32,
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
    seat: String,
    name: String,
    owner: String,
    buffered: Cell<bool>,
}
impl Client {
    pub fn system(seat: &str) -> Result<Self, dbus::Error> {
        Self::system_with_timeout(seat, DEFAULT_TIMEOUT)
    }
    pub fn system_with_timeout(seat: &str, timeout: Duration) -> Result<Self, dbus::Error> {
        validate(seat, timeout)?;
        Self::from_channel(
            dbus::channel::Channel::get_private(dbus::channel::BusType::System)?,
            seat,
            timeout,
        )
    }
    /// Explicit private-bus/test integration. Never changes the process environment.
    pub fn for_address(address: &str, seat: &str, timeout: Duration) -> Result<Self, dbus::Error> {
        validate(seat, timeout)?;
        let mut channel = dbus::channel::Channel::open_private(address)?;
        channel.register()?;
        Self::from_channel(channel, seat, timeout)
    }
    pub fn from_channel(
        mut channel: dbus::channel::Channel,
        seat: &str,
        timeout: Duration,
    ) -> Result<Self, dbus::Error> {
        let name = validate(seat, timeout)?;
        channel.set_watch_enabled(true);
        let connection = Connection::from(channel);
        let deadline = Instant::now() + timeout;
        let (owner,): (String,) =
            bus_call(&connection, remaining(deadline)?, "GetNameOwner", (&name,))?;
        if !owner.starts_with(':') {
            return Err(ErrorKind::NotAuthorized.error("invalid unique bus owner"));
        }
        let (uid,): (u32,) = bus_call(
            &connection,
            remaining(deadline)?,
            "GetConnectionUnixUser",
            (&owner,),
        )?;
        if uid != 0 {
            return Err(ErrorKind::NotAuthorized.error("seat service is not root-owned"));
        }
        Ok(Self {
            connection,
            timeout,
            seat: seat.into(),
            name,
            owner,
            buffered: Cell::new(true),
        })
    }
    pub fn seat(&self) -> &str {
        &self.seat
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
    pub fn verify_owner(&self) -> Result<(), dbus::Error> {
        self.verify_owner_until(Instant::now() + self.timeout)
    }
    fn verify_owner_until(&self, deadline: Instant) -> Result<(), dbus::Error> {
        self.buffered.set(true);
        let (current,): (String,) = bus_call(
            &self.connection,
            remaining(deadline)?,
            "GetNameOwner",
            (&self.name,),
        )?;
        if current != self.owner {
            return Err(
                ErrorKind::NotReady.error("seat service owner changed; create a new client")
            );
        }
        Ok(())
    }
    fn call<A: AppendAll, R: ReadAll>(&self, method: &str, args: A) -> Result<R, dbus::Error> {
        let deadline = Instant::now() + self.timeout;
        self.verify_owner_until(deadline)?;
        let mut message =
            dbus::Message::new_method_call(&self.owner, OBJECT_PATH, INTERFACE_NAME, method)
                .map_err(|error| dbus::Error::new_failed(&error))?;
        message.set_auto_start(false);
        message.append_all(args);
        // Preserve the actual remote error category/message, including CriticalFailure.
        self.connection
            .send_with_reply_and_block(message, remaining(deadline)?)?
            .read_all()
    }
    pub fn create_context(&self, vt: u32) -> Result<Context, dbus::Error> {
        let (fd, text): (dbus::arg::OwnedFd, String) = self.call("CreateContext", (vt,))?;
        let id = text
            .parse()
            .map_err(|error: InvalidId| dbus::Error::new_failed(&error.to_string()))?;
        Ok(Context {
            id,
            authority: received(fd)?,
        })
    }
    pub fn activate_context(&self, id: ContextId) -> Result<(), dbus::Error> {
        self.id_call("ActivateContext", id)
    }
    pub fn deactivate_context(&self, id: ContextId) -> Result<(), dbus::Error> {
        self.id_call("DeactivateContext", id)
    }
    pub fn move_to_foreground(&self, id: ContextId) -> Result<(), dbus::Error> {
        self.id_call("MoveToForeground", id)
    }
    pub fn remove_context_by_id(&self, id: ContextId) -> Result<(), dbus::Error> {
        self.id_call("RemoveContextById", id)
    }
    fn id_call(&self, method: &str, id: ContextId) -> Result<(), dbus::Error> {
        self.call(method, (id.to_string(),))
    }
    pub fn remove_context(&self, authority: BorrowedFd<'_>) -> Result<(), dbus::Error> {
        self.call("RemoveContext", (argument(authority)?,))
    }
    pub fn add_acl_grant(&self, authority: BorrowedFd<'_>, uid: u32) -> Result<(), dbus::Error> {
        self.call("AddAclGrant", (argument(authority)?, uid))
    }
    pub fn remove_acl_grant(&self, authority: BorrowedFd<'_>, uid: u32) -> Result<(), dbus::Error> {
        self.call("RemoveAclGrant", (argument(authority)?, uid))
    }
    pub fn create_connection(
        &self,
        authority: BorrowedFd<'_>,
    ) -> Result<SeatConnection, dbus::Error> {
        let (fd, handle): (dbus::arg::OwnedFd, u32) =
            self.call("CreateConnection", (argument(authority)?,))?;
        if handle > i32::MAX as u32 {
            return Err(dbus::Error::new_failed("invalid connection handle"));
        }
        Ok(SeatConnection {
            handle,
            descriptor: received(fd)?,
        })
    }
    pub fn seat_metadata(&self, authority: BorrowedFd<'_>) -> Result<(String, u32), dbus::Error> {
        let metadata: (String, u32) = self.call("GetSeatMetadata", (argument(authority)?,))?;
        if metadata.0 != self.seat || metadata.1 > 63 {
            return Err(dbus::Error::new_failed("invalid or wrong-seat metadata"));
        }
        Ok(metadata)
    }
    pub fn get_context(&self, authority: BorrowedFd<'_>) -> Result<ContextInfo, dbus::Error> {
        let (info,) = self.call("GetContext", (argument(authority)?,))?;
        Ok(info)
    }
    pub fn get_context_by_master_pid(
        &self,
        pid: u32,
        start_time: u64,
    ) -> Result<ContextInfo, dbus::Error> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(ErrorKind::InvalidArgument.error("invalid master PID"));
        }
        let (context,) = self.call("GetContextByMasterPid", (pid, start_time))?;
        Ok(context)
    }
    pub fn list_contexts(&self) -> Result<Vec<ContextInfo>, dbus::Error> {
        let (contexts,) = self.call("ListContexts", ())?;
        Ok(contexts)
    }
    pub fn remove_unassigned_devices(&self) -> Result<(), dbus::Error> {
        self.call("RemoveUnassignedDevices", ())
    }
    pub fn add_assigned_devices(&self) -> Result<(), dbus::Error> {
        self.call("AddAssignedDevices", ())
    }
    /// Public coalesced requery hints. The caller explicitly drives dispatch().
    pub fn subscribe(
        &self,
        mut callback: impl FnMut(u64) + Send + 'static,
    ) -> Result<dbus::channel::Token, dbus::Error> {
        self.verify_owner()?;
        let rule = dbus::message::MatchRule::new_signal(INTERFACE_NAME, "StateChanged")
            .with_path(OBJECT_PATH)
            .with_sender(self.owner.clone());
        let token = self
            .connection
            .add_match(rule, move |(revision,): (u64,), _, _| {
                callback(revision);
                true
            })?;
        if let Err(error) = self.verify_owner() {
            let _ = self.connection.remove_match(token);
            return Err(error);
        }
        Ok(token)
    }
    /// Caller-owned poll state. A true buffered flag requires immediate dispatch;
    /// there are no asynchronous RPC timers, so the transport timeout is None.
    pub fn poll_state(&self) -> (dbus::channel::Watch, bool, Option<Duration>) {
        (self.connection.channel().watch(), self.buffered.get(), None)
    }
    /// Dispatch at most limit messages without blocking. True means more work may remain.
    pub fn dispatch(&self, limit: usize) -> Result<bool, dbus::Error> {
        if !(1..=256).contains(&limit) {
            return Err(ErrorKind::InvalidArgument.error("dispatch limit must be 1..256"));
        }
        for _ in 0..limit {
            if !self.connection.process(Duration::ZERO)? {
                self.buffered.set(false);
                return Ok(false);
            }
        }
        self.buffered.set(true);
        Ok(true)
    }
    pub fn process(&self, timeout: Duration) -> Result<bool, dbus::Error> {
        let result = self.connection.process(timeout);
        self.buffered.set(result.as_ref().copied().unwrap_or(false));
        result
    }
}

/// Local endpoint shutdown only. This neither closes the borrowed FD nor attests remote revocation.
pub fn remove_connection(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    if unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_RDWR) } == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn validate(seat: &str, timeout: Duration) -> Result<String, dbus::Error> {
    if timeout.is_zero() || timeout > Duration::from_secs(3600) {
        return Err(
            ErrorKind::InvalidArgument.error("timeout must be positive and at most one hour")
        );
    }
    bus_name(seat).map_err(|error| ErrorKind::InvalidArgument.error(&error.to_string()))
}
fn remaining(deadline: Instant) -> Result<Duration, dbus::Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            dbus::Error::new_custom(
                "org.freedesktop.DBus.Error.Timeout",
                "client operation deadline expired",
            )
        })
}
fn bus_call<A: AppendAll, R: ReadAll>(
    connection: &Connection,
    timeout: Duration,
    method: &str,
    args: A,
) -> Result<R, dbus::Error> {
    let mut message = dbus::Message::new_method_call(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        method,
    )
    .map_err(|error| dbus::Error::new_failed(&error))?;
    message.set_auto_start(false);
    message.append_all(args);
    connection
        .send_with_reply_and_block(message, timeout)?
        .read_all()
}
fn argument(fd: BorrowedFd<'_>) -> Result<dbus::arg::OwnedFd, dbus::Error> {
    let fd = duplicate(fd).map_err(|e| dbus::Error::new_failed(&e.to_string()))?;
    Ok(unsafe { dbus::arg::OwnedFd::from_raw_fd(fd.into_raw_fd()) })
}
fn duplicate(fd: BorrowedFd<'_>) -> std::io::Result<OwnedFd> {
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}
fn received(fd: dbus::arg::OwnedFd) -> Result<OwnedFd, dbus::Error> {
    let fd = unsafe { OwnedFd::from_raw_fd(fd.into_raw_fd()) };
    let fd = duplicate(fd.as_fd()).map_err(|e| dbus::Error::new_failed(&e.to_string()))?;
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result == -1 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(dbus::Error::new_failed(
            "returned FD is not a credential-bearing local socket",
        ));
    }
    let credentials = unsafe { credentials.assume_init() };
    let mut kind = 0i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut i32).cast(),
            &mut length,
        )
    };
    if result == -1 || kind != libc::SOCK_STREAM || credentials.uid != 0 || credentials.pid <= 0 {
        return Err(dbus::Error::new_failed(
            "returned FD is not a root-peer stream socket",
        ));
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    #[test]
    fn local_shutdown_affects_duplicates_but_does_not_close_borrowed_fd() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let other = socket.try_clone().unwrap();
        remove_connection(socket.as_fd()).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        assert!(unsafe { libc::fcntl(other.as_raw_fd(), libc::F_GETFD) } >= 0);
        assert!(unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) } >= 0);
    }
    #[test]
    fn closing_only_a_parent_copy_keeps_child_endpoint_alive() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let other = socket.try_clone().unwrap();
        drop(socket);
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(other);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}
