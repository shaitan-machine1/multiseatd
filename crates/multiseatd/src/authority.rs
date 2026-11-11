//! Context capabilities: socket identity, anchor lifetime and invalidation.
//!
//! This owns no devices or activation policy. The controller must remove each
//! invalidated context and retain its resource cleanup independently. In
//! particular, evicting a retry tombstone must never discard resource handles.

use libmultiseatd::ContextId;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicI32, Ordering},
};

#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    #[error("invalid or removed context authority")]
    AccessDenied,
    #[error("context authority limit reached")]
    LimitExceeded,
    #[error("authority limits must be nonzero")]
    InvalidLimits,
    #[error("authority socket operation failed: {0}")]
    System(#[from] io::Error),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Cookie(u64);

struct LiveAuthority {
    context: ContextId,
    registration: Registration,
}

/// Resource-local lifetime ownership, never a policy/catalog reference.
#[derive(Clone)]
pub struct Registration {
    anchor: Arc<UnixStream>,
    alive: Arc<AtomicBool>,
    error: Arc<AtomicI32>,
}
impl Registration {
    pub fn is_alive(&self) -> io::Result<bool> {
        let error = self.error.load(Ordering::Acquire);
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        if !self.alive.load(Ordering::Acquire) {
            return Ok(false);
        }
        let ready = match probe(&self.anchor) {
            Ok(ready) => ready,
            Err(error) => {
                self.alive.store(false, Ordering::Release);
                let _ = self.error.compare_exchange(
                    0,
                    error.raw_os_error().unwrap_or(libc::EIO),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                return Err(error);
            }
        };
        if ready.is_some() {
            self.alive.store(false, Ordering::Release);
            return Ok(false);
        }
        Ok(true)
    }
    pub fn invalidate(&self) {
        self.alive.store(false, Ordering::Release);
    }
}

/// The caller owns the returned endpoint, including publication failure cleanup.
/// There is no daemon-held duplicate of this endpoint.
#[derive(Debug)]
pub struct IssuedAuthority {
    pub context: ContextId,
    pub endpoint: OwnedFd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationReason {
    /// Final close and write-side shutdown are intentionally indistinguishable.
    PeerClosed,
    /// The capability is a key, not an application protocol socket.
    UnexpectedData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Invalidation {
    pub context: ContextId,
    pub reason: InvalidationReason,
}

/// Bounded daemon-lifetime authority index. IDs are generated internally, never
/// rebound by a caller. Retry cookies authorize removal only, not other work.
pub struct Authorities {
    live: HashMap<Cookie, LiveAuthority>,
    contexts: HashMap<ContextId, Cookie>,
    retired: HashMap<Cookie, ContextId>,
    retired_order: VecDeque<Cookie>,
    live_limit: usize,
    retired_limit: usize,
}

impl Authorities {
    pub fn new(live_limit: usize, retired_limit: usize) -> Result<Self, AuthorityError> {
        if live_limit == 0 || retired_limit == 0 {
            return Err(AuthorityError::InvalidLimits);
        }
        // Probe required kernel support during initialization, before bus
        // publication, rather than discovering it on the first root request.
        let (_anchor, endpoint) = UnixStream::pair()?;
        identity(endpoint.as_fd())?;
        Ok(Self {
            live: HashMap::new(),
            contexts: HashMap::new(),
            retired: HashMap::new(),
            retired_order: VecDeque::new(),
            live_limit,
            retired_limit,
        })
    }

    /// Register before publication. If publication fails, invalidate this ID;
    /// closing the unreturned endpoint also makes anchor readiness observable.
    pub fn issue(&mut self) -> Result<IssuedAuthority, AuthorityError> {
        if self.live.len() >= self.live_limit {
            return Err(AuthorityError::LimitExceeded);
        }
        let context = ContextId::generate();
        if self.contexts.contains_key(&context) || self.retired.values().any(|id| *id == context) {
            return Err(io::Error::other("generated a duplicate context ID").into());
        }
        // std creates both endpoints atomically with SOCK_CLOEXEC on Linux.
        let (anchor, endpoint) = UnixStream::pair()?;
        anchor.set_nonblocking(true)?;
        let cookie = identity(endpoint.as_fd())?;
        if self.live.contains_key(&cookie) || self.retired.contains_key(&cookie) {
            return Err(io::Error::other("kernel reused a registered socket cookie").into());
        }
        self.live.insert(
            cookie,
            LiveAuthority {
                context,
                registration: Registration {
                    anchor: Arc::new(anchor),
                    alive: Arc::new(AtomicBool::new(true)),
                    error: Arc::new(AtomicI32::new(0)),
                },
            },
        );
        self.contexts.insert(context, cookie);
        Ok(IssuedAuthority {
            context,
            endpoint: endpoint.into(),
        })
    }

    /// Possession is established by the returned endpoint's identity, not the
    /// caller's UID, peer credentials, descriptor number or supplied context ID.
    /// The caller retains ownership of the request's descriptor on every path.
    pub fn resolve(&self, endpoint: BorrowedFd<'_>) -> Result<ContextId, AuthorityError> {
        let cookie = identity(endpoint)?;
        let entry = self.live.get(&cookie).ok_or(AuthorityError::AccessDenied)?;
        // Do not authorize a shut-down/data-bearing capability just because the
        // controller has not consumed its anchor readiness notification yet.
        if !entry.registration.is_alive()? {
            return Err(AuthorityError::AccessDenied);
        }
        Ok(entry.context)
    }

    /// A removed authority can only repeat removal while its bounded tombstone
    /// remains. This never authorizes activation, grants or new connections.
    pub fn resolve_removal(&self, endpoint: BorrowedFd<'_>) -> Result<ContextId, AuthorityError> {
        let cookie = identity(endpoint)?;
        self.live
            .get(&cookie)
            .map(|entry| entry.context)
            .or_else(|| self.retired.get(&cookie).copied())
            .ok_or(AuthorityError::AccessDenied)
    }

    /// Invalidate all copies before scheduling any asynchronous resource cleanup.
    /// Repeated invalidation is harmless; it never recreates an authority.
    pub fn invalidate(&mut self, context: ContextId) -> bool {
        let Some(cookie) = self.contexts.remove(&context) else {
            return false;
        };
        // Dropping the opposite endpoint is safe: no client device descriptor is
        // owned here. Actual device/ACL revocation belongs to the controller.
        if let Some(entry) = self.live.remove(&cookie) {
            entry.registration.invalidate();
        }
        if self.retired.len() == self.retired_limit {
            let oldest = self
                .retired_order
                .pop_front()
                .expect("retired index is paired");
            self.retired.remove(&oldest);
        }
        self.retired.insert(cookie, context);
        self.retired_order.push_back(cookie);
        true
    }

    /// Nonblocking bounded inspection, to be driven by anchor readiness. No data
    /// is parsed/drained: unexpected data retires the socket, preventing a spin.
    /// On an inspection error no invalidation events have been consumed.
    pub fn retire_ready(&mut self) -> Result<Vec<Invalidation>, AuthorityError> {
        let mut invalidated = Vec::new();
        for entry in self.live.values() {
            let error = entry.registration.error.load(Ordering::Acquire);
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error).into());
            }
            if let Some(reason) = probe(&entry.registration.anchor)? {
                invalidated.push(Invalidation {
                    context: entry.context,
                    reason,
                });
            }
        }
        invalidated.sort_unstable_by_key(|event| event.context);
        for event in &invalidated {
            self.invalidate(event.context);
        }
        Ok(invalidated)
    }

    /// Revoke admission on shutdown; the returned IDs still require controller
    /// cleanup even if no endpoint is open or a retry tombstone is evicted.
    pub fn invalidate_all(&mut self) -> Vec<ContextId> {
        let mut contexts: Vec<_> = self.contexts.keys().copied().collect();
        contexts.sort_unstable();
        for context in &contexts {
            self.invalidate(*context);
        }
        contexts
    }

    /// Readiness registration borrows anchors, never duplicates returned ends.
    pub fn anchors(&self) -> impl Iterator<Item = (ContextId, BorrowedFd<'_>)> {
        self.live
            .values()
            .map(|entry| (entry.context, entry.registration.anchor.as_fd()))
    }

    pub fn registration(&self, context: ContextId) -> Result<Registration, AuthorityError> {
        let cookie = self
            .contexts
            .get(&context)
            .ok_or(AuthorityError::AccessDenied)?;
        self.live
            .get(cookie)
            .map(|entry| entry.registration.clone())
            .ok_or(AuthorityError::AccessDenied)
    }

    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    pub fn retired_count(&self) -> usize {
        self.retired.len()
    }
}

fn identity(endpoint: BorrowedFd<'_>) -> Result<Cookie, AuthorityError> {
    if socket_option::<libc::c_int>(endpoint, libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_option::<libc::c_int>(endpoint, libc::SO_TYPE)? != libc::SOCK_STREAM
    {
        return Err(AuthorityError::AccessDenied);
    }
    let cookie = socket_option::<u64>(endpoint, libc::SO_COOKIE)?;
    if cookie == 0 {
        return Err(io::Error::other("kernel returned an unset socket cookie").into());
    }
    Ok(Cookie(cookie))
}

fn socket_option<T: Copy + Default>(
    endpoint: BorrowedFd<'_>,
    option: libc::c_int,
) -> Result<T, AuthorityError> {
    let mut value = T::default();
    let mut length = std::mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: value and length are writable for the exact requested sizes; the
    // borrowed descriptor remains open. Callers use c_int/u64 socket options.
    let result = unsafe {
        libc::getsockopt(
            endpoint.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            std::ptr::from_mut(&mut value).cast(),
            &mut length,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(libc::ENOTSOCK) {
            AuthorityError::AccessDenied
        } else {
            // In particular, unsupported SO_COOKIE never falls back to UID or
            // descriptor-number authentication.
            AuthorityError::System(error)
        });
    }
    if length as usize != std::mem::size_of::<T>() {
        return Err(io::Error::other("unexpected socket-option size").into());
    }
    Ok(value)
}

fn probe(anchor: &UnixStream) -> io::Result<Option<InvalidationReason>> {
    let mut byte = 0u8;
    loop {
        // SAFETY: byte is writable for one byte and anchor owns a live socket.
        // No ancillary descriptors are installed by recv without a control
        // buffer. Queued SCM_RIGHTS are released when the anchor is retired.
        let result = unsafe {
            libc::recv(
                anchor.as_raw_fd(),
                std::ptr::from_mut(&mut byte).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if result == 0 {
            return Ok(Some(InvalidationReason::PeerClosed));
        }
        if result > 0 {
            return Ok(Some(InvalidationReason::UnexpectedData));
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::WouldBlock => return Ok(None),
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::ConnectionReset => return Ok(Some(InvalidationReason::PeerClosed)),
            _ => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
    use std::io::{IoSlice, IoSliceMut, Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixDatagram;

    fn authorities() -> Authorities {
        Authorities::new(4, 2).unwrap()
    }

    fn denied(result: Result<ContextId, AuthorityError>) {
        assert!(
            matches!(result, Err(AuthorityError::AccessDenied)),
            "{result:?}"
        );
    }

    fn transfer(endpoint: BorrowedFd<'_>) -> OwnedFd {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let rights = [endpoint.as_raw_fd()];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(b"x")],
            &[ControlMessage::ScmRights(&rights)],
            MsgFlags::MSG_NOSIGNAL,
            None,
        )
        .unwrap();
        let mut bytes = [0];
        let mut slices = [IoSliceMut::new(&mut bytes)];
        let mut control = nix::cmsg_space!([libc::c_int; 1]);
        let message = recvmsg::<()>(
            receiver.as_raw_fd(),
            &mut slices,
            Some(&mut control),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )
        .unwrap();
        assert!(!message.flags.contains(MsgFlags::MSG_CTRUNC));
        let mut received = Vec::new();
        for cmsg in message.cmsgs().unwrap() {
            if let ControlMessageOwned::ScmRights(rights) = cmsg {
                for fd in rights {
                    // SAFETY: recvmsg transferred each descriptor exactly once.
                    received.push(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        }
        assert_eq!(received.len(), 1);
        received.pop().unwrap()
    }

    #[test]
    fn duplicate_and_transferred_capabilities_keep_identity_until_final_close() {
        let mut registry = authorities();
        let issued = registry.issue().unwrap();
        let duplicate = issued.endpoint.try_clone().unwrap();
        let transferred = transfer(issued.endpoint.as_fd());
        for fd in [&issued.endpoint, &duplicate, &transferred] {
            assert_eq!(registry.resolve(fd.as_fd()).unwrap(), issued.context);
        }
        drop(issued.endpoint);
        drop(duplicate);
        assert!(registry.retire_ready().unwrap().is_empty());
        assert_eq!(
            registry.resolve(transferred.as_fd()).unwrap(),
            issued.context
        );
        drop(transferred);
        assert_eq!(
            registry.retire_ready().unwrap(),
            vec![Invalidation {
                context: issued.context,
                reason: InvalidationReason::PeerClosed,
            }]
        );
        assert_eq!(registry.live_count(), 0);
        assert!(registry.retire_ready().unwrap().is_empty());
    }

    #[test]
    fn wrong_endpoint_unrelated_socket_file_and_wrong_socket_classes_are_denied() {
        let mut registry = authorities();
        let issued = registry.issue().unwrap();
        let (_, anchor) = registry.anchors().next().unwrap();
        denied(registry.resolve(anchor));
        let (unrelated, _peer) = UnixStream::pair().unwrap();
        denied(registry.resolve(unrelated.as_fd()));
        let (datagram, _peer) = UnixDatagram::pair().unwrap();
        denied(registry.resolve(datagram.as_fd()));
        let file = tempfile::tempfile().unwrap();
        denied(registry.resolve(file.as_fd()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        denied(registry.resolve(tcp.as_fd()));
        assert_eq!(
            registry.resolve(issued.endpoint.as_fd()).unwrap(),
            issued.context
        );
    }

    #[test]
    fn invalidation_is_irreversible_but_bounded_removal_retries_are_authorized() {
        let mut registry = authorities();
        let old = registry.issue().unwrap();
        let duplicate = old.endpoint.try_clone().unwrap();
        assert!(registry.invalidate(old.context));
        assert!(!registry.invalidate(old.context));
        denied(registry.resolve(old.endpoint.as_fd()));
        assert_eq!(
            registry.resolve_removal(duplicate.as_fd()).unwrap(),
            old.context
        );
        for _ in 0..2 {
            let next = registry.issue().unwrap();
            assert_ne!(next.context, old.context);
            assert!(registry.invalidate(next.context));
        }
        assert_eq!(registry.retired_count(), 2);
        denied(registry.resolve_removal(old.endpoint.as_fd()));
        denied(registry.resolve(duplicate.as_fd()));
        assert_eq!(registry.live_count(), 0);
    }

    #[test]
    fn shutdown_fences_all_copies_before_readiness_is_processed() {
        let mut registry = authorities();
        let issued = registry.issue().unwrap();
        let duplicate = issued.endpoint.try_clone().unwrap();
        nix::sys::socket::shutdown(
            issued.endpoint.as_raw_fd(),
            nix::sys::socket::Shutdown::Write,
        )
        .unwrap();
        denied(registry.resolve(issued.endpoint.as_fd()));
        denied(registry.resolve(duplicate.as_fd()));
        assert_eq!(
            registry.resolve_removal(duplicate.as_fd()).unwrap(),
            issued.context
        );
        assert_eq!(registry.retire_ready().unwrap().len(), 1);
        assert_eq!(registry.live_count(), 0);
    }

    #[test]
    fn unexpected_data_invalidates_without_a_parser_or_readiness_spin() {
        let mut registry = authorities();
        let issued = registry.issue().unwrap();
        let mut endpoint = UnixStream::from(issued.endpoint);
        endpoint.write_all(b"not a protocol").unwrap();
        denied(registry.resolve(endpoint.as_fd()));
        assert_eq!(
            registry.retire_ready().unwrap(),
            vec![Invalidation {
                context: issued.context,
                reason: InvalidationReason::UnexpectedData,
            }]
        );
        for _ in 0..4 {
            assert!(registry.retire_ready().unwrap().is_empty());
        }
        let mut byte = [0];
        // Unread incoming data can cause ECONNRESET instead of clean EOF.
        assert!(matches!(endpoint.read(&mut byte), Ok(0) | Err(_)));
    }

    #[test]
    fn unexpected_rights_are_not_installed_or_retained_after_invalidation() {
        let mut registry = authorities();
        let issued = registry.issue().unwrap();
        let (mut reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        sendmsg::<()>(
            issued.endpoint.as_raw_fd(),
            &[IoSlice::new(b"x")],
            &[ControlMessage::ScmRights(&[writer.as_raw_fd()])],
            MsgFlags::MSG_NOSIGNAL,
            None,
        )
        .unwrap();
        drop(writer);
        denied(registry.resolve(issued.endpoint.as_fd()));
        assert_eq!(registry.retire_ready().unwrap().len(), 1);
        assert_eq!(reader.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn previous_daemon_authority_cannot_identify_a_new_context() {
        let mut previous = authorities();
        let old = previous.issue().unwrap();
        drop(previous);
        let mut current = authorities();
        let new = current.issue().unwrap();
        assert_ne!(new.context, old.context);
        denied(current.resolve(old.endpoint.as_fd()));
        denied(current.resolve_removal(old.endpoint.as_fd()));
        assert_eq!(current.resolve(new.endpoint.as_fd()).unwrap(), new.context);
    }

    #[test]
    fn authority_endpoints_and_anchors_are_close_on_exec() {
        let mut registry = authorities();
        let issued = registry.issue().unwrap();
        let (_, anchor) = registry.anchors().next().unwrap();
        for fd in [issued.endpoint.as_fd(), anchor] {
            // SAFETY: F_GETFD only queries the borrowed live descriptor.
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0);
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
    }

    #[test]
    fn bounds_publication_failure_and_daemon_shutdown_do_not_leak_authorities() {
        assert!(matches!(
            Authorities::new(0, 1),
            Err(AuthorityError::InvalidLimits)
        ));
        assert!(matches!(
            Authorities::new(1, 0),
            Err(AuthorityError::InvalidLimits)
        ));
        let mut registry = Authorities::new(1, 1).unwrap();
        let unpublished = registry.issue().unwrap();
        assert!(matches!(
            registry.issue(),
            Err(AuthorityError::LimitExceeded)
        ));
        drop(unpublished.endpoint);
        assert_eq!(registry.retire_ready().unwrap().len(), 1);
        let issued = registry.issue().unwrap();
        let duplicate = issued.endpoint.try_clone().unwrap();
        assert_eq!(registry.invalidate_all(), vec![issued.context]);
        assert!(registry.invalidate_all().is_empty());
        denied(registry.resolve(duplicate.as_fd()));
        assert_eq!(registry.retired_count(), 1);
        let mut endpoint = UnixStream::from(issued.endpoint);
        endpoint.shutdown(Shutdown::Write).unwrap();
        assert_eq!(endpoint.read(&mut [0]).unwrap(), 0);
    }
}
