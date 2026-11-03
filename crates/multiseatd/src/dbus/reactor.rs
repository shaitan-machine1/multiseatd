//! Single-channel Tokio D-Bus pump. Credentials are queried without blocking a
//! method handler. Only bus-authenticated replies can satisfy a UID lookup.

use crate::daemon::{Shutdown, ShutdownPhase};
use dbus::channel::{BusType, Channel};
use dbus::{Message, MessageType};
use libmultiseatd::contract::{BUS_NAME, ErrorKind};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::time::Duration;
use tokio::io::{Interest, unix::AsyncFd};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, interval, timeout};

const QUEUE: usize = 64;
const UID_LIMIT: usize = 128;
const CACHE_LIMIT: usize = 512;
const BUS: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";

pub struct Request {
    pub message: Message,
    /// Present only for methods requiring independently authenticated root.
    pub uid: Option<u32>,
}

#[derive(Clone)]
pub struct Replies(mpsc::Sender<Message>, watch::Sender<u64>);

impl Replies {
    pub fn state_changed(&self, revision: u64) {
        self.1.send_replace(revision);
    }
    pub fn send(&self, message: Message) -> io::Result<()> {
        self.0.try_send(message).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "D-Bus output queue is full")
            }
            mpsc::error::TrySendError::Closed(_) => {
                io::Error::new(io::ErrorKind::BrokenPipe, "D-Bus pump stopped")
            }
        })
    }
}

pub fn error_reply(message: &Message, kind: ErrorKind, text: &str) -> Message {
    let name = dbus::strings::ErrorName::new(kind.name()).expect("static error name");
    let text = CString::new(text.replace('\0', "?")).expect("NUL removed");
    message.error(&name, &text)
}

struct Credential {
    request: Message,
    sender: String,
    deadline: Instant,
}

pub struct BusIo {
    // Duplicate for registration: libdbus may close its original on disconnect.
    // The owned watch FD cannot change underneath Tokio, even in that case.
    watched: AsyncFd<OwnedFd>,
    channel: Channel,
    requests: mpsc::Sender<Request>,
    output: mpsc::Receiver<Message>,
    credentials: HashMap<u32, Credential>,
    cache: HashMap<String, u32>,
    cache_order: VecDeque<String>,
    revision: watch::Receiver<u64>,
    signal_revision: u64,
    signal_peers: VecDeque<String>,
}

impl BusIo {
    /// Connection/authentication occurs once during controlled startup. No
    /// reconnect or hidden D-Bus thread. Name publication happens in run().
    pub fn connect(session: bool) -> io::Result<(Self, mpsc::Receiver<Request>, Replies)> {
        let mut channel = Channel::get_private(if session {
            BusType::Session
        } else {
            BusType::System
        })
        .map_err(io::Error::other)?;
        channel.set_watch_enabled(true);
        // SAFETY: channel is connected and solely owned here, and no read_write
        // or close can run during this short borrow/duplicate operation.
        let descriptor =
            unsafe { BorrowedFd::borrow_raw(channel.watch().fd) }.try_clone_to_owned()?;
        // SAFETY: the owned duplicate remains the same live FD until the watch
        // is dropped. Only this task can access it, and it is never replaced.
        let watched = unsafe { AsyncFd::register(descriptor) }?;
        let (requests, receiver) = mpsc::channel(QUEUE);
        let (sender, output) = mpsc::channel(QUEUE);
        let (revisions, revision) = watch::channel(0);
        Ok((
            Self {
                watched,
                channel,
                requests,
                output,
                credentials: HashMap::new(),
                cache: HashMap::new(),
                cache_order: VecDeque::new(),
                revision,
                signal_revision: 0,
                signal_peers: VecDeque::new(),
            },
            receiver,
            Replies(sender, revisions),
        ))
    }

    async fn bus_call(
        &mut self,
        member: &str,
        append: impl FnOnce(Message) -> Message,
    ) -> io::Result<Message> {
        let call =
            Message::new_method_call(BUS, BUS_PATH, BUS, member).map_err(io::Error::other)?;
        let serial = self
            .channel
            .send(append(call))
            .map_err(|_| io::Error::other("D-Bus send failed"))?;
        timeout(Duration::from_secs(2), async {
            loop {
                self.channel
                    .read_write(Some(Duration::ZERO))
                    .map_err(|_| io::Error::other("D-Bus disconnected"))?;
                for _ in 0..32 {
                    let Some(mut message) = self.channel.pop_message() else {
                        break;
                    };
                    if from_bus(&message) && message.get_reply_serial() == Some(serial) {
                        message.as_result().map_err(io::Error::other)?;
                        return Ok(message);
                    }
                    // During initialization no application method is admitted.
                    // A caller racing name publication gets a retryable error.
                    if message.msg_type() == MessageType::MethodCall {
                        let _ = self.channel.send(error_reply(
                            &message,
                            ErrorKind::TransitionPending,
                            "daemon is starting",
                        ));
                    }
                }
                io_ready(&self.watched, &self.channel).await?;
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "D-Bus setup timed out"))?
    }

    /// Publish only after the caller's topology, cleanup and controllers are
    /// ready. Report readiness after both bus subscription and name acquisition.
    pub async fn run(
        mut self,
        mut shutdown: Shutdown,
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> io::Result<()> {
        self.bus_call("AddMatch", |call| call.append1("type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged'")).await?;
        let reply = self
            .bus_call("RequestName", |call| call.append2(BUS_NAME, 4u32))
            .await?;
        if reply.read1::<u32>().map_err(io::Error::other)? != 1 {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "multiseatd2 name already owned",
            ));
        }
        ready
            .send(())
            .map_err(|_| io::Error::other("startup owner disappeared"))?;
        let mut expiry = interval(Duration::from_millis(100));
        loop {
            // Bounded protocol batches; recheck shutdown and output every turn.
            if shutdown.phase() >= ShutdownPhase::Quiesce {
                return Ok(());
            }
            if self.requests.is_closed() {
                return Err(io::Error::other("request owner disappeared"));
            }
            self.expire();
            self.channel
                .read_write(Some(Duration::ZERO))
                .map_err(|_| io::Error::other("D-Bus disconnected"))?;
            let mut count = 0;
            while count < 32 {
                let Some(message) = self.channel.pop_message() else {
                    break;
                };
                self.message(message)?;
                count += 1;
            }
            if !self.channel.has_messages_to_send()
                && let Ok(message) = self.output.try_recv()
            {
                self.channel
                    .send(message)
                    .map_err(|_| io::Error::other("D-Bus send failed"))?;
            }
            if self.revision.has_changed().unwrap_or(false) {
                self.signal_revision = *self.revision.borrow_and_update();
                self.signal_peers = self
                    .cache
                    .iter()
                    .filter(|(_, uid)| **uid == 0)
                    .map(|(peer, _)| peer.clone())
                    .collect();
            }
            if !self.channel.has_messages_to_send()
                && let Some(peer) = self.signal_peers.pop_front()
                && self.cache.get(&peer) == Some(&0)
            {
                let mut message = Message::new_signal(
                    libmultiseatd::contract::OBJECT_PATH,
                    libmultiseatd::contract::INTERFACE_NAME,
                    "StateChanged",
                )
                .map_err(io::Error::other)?
                .append1(self.signal_revision);
                message.set_destination(Some(
                    dbus::strings::BusName::new(peer).expect("authenticated unique name"),
                ));
                self.channel
                    .send(message)
                    .map_err(|_| io::Error::other("state hint delivery failed"))?;
            }
            if count == 32
                || (!self.signal_peers.is_empty() && !self.channel.has_messages_to_send())
            {
                tokio::task::yield_now().await;
                continue;
            }
            tokio::select! {
                biased;
                _ = shutdown.reached(ShutdownPhase::Quiesce) => return Ok(()),
                _ = expiry.tick() => self.expire(),
                message = self.output.recv(), if !self.channel.has_messages_to_send() => {
                    let message = message.ok_or_else(|| io::Error::other("D-Bus reply owner disappeared"))?;
                    self.channel.send(message).map_err(|_| io::Error::other("D-Bus send failed"))?;
                }
                result = io_ready(&self.watched, &self.channel) => result?,
            }
            if !self.channel.is_connected() {
                return Err(io::Error::other("D-Bus disconnected"));
            }
        }
    }

    fn reject(&self, request: &Message, kind: ErrorKind, reason: &str) {
        // Never accumulate an unbounded overload-error queue. At saturation the
        // caller can time out; no work/descriptor publication was admitted.
        if !self.channel.has_messages_to_send() {
            let _ = self.channel.send(error_reply(request, kind, reason));
        }
    }

    fn forward(&self, message: Message, uid: Option<u32>) {
        if let Err(error) = self.requests.try_send(Request { message, uid }) {
            let request = error.into_inner();
            self.reject(
                &request.message,
                ErrorKind::LimitExceeded,
                "D-Bus admission queue is full",
            );
        }
    }

    fn message(&mut self, message: Message) -> io::Result<()> {
        if from_bus(&message) {
            if let Some(serial) = message.get_reply_serial()
                && let Some(pending) = self.credentials.remove(&serial)
            {
                match message.read1::<u32>() {
                    Ok(uid) if message.msg_type() == MessageType::MethodReturn => {
                        if self.cache.len() == CACHE_LIMIT
                            && let Some(old) = self.cache_order.pop_front()
                        {
                            self.cache.remove(&old);
                        }
                        if self.cache.insert(pending.sender.clone(), uid).is_none() {
                            self.cache_order.push_back(pending.sender);
                        }
                        self.forward(pending.request, Some(uid));
                    }
                    _ => self.reject(
                        &pending.request,
                        ErrorKind::AccessDenied,
                        "caller credentials unavailable",
                    ),
                }
                return Ok(());
            }
            if message.msg_type() == MessageType::Signal
                && message.path().as_deref() == Some(BUS_PATH)
                && message.interface().as_deref() == Some(BUS)
                && message.member().as_deref() == Some("NameOwnerChanged")
                && let Ok((name, _, new)) = message.read3::<String, String, String>()
                && new.is_empty()
            {
                self.cache.remove(&name);
                self.cache_order.retain(|old| old != &name);
            }
        }
        if message.msg_type() != MessageType::MethodCall {
            return Ok(());
        }
        if !bounded_arguments(&message) {
            self.reject(
                &message,
                ErrorKind::InvalidArgument,
                "unsupported or oversized arguments",
            );
            return Ok(());
        }
        let member = message.member().map(|m| m.to_string()).unwrap_or_default();
        if !requires_root(&member) {
            self.forward(message, None);
            return Ok(());
        }
        let Some(sender) = message
            .sender()
            .map(|name| name.to_string())
            .filter(|name| name.starts_with(':'))
        else {
            self.reject(&message, ErrorKind::AccessDenied, "missing unique sender");
            return Ok(());
        };
        if let Some(uid) = self.cache.get(&sender).copied() {
            self.forward(message, Some(uid));
        } else if self.credentials.len() < UID_LIMIT {
            let query = Message::new_method_call(BUS, BUS_PATH, BUS, "GetConnectionUnixUser")
                .map_err(io::Error::other)?
                .append1(&sender);
            let serial = self
                .channel
                .send(query)
                .map_err(|_| io::Error::other("credential query failed"))?;
            self.credentials.insert(
                serial,
                Credential {
                    request: message,
                    sender,
                    deadline: Instant::now() + Duration::from_secs(2),
                },
            );
        } else {
            self.reject(
                &message,
                ErrorKind::LimitExceeded,
                "credential lookup limit reached",
            );
        }
        Ok(())
    }

    fn expire(&mut self) {
        let expired: Vec<_> = self
            .credentials
            .iter()
            .filter(|(_, pending)| pending.deadline <= Instant::now())
            .map(|(serial, _)| *serial)
            .collect();
        for serial in expired {
            if let Some(pending) = self.credentials.remove(&serial) {
                self.reject(
                    &pending.request,
                    ErrorKind::AccessDenied,
                    "credential lookup timed out",
                );
            }
        }
    }
}

async fn io_ready(watched: &AsyncFd<OwnedFd>, channel: &Channel) -> io::Result<()> {
    let interest = if channel.has_messages_to_send() {
        Interest::READABLE | Interest::WRITABLE
    } else {
        Interest::READABLE
    };
    let mut ready = watched.ready(interest).await?;
    channel
        .read_write(Some(Duration::ZERO))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "D-Bus disconnected"))?;
    ready.clear_ready();
    Ok(())
}

fn from_bus(message: &Message) -> bool {
    message.sender().as_deref() == Some(BUS)
}

pub fn requires_root(member: &str) -> bool {
    matches!(
        member,
        "CreateContext"
            | "ListSeats"
            | "ListContexts"
            | "ListConnections"
            | "ActivateContextById"
            | "DeactivateContextById"
            | "RemoveContextById"
            | "RemoveConnectionById"
    )
}

fn bounded_arguments(message: &Message) -> bool {
    use dbus::arg::ArgType;
    let mut iter = message.iter_init();
    for _ in 0..4 {
        match iter.arg_type() {
            ArgType::Invalid => return true,
            ArgType::String => {
                if !iter.get::<&str>().is_some_and(|text| text.len() <= 256) {
                    return false;
                }
            }
            ArgType::UnixFd | ArgType::UInt32 => {}
            _ => return false,
        }
        iter.next();
    }
    iter.arg_type() == ArgType::Invalid
}

#[cfg(test)]
mod tests {
    use super::*;
    use libmultiseatd::contract::{INTERFACE_NAME, OBJECT_PATH};

    #[test]
    fn credential_reply_serial_alone_cannot_authenticate_root() {
        let mut request =
            Message::new_method_call(BUS, BUS_PATH, BUS, "GetConnectionUnixUser").unwrap();
        request.set_serial(123);
        let mut reply = request.method_return().append1(0u32);
        reply.set_sender(Some(dbus::strings::BusName::new(":1.42").unwrap()));
        assert_eq!(reply.get_reply_serial(), Some(123));
        assert!(!from_bus(&reply));
        reply.set_sender(Some(dbus::strings::BusName::new(BUS).unwrap()));
        assert!(from_bus(&reply));
    }

    #[test]
    fn arguments_are_bounded_before_owned_decoding() {
        let call = || {
            Message::new_method_call(BUS_NAME, OBJECT_PATH, INTERFACE_NAME, "CreateContext")
                .unwrap()
        };
        assert!(bounded_arguments(&call().append1("seat-test")));
        assert!(!bounded_arguments(&call().append1("x".repeat(257))));
        assert!(!bounded_arguments(&call().append1(vec![0u32; 32])));
        assert!(!bounded_arguments(
            &call().append3("a", "b", "c").append2("d", "e")
        ));
    }
}
