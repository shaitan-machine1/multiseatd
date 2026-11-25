//! Single-channel nonblocking D-Bus pump with authenticated root lookups and
//! actual libdbus output-flush acknowledgements. No hidden bus worker/runtime.
use crate::fatal::{FLUSH_LIMIT, Fatal};
use crate::master::Master;
use dbus::channel::{BusType, Channel};
use dbus::{Message, MessageType};
use libmultiseatd::ErrorKind;
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{Interest, unix::AsyncFd};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, interval, timeout};
const QUEUE: usize = 64;
const BUS: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
pub struct Request {
    pub message: Message,
    pub uid: Option<u32>,
    pub master: Option<Arc<Master>>,
    pub received: Instant,
}
struct Output {
    message: Message,
    flushed: oneshot::Sender<()>,
}
#[derive(Clone)]
pub struct Replies(mpsc::Sender<Output>, watch::Sender<u64>);
impl Replies {
    pub fn state_changed(&self, revision: u64) {
        self.1.send_replace(revision);
    }
    pub async fn send_flush(&self, message: Message) -> io::Result<()> {
        timeout(FLUSH_LIMIT, async {
            let (flushed, result) = oneshot::channel();
            self.0
                .send(Output { message, flushed })
                .await
                .map_err(|_| io::Error::other("D-Bus output stopped"))?;
            result
                .await
                .map_err(|_| io::Error::other("D-Bus output did not flush"))
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bounded D-Bus send/flush expired"))?
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
    received: Instant,
    deadline: Instant,
}
pub struct BusIo {
    watched: AsyncFd<OwnedFd>,
    channel: Channel,
    name: String,
    fatal: Fatal,
    requests: mpsc::Sender<Request>,
    output: mpsc::Receiver<Output>,
    flushing: Option<oneshot::Sender<()>>,
    credentials: HashMap<u32, Credential>,
    cache: HashMap<String, u32>,
    cache_order: VecDeque<String>,
    revision: watch::Receiver<u64>,
    signal_revision: u64,
    signal_pending: bool,
}
impl BusIo {
    pub fn connect(
        name: String,
        address: Option<&str>,
        fatal: Fatal,
    ) -> io::Result<(Self, mpsc::Receiver<Request>, Replies)> {
        let mut channel = if let Some(address) = address {
            let mut channel = Channel::open_private(address).map_err(io::Error::other)?;
            channel.register().map_err(io::Error::other)?;
            channel
        } else {
            Channel::get_private(BusType::System).map_err(io::Error::other)?
        };
        channel.set_watch_enabled(true);
        let descriptor =
            unsafe { BorrowedFd::borrow_raw(channel.watch().fd) }.try_clone_to_owned()?;
        let watched = unsafe { AsyncFd::register(descriptor) }?;
        let (requests, receiver) = mpsc::channel(QUEUE);
        let (sender, output) = mpsc::channel(QUEUE);
        let (revisions, revision) = watch::channel(0);
        Ok((
            Self {
                watched,
                channel,
                name,
                fatal,
                requests,
                output,
                flushing: None,
                credentials: HashMap::new(),
                cache: HashMap::new(),
                cache_order: VecDeque::new(),
                revision,
                signal_revision: 0,
                signal_pending: false,
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
            .map_err(|_| io::Error::other("D-Bus setup send failed"))?;
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
                    if message.msg_type() == MessageType::MethodCall {
                        let _ = self.channel.send(error_reply(
                            &message,
                            ErrorKind::NotReady,
                            "seat is starting",
                        ));
                    }
                }
                io_ready(&self.watched, &self.channel).await?;
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "D-Bus setup timed out"))?
    }
    pub async fn run(
        mut self,
        mut stop: watch::Receiver<bool>,
        ready: oneshot::Sender<()>,
    ) -> io::Result<()> {
        self.bus_call("AddMatch", |call| call.append1("type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged'")).await?;
        let name = self.name.clone();
        if self
            .bus_call("RequestName", |call| call.append2(name, 4u32))
            .await?
            .read1::<u32>()
            .map_err(io::Error::other)?
            != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "per-seat bus name already owned",
            ));
        }
        ready
            .send(())
            .map_err(|_| io::Error::other("startup owner disappeared"))?;
        let mut expiry = interval(Duration::from_millis(100));
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            self.expire();
            self.channel
                .read_write(Some(Duration::ZERO))
                .map_err(|_| io::Error::other("D-Bus disconnected"))?;
            if !self.channel.has_messages_to_send()
                && let Some(flushed) = self.flushing.take()
            {
                let _ = flushed.send(());
            }
            let mut count = 0;
            while count < 32 {
                let Some(message) = self.channel.pop_message() else {
                    break;
                };
                self.message(message)?;
                count += 1;
            }
            if !self.channel.has_messages_to_send()
                && let Ok(output) = self.output.try_recv()
            {
                self.output(output)?;
            }
            if self.revision.has_changed().unwrap_or(false) {
                self.signal_revision = *self.revision.borrow_and_update();
                self.signal_pending = true;
            }
            if !self.channel.has_messages_to_send() && self.signal_pending {
                self.signal_pending = false;
                let message = Message::new_signal(
                    libmultiseatd::OBJECT_PATH,
                    libmultiseatd::INTERFACE_NAME,
                    "StateChanged",
                )
                .map_err(io::Error::other)?
                .append1(self.signal_revision);
                self.channel
                    .send(message)
                    .map_err(|_| io::Error::other("state hint send failed"))?;
            }
            if count == 32 {
                tokio::task::yield_now().await;
                continue;
            }
            tokio::select! {
                biased;
                _ = stop.changed() => if *stop.borrow() { return Ok(()) },
                _ = expiry.tick() => {},
                output = self.output.recv(), if !self.channel.has_messages_to_send() => {
                    self.output(output.ok_or_else(|| io::Error::other("D-Bus reply owner disappeared"))?)?;
                }
                result = io_ready(&self.watched, &self.channel) => result?,
            }
            if !self.channel.is_connected() {
                return Err(io::Error::other("D-Bus disconnected"));
            }
        }
    }
    fn output(&mut self, output: Output) -> io::Result<()> {
        self.channel
            .send(output.message)
            .map_err(|_| io::Error::other("D-Bus output send failed"))?;
        self.flushing = Some(output.flushed);
        Ok(())
    }
    fn reject(&self, request: &Message, kind: ErrorKind, reason: &str) {
        if !self.channel.has_messages_to_send() {
            let _ = self.channel.send(error_reply(request, kind, reason));
        }
    }
    fn forward(
        &self,
        message: Message,
        uid: Option<u32>,
        master: Option<Arc<Master>>,
        received: Instant,
    ) {
        if self.fatal.stopping() {
            self.reject(&message, ErrorKind::Stopping, "seat is stopping");
            return;
        }
        if let Err(error) = self.requests.try_send(Request {
            message,
            uid,
            master,
            received,
        }) {
            self.reject(
                &error.into_inner().message,
                ErrorKind::LimitExceeded,
                "D-Bus admission queue is full",
            );
        }
    }
    fn message(&mut self, mut message: Message) -> io::Result<()> {
        if from_bus(&message) {
            if let Some(serial) = message.get_reply_serial()
                && let Some(pending) = self.credentials.remove(&serial)
            {
                if pending.request.member().as_deref() == Some("CreateContext") {
                    let acquired = (|| -> io::Result<Arc<Master>> {
                        message.as_result().map_err(io::Error::other)?;
                        let credentials = message
                            .read1::<dbus::arg::PropMap>()
                            .map_err(io::Error::other)?;
                        if credentials.get("UnixUserID").and_then(|v| v.0.as_u64()) != Some(0) {
                            return Err(io::Error::other("authenticated root is required"));
                        }
                        let fd = credentials
                            .get("ProcessFD")
                            .and_then(|v| v.0.as_any().downcast_ref::<std::fs::File>())
                            .ok_or_else(|| {
                                io::Error::other(
                                    "bus ProcessFD is required; no numeric-PID fallback",
                                )
                            })?;
                        let fd = unsafe { BorrowedFd::borrow_raw(fd.as_raw_fd()) }
                            .try_clone_to_owned()?;
                        Master::acquire(fd)
                    })();
                    match acquired {
                        Ok(master) => {
                            self.forward(pending.request, Some(0), Some(master), pending.received)
                        }
                        Err(e) => {
                            self.reject(&pending.request, ErrorKind::NotAuthorized, &e.to_string())
                        }
                    }
                    return Ok(());
                }
                match message.read1::<u32>() {
                    Ok(uid) if message.msg_type() == MessageType::MethodReturn => {
                        if self.cache.len() == 512
                            && let Some(old) = self.cache_order.pop_front()
                        {
                            self.cache.remove(&old);
                        }
                        if self.cache.insert(pending.sender.clone(), uid).is_none() {
                            self.cache_order.push_back(pending.sender);
                        }
                        self.forward(pending.request, Some(uid), None, pending.received);
                    }
                    _ => self.reject(
                        &pending.request,
                        ErrorKind::NotAuthorized,
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
                self.credentials.retain(|_, pending| pending.sender != name);
            }
        }
        if message.msg_type() != MessageType::MethodCall {
            return Ok(());
        }
        let received = Instant::now();
        if !bounded_arguments(&message) {
            self.reject(
                &message,
                ErrorKind::InvalidArgument,
                "unsupported or oversized arguments",
            );
            return Ok(());
        }
        if !requires_root(
            &message
                .member()
                .map(|member| member.to_string())
                .unwrap_or_default(),
        ) {
            self.forward(message, None, None, received);
            return Ok(());
        }
        let Some(sender) = message
            .sender()
            .map(|name| name.to_string())
            .filter(|name| name.starts_with(':'))
        else {
            self.reject(
                &message,
                ErrorKind::NotAuthorized,
                "missing authenticated unique sender",
            );
            return Ok(());
        };
        let creating = message.member().as_deref() == Some("CreateContext");
        if let Some(uid) = self.cache.get(&sender).copied().filter(|_| !creating) {
            self.forward(message, Some(uid), None, received);
        } else if self.credentials.len() < 128 {
            let query = Message::new_method_call(
                BUS,
                BUS_PATH,
                BUS,
                if creating {
                    "GetConnectionCredentials"
                } else {
                    "GetConnectionUnixUser"
                },
            )
            .map_err(io::Error::other)?
            .append1(&sender);
            let serial = self
                .channel
                .send(query)
                .map_err(|_| io::Error::other("credential query send failed"))?;
            self.credentials.insert(
                serial,
                Credential {
                    request: message,
                    sender,
                    received,
                    deadline: received + Duration::from_secs(2),
                },
            );
        } else {
            self.reject(
                &message,
                ErrorKind::LimitExceeded,
                "credential lookup limit",
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
                    ErrorKind::NotAuthorized,
                    "credential lookup expired",
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
            | "ActivateContext"
            | "DeactivateContext"
            | "RemoveContextById"
            | "ListContexts"
            | "MoveToForeground"
            | "RemoveUnassignedDevices"
            | "AddAssignedDevices"
    )
}
fn bounded_arguments(message: &Message) -> bool {
    use dbus::arg::ArgType;
    let mut iter = message.iter_init();
    for _ in 0..2 {
        match iter.arg_type() {
            ArgType::Invalid => return true,
            ArgType::String if iter.get::<&str>().is_some_and(|value| value.len() <= 256) => {}
            ArgType::UnixFd | ArgType::UInt32 | ArgType::UInt64 => {}
            _ => return false,
        }
        iter.next();
    }
    iter.arg_type() == ArgType::Invalid
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_reply_serial_alone_never_authenticates_root() {
        let mut request =
            Message::new_method_call(BUS, BUS_PATH, BUS, "GetConnectionUnixUser").unwrap();
        request.set_serial(123);
        let mut reply = request.method_return().append1(0u32);
        reply.set_sender(Some(dbus::strings::BusName::new(":1.42").unwrap()));
        assert!(!from_bus(&reply));
        reply.set_sender(Some(dbus::strings::BusName::new(BUS).unwrap()));
        assert!(from_bus(&reply));
    }
    #[test]
    fn bounds_are_checked_before_owned_decoding_and_authorization_is_exact() {
        let call = || {
            Message::new_method_call(
                "org.SGLogin.Multiseatd1.Seat_seat0",
                libmultiseatd::OBJECT_PATH,
                libmultiseatd::INTERFACE_NAME,
                "CreateContext",
            )
            .unwrap()
        };
        assert!(bounded_arguments(&call().append1(7u32)));
        assert!(!bounded_arguments(&call().append1("x".repeat(257))));
        assert!(!bounded_arguments(&call().append1(vec![0u32; 32])));
        assert!(!bounded_arguments(&call().append3(0u32, 0u32, 0u32)));
        for method in [
            "ActivateContext",
            "DeactivateContext",
            "MoveToForeground",
            "RemoveUnassignedDevices",
            "AddAssignedDevices",
        ] {
            assert!(requires_root(method));
        }
        for method in [
            "GetContext",
            "RemoveContext",
            "AddAclGrant",
            "CreateConnection",
        ] {
            assert!(!requires_root(method));
        }
    }
}
