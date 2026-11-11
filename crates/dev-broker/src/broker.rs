//! Context-free socket/resource owner. Commands start work; dispatch never waits
//! for State, a catalog callback, an ACK, native switching, or a kernel worker.
use crate::{
    connection,
    connections::{Connections, Membership},
    device::AllowedDevice,
    devices::Devices,
    permit::Permit,
    resources::{ConnectionKey, Resources},
    seatd::protocol as wire,
};
use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};

type Reply<T> = oneshot::Sender<io::Result<T>>;
pub struct RegisteredConnection {
    pub key: ConnectionKey,
    pub handle: u32,
    pub close: connection::Close,
}
pub enum Event {
    Open {
        key: ConnectionKey,
        path: PathBuf,
        permission: Permit,
        done: oneshot::Sender<()>,
    },
    Switch {
        key: ConnectionKey,
        target: u32,
        permission: Permit,
        done: oneshot::Sender<()>,
    },
    Publish {
        key: ConnectionKey,
        slot: i32,
        permission: Permit,
        output: connection::Output,
        done: Option<oneshot::Sender<()>>,
    },
    Gone(ConnectionKey),
}
enum Command {
    Add {
        descriptor: OwnedFd,
        permission: Option<Permit>,
        reply: Reply<RegisteredConnection>,
    },
    Open {
        key: ConnectionKey,
        admission: Option<(AllowedDevice, Permit)>,
        start: oneshot::Receiver<()>,
        done: oneshot::Sender<()>,
        reply: Reply<()>,
    },
    SwitchDone {
        key: ConnectionKey,
        result: io::Result<()>,
        done: oneshot::Sender<()>,
    },
    Publish {
        key: ConnectionKey,
        output: connection::Output,
        reply: Reply<()>,
    },
    Reject {
        key: ConnectionKey,
        slot: i32,
    },
    Allow {
        keys: Vec<ConnectionKey>,
        permission: Permit,
        reply: Reply<()>,
    },
    Withdraw {
        keys: Vec<ConnectionKey>,
        remove: bool,
        reply: Reply<()>,
    },
    Revoke {
        keep: BTreeMap<PathBuf, AllowedDevice>,
        reply: Reply<()>,
    },
    Shutdown {
        reply: Reply<()>,
    },
}
#[derive(Clone)]
pub struct Control {
    commands: mpsc::Sender<Command>,
    emergency: watch::Sender<bool>,
    resources: Arc<Resources>,
}
impl Control {
    async fn request<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> io::Result<T> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(make(reply))
            .await
            .map_err(|_| stopped())?;
        result.await.map_err(|_| stopped())?
    }
    pub async fn add_connection(
        &self,
        descriptor: OwnedFd,
        permission: Option<Permit>,
    ) -> io::Result<RegisteredConnection> {
        self.request(|reply| Command::Add {
            descriptor,
            permission,
            reply,
        })
        .await
    }
    pub async fn register_open(
        &self,
        key: ConnectionKey,
        admission: Option<(AllowedDevice, Permit)>,
        start: oneshot::Receiver<()>,
        done: oneshot::Sender<()>,
    ) -> io::Result<()> {
        self.request(|reply| Command::Open {
            key,
            admission,
            start,
            done,
            reply,
        })
        .await
    }
    pub async fn switch_completed(
        &self,
        key: ConnectionKey,
        result: io::Result<()>,
        done: oneshot::Sender<()>,
    ) -> io::Result<()> {
        self.commands
            .send(Command::SwitchDone { key, result, done })
            .await
            .map_err(|_| stopped())
    }
    /// The caller holds its final admission read guard until actual FD flush.
    /// Required withdrawal never waits for this State-dependent publication.
    pub async fn publish(&self, key: ConnectionKey, output: connection::Output) -> io::Result<()> {
        self.request(|reply| Command::Publish { key, output, reply })
            .await
    }
    pub async fn reject_publication(&self, key: ConnectionKey, slot: i32) -> io::Result<()> {
        self.commands
            .send(Command::Reject { key, slot })
            .await
            .map_err(|_| stopped())
    }
    pub async fn allow_connections(
        &self,
        keys: Vec<ConnectionKey>,
        permission: Permit,
    ) -> io::Result<()> {
        self.request(|reply| Command::Allow {
            keys,
            permission,
            reply,
        })
        .await
    }
    pub async fn withdraw_connections(
        &self,
        keys: Vec<ConnectionKey>,
        remove: bool,
    ) -> io::Result<()> {
        self.request(|reply| Command::Withdraw {
            keys,
            remove,
            reply,
        })
        .await
    }
    pub async fn revoke_unlisted_devices(
        &self,
        keep: BTreeMap<PathBuf, AllowedDevice>,
    ) -> io::Result<()> {
        self.request(|reply| Command::Revoke { keep, reply }).await
    }
    pub async fn shutdown(&self) -> io::Result<()> {
        self.request(|reply| Command::Shutdown { reply }).await
    }
    /// Pure atomic fence for a native watchdog which cannot wait for any lock.
    pub fn fence_only(&self) {
        self.resources.fence();
    }
    pub fn emergency_stop(&self) {
        self.resources.fence();
        self.emergency.send_replace(true);
    }
    pub fn resources(&self) -> Arc<Resources> {
        self.resources.clone()
    }
}
struct Binding {
    permission: Option<Permit>,
    active: bool,
    job: bool,
    switches: usize,
    disable_deadline: Option<Instant>,
    _quota: OwnedSemaphorePermit,
}
enum Transaction {
    Allow(Vec<ConnectionKey>, Reply<()>),
    Withdraw(Vec<ConnectionKey>, Reply<()>),
    Revoke {
        keep: Option<BTreeMap<PathBuf, AllowedDevice>>,
        running: bool,
        complete: bool,
        reply: Option<Reply<()>>,
    },
    Shutdown(Reply<()>),
}
#[derive(Clone, Copy)]
enum Work {
    Activate(ConnectionKey),
    Deactivate(ConnectionKey),
    Close(ConnectionKey),
    Revoke,
}
struct Completion {
    work: Work,
    errors: Vec<io::Error>,
}
pub struct Broker {
    seat: String,
    synthetic: bool,
    commands: mpsc::Receiver<Command>,
    emergency: watch::Receiver<bool>,
    events: mpsc::Sender<Event>,
    bindings: BTreeMap<ConnectionKey, Binding>,
    connections: Connections<ConnectionKey>,
    devices: Devices<ConnectionKey>,
    resources: Arc<Resources>,
    workers: Arc<Semaphore>,
    quota: Arc<Semaphore>,
    requests: mpsc::Receiver<connection::Request<ConnectionKey>>,
    request_sender: mpsc::Sender<connection::Request<ConnectionKey>>,
    deliveries: mpsc::Receiver<connection::Event<ConnectionKey>>,
    delivery_sender: mpsc::Sender<connection::Event<ConnectionKey>>,
    transports: JoinSet<(ConnectionKey, io::Result<()>)>,
    jobs: JoinSet<Completion>,
    transactions: Vec<Transaction>,
    stopping: bool,
    publications: BTreeMap<u64, (ConnectionKey, Reply<()>)>,
    next_publication: u64,
}
impl Broker {
    pub fn new(
        seat: String,
        synthetic: bool,
        resources: Arc<Resources>,
        workers: Arc<Semaphore>,
    ) -> (Self, Control, mpsc::Receiver<Event>) {
        let (commands, receiver) = mpsc::channel(256);
        let (emergency, stopped) = watch::channel(false);
        let (events, incoming) = mpsc::channel(256);
        let (request_sender, requests) = mpsc::channel(256);
        let (delivery_sender, deliveries) = mpsc::channel(256);
        let control = Control {
            commands,
            emergency,
            resources: resources.clone(),
        };
        (
            Self {
                seat,
                synthetic,
                commands: receiver,
                emergency: stopped,
                events,
                bindings: BTreeMap::new(),
                connections: Connections::new(4096),
                devices: Devices::new(
                    resources.clone(),
                    workers.clone(),
                    Arc::new(Semaphore::new(1024)),
                    4096,
                ),
                resources,
                workers,
                quota: Arc::new(Semaphore::new(4096)),
                requests,
                request_sender,
                deliveries,
                delivery_sender,
                transports: JoinSet::new(),
                jobs: JoinSet::new(),
                transactions: Vec::new(),
                stopping: false,
                publications: BTreeMap::new(),
                next_publication: u64::MAX,
            },
            control,
            incoming,
        )
    }
    pub async fn run(mut self) -> io::Result<()> {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        loop {
            self.progress()?;
            if self.stopping
                && self.bindings.is_empty()
                && self.transports.is_empty()
                && self.jobs.is_empty()
                && !self.devices.has_jobs()
            {
                for transaction in self.transactions.drain(..) {
                    finish(transaction);
                }
                return Ok(());
            }
            tokio::select! {
                biased;
                changed = self.emergency.changed() => {
                    if changed.is_err() || *self.emergency.borrow() { self.stop(); }
                }
                command = self.commands.recv() => match command { Some(command) => self.command(command)?, None => self.stop() },
                result = self.jobs.join_next(), if !self.jobs.is_empty() => {
                    self.complete(result.expect("owned job").map_err(io::Error::other)?)?;
                }
                result = self.devices.next_completion(), if self.devices.has_jobs() => self.device_reply(result?)?,
                result = self.transports.join_next(), if !self.transports.is_empty() => {
                    let (key, _) = result.expect("owned transport").map_err(io::Error::other)?;
                    if self.bindings.contains_key(&key) { self.connections.gone(key); }
                    self.publications.retain(|_, (owner, _)| *owner != key);
                }
                delivery = self.deliveries.recv() => if let Some(connection::Event::Delivered { connection, tag }) = delivery {
                    if let Some((owner, reply)) = self.publications.remove(&tag) {
                        if owner != connection { return Err(io::Error::other("wrong publication incarnation")); }
                        let _ = reply.send(Ok(()));
                    } else { self.connections.delivered(connection, tag); }
                },
                request = self.requests.recv(), if !self.stopping => if let Some(request) = request { self.packet(request)?; },
                _ = tick.tick() => {},
            }
        }
    }
    fn command(&mut self, command: Command) -> io::Result<()> {
        match command {
            Command::Add {
                descriptor,
                permission,
                reply,
            } => {
                let result = self.add(descriptor, permission);
                // Failed registration publication closes the newly owned socket.
                if let Err(Ok(registered)) = reply.send(result) {
                    registered.close.signal();
                }
            }
            Command::Open {
                key,
                admission,
                start,
                done,
                reply,
            } => {
                if !self.stopping && self.bindings.contains_key(&key) {
                    if let Some(result) =
                        self.devices
                            .open(key, admission, start, self.synthetic, done)
                    {
                        self.device_reply(result)?;
                    }
                    let _ = reply.send(Ok(())); // Job is registered, NOT kernel-complete.
                } else {
                    let _ = reply.send(Err(stopped()));
                }
            }
            Command::SwitchDone { key, result, done } => {
                if let Some(binding) = self.bindings.get_mut(&key) {
                    binding.switches = binding.switches.saturating_sub(1);
                    let bytes = match result {
                        Ok(()) => wire::empty(wire::SERVER_SESSION_SWITCHED),
                        Err(e) => wire::error(e.raw_os_error().unwrap_or(libc::EIO)),
                    };
                    self.connections.send(key, bytes, None);
                }
                let _ = done.send(());
            }
            Command::Publish {
                key,
                mut output,
                reply,
            } => {
                if self.stopping
                    || self.publications.len() >= 64
                    || !self.connections.get(&key).is_some_and(|entry| entry.live())
                    || !output.permission.as_ref().is_some_and(Permit::is_open)
                {
                    self.connections.close(key);
                    let _ = reply.send(Err(stopped()));
                } else {
                    let tag = self.next_publication;
                    self.next_publication =
                        tag.checked_sub(1)
                            .filter(|tag| *tag >= (1u64 << 63))
                            .ok_or_else(|| io::Error::other("publication generation exhaustion"))?;
                    output.tag = Some(tag);
                    if self.connections[&key].send(output) {
                        self.publications.insert(tag, (key, reply));
                    } else {
                        let _ = reply.send(Err(stopped()));
                    }
                }
            }
            Command::Reject { key, slot } => {
                self.devices.unpublished(key, slot);
                self.connections.send(key, wire::error(libc::EACCES), None);
            }
            Command::Allow {
                keys,
                permission,
                reply,
            } => {
                if self.stopping {
                    let _ = reply.send(Err(stopped()));
                    return Ok(());
                }
                if self.transactions.len() >= 64 {
                    let _ = reply.send(Err(io::Error::from_raw_os_error(libc::EAGAIN)));
                    return Ok(());
                }
                for key in &keys {
                    if let Some(binding) = self.bindings.get_mut(key) {
                        binding.permission = Some(permission.clone());
                    }
                }
                self.transactions.push(Transaction::Allow(keys, reply));
            }
            Command::Withdraw {
                keys,
                remove,
                reply,
            } => {
                if self.transactions.len() >= 64 {
                    return Err(io::Error::other("withdrawal capacity exhausted"));
                }
                for &key in &keys {
                    if let Some(binding) = self.bindings.get_mut(&key) {
                        binding.permission = None;
                        if remove {
                            self.connections.close(key);
                        } else if self.connections.pause(key) {
                            let deadline = Instant::now() + Duration::from_secs(2);
                            binding.disable_deadline = Some(
                                binding
                                    .disable_deadline
                                    .map_or(deadline, |old| old.min(deadline)),
                            );
                        }
                        self.devices.retire_inputs(key);
                    }
                }
                self.transactions.push(Transaction::Withdraw(keys, reply));
            }
            Command::Revoke { keep, reply } => {
                if self.transactions.len() >= 64 {
                    return Err(io::Error::other("withdrawal capacity exhausted"));
                }
                self.devices.retire_outdated(&keep);
                self.transactions.push(Transaction::Revoke {
                    keep: Some(keep),
                    running: false,
                    complete: false,
                    reply: Some(reply),
                });
            }
            Command::Shutdown { reply } => {
                self.stop();
                self.transactions.push(Transaction::Shutdown(reply));
            }
        }
        Ok(())
    }
    fn add(
        &mut self,
        descriptor: OwnedFd,
        permission: Option<Permit>,
    ) -> io::Result<RegisteredConnection> {
        if self.stopping {
            return Err(stopped());
        }
        let quota = self
            .quota
            .clone()
            .try_acquire_owned()
            .map_err(|_| io::Error::from_raw_os_error(libc::EMFILE))?;
        let key = ConnectionKey::generate();
        let handle = descriptor.as_raw_fd() as u32;
        self.devices.register(key)?;
        let (port, output, closed) = connection::channel();
        let close = self.connections.add(key, port);
        let requests = self.request_sender.clone();
        let deliveries = self.delivery_sender.clone();
        self.transports.spawn(async move {
            (
                key,
                connection::run(key, descriptor, output, closed, requests, deliveries).await,
            )
        });
        self.bindings.insert(
            key,
            Binding {
                permission,
                active: false,
                job: false,
                switches: 0,
                disable_deadline: None,
                _quota: quota,
            },
        );
        Ok(RegisteredConnection { key, handle, close })
    }
    fn packet(&mut self, request: connection::Request<ConnectionKey>) -> io::Result<()> {
        let connection::Request {
            connection: key,
            packet,
            done,
        } = request;
        if !self.connections.valid_packet(key, &packet) {
            self.connections.close(key);
            return Ok(());
        }
        match packet.opcode {
            wire::CLIENT_OPEN_SEAT => {
                if self.connections.open_seat(key) {
                    self.connections
                        .send(key, wire::seat_opened(&self.seat)?, None);
                } else {
                    self.connections.send(key, wire::error(libc::EBUSY), None);
                }
            }
            wire::CLIENT_CLOSE_SEAT => {
                self.connections.close_seat(key, done);
                return Ok(());
            }
            wire::CLIENT_DISABLE_SEAT => {
                self.connections.acknowledge(key);
                if self.connections[&key].membership == Membership::Disabled {
                    self.bindings
                        .get_mut(&key)
                        .expect("member")
                        .disable_deadline = None;
                }
            }
            wire::CLIENT_PING => {
                self.connections
                    .send(key, wire::empty(wire::SERVER_PONG), None);
            }
            wire::CLIENT_OPEN_DEVICE => {
                let permission = self
                    .connections
                    .get(&key)
                    .filter(|entry| entry.live() && entry.membership == Membership::Enabled)
                    .and_then(|entry| entry.epoch.clone())
                    .filter(Permit::is_open);
                if let Some(permission) = permission {
                    let event = Event::Open {
                        key,
                        path: wire::parse_path(&packet.payload)
                            .map_err(io::Error::from_raw_os_error)?,
                        permission,
                        done,
                    };
                    if let Err(error) = self.events.try_send(event)
                        && let Event::Open { done, .. } = error.into_inner()
                    {
                        self.connections.send(key, wire::error(libc::EAGAIN), None);
                        let _ = done.send(());
                    }
                    return Ok(());
                }
                self.connections.send(key, wire::error(libc::EACCES), None);
            }
            wire::CLIENT_CLOSE_DEVICE => {
                let number =
                    wire::parse_i32(&packet.payload).map_err(io::Error::from_raw_os_error)?;
                if let Some(reply) = self.devices.close(key, number, done) {
                    self.device_reply(reply)?;
                }
                return Ok(());
            }
            wire::CLIENT_SWITCH_SESSION => {
                let target =
                    wire::parse_i32(&packet.payload).map_err(io::Error::from_raw_os_error)?;
                let permission = self
                    .connections
                    .get(&key)
                    .filter(|entry| entry.live() && entry.membership == Membership::Enabled)
                    .and_then(|entry| entry.epoch.clone())
                    .filter(Permit::is_open);
                if let Some(permission) = permission.filter(|_| (1..=63).contains(&target)) {
                    let event = Event::Switch {
                        key,
                        target: target as u32,
                        permission,
                        done,
                    };
                    match self.events.try_send(event) {
                        Ok(()) => {
                            self.bindings.get_mut(&key).expect("member").switches += 1;
                        }
                        Err(error) => {
                            if let Event::Switch { done, .. } = error.into_inner() {
                                self.connections.send(key, wire::error(libc::EAGAIN), None);
                                let _ = done.send(());
                            }
                        }
                    }
                    return Ok(());
                }
                self.connections.send(key, wire::error(libc::EACCES), None);
            }
            _ => self.connections.close(key),
        }
        let _ = done.send(());
        Ok(())
    }
    fn progress(&mut self) -> io::Result<()> {
        let keys: Vec<_> = self.bindings.keys().copied().collect();
        for key in keys {
            let connection = &self.connections[&key];
            let binding = self.bindings.get_mut(&key).expect("binding");
            if binding
                .disable_deadline
                .is_some_and(|deadline| deadline <= Instant::now())
            {
                if connection.membership == Membership::PendingDisable {
                    self.connections.close(key);
                }
                binding.disable_deadline = None;
            }
            if !self.connections[&key].live() && !self.connections[&key].gone {
                self.connections.close(key);
            }
            let connection = &self.connections[&key];
            if connection.cleanup && !binding.job && !self.devices.running(key) {
                if let Ok(quota) = self.workers.clone().try_acquire_owned() {
                    self.devices.begin_cleanup(key);
                    self.connections.cleanup_started(key);
                    binding.job = true;
                    self.spawn(Work::Close(key), quota, None);
                }
                continue;
            }
            if connection.cleanup || !connection.live() {
                continue;
            }
            let wants = binding.permission.as_ref().is_some_and(Permit::is_open)
                && connection.membership != Membership::Connected;
            if wants != binding.active && !binding.job && !self.devices.running(key) {
                if let Ok(quota) = self.workers.clone().try_acquire_owned() {
                    binding.job = true;
                    let permission = binding.permission.clone();
                    self.spawn(
                        if wants {
                            Work::Activate(key)
                        } else {
                            Work::Deactivate(key)
                        },
                        quota,
                        permission,
                    );
                }
            } else if wants
                && binding.active
                && !binding.job
                && connection.membership == Membership::Disabled
            {
                self.connections.enable(key, binding.permission.as_ref())?;
            }
        }
        self.devices.settle_retired();
        // Unlisted work waits for registered opens, never for a State callback.
        let settled = !self.devices.has_jobs();
        if settled {
            for transaction in &mut self.transactions {
                if let Transaction::Revoke {
                    keep,
                    running,
                    complete,
                    ..
                } = transaction
                    && !*running
                    && !*complete
                    && let Ok(quota) = self.workers.clone().try_acquire_owned()
                {
                    let keep = keep.take().expect("owned removal batch");
                    *running = true;
                    let resources = self.resources.clone();
                    self.jobs.spawn(async move {
                        let errors = tokio::task::spawn_blocking(move || {
                            let _quota = quota;
                            resources.revoke_unlisted(&keep)
                        })
                        .await
                        .expect("revoke worker panicked");
                        Completion {
                            work: Work::Revoke,
                            errors,
                        }
                    });
                    break;
                }
            }
        }
        let mut pending = Vec::new();
        for transaction in self.transactions.drain(..) {
            if let Transaction::Allow(keys, _) = &transaction
                && keys.iter().any(|key| {
                    self.bindings.get(key).is_some_and(|binding| {
                        binding
                            .permission
                            .as_ref()
                            .is_none_or(|permission| !permission.is_open())
                    })
                })
            {
                if let Transaction::Allow(_, reply) = transaction {
                    let _ = reply.send(Err(io::Error::from_raw_os_error(libc::EACCES)));
                }
                continue;
            }
            let complete = match &transaction {
                Transaction::Allow(keys, _) => keys.iter().all(|key| {
                    self.bindings.get(key).is_none_or(|binding| {
                        let entry = &self.connections[key];
                        (entry.membership == Membership::Connected
                            || (entry.membership == Membership::Enabled
                                && self.connections.enable_delivered(*key)))
                            && !binding.job
                            && !entry.cleanup
                            && entry.live()
                    })
                }),
                Transaction::Withdraw(keys, _) => keys.iter().all(|key| {
                    self.bindings.get(key).is_none_or(|binding| {
                        !binding.active
                            && !binding.job
                            && !self.devices.pending(*key)
                            && self.connections[key].membership != Membership::PendingDisable
                            && !self.connections[key].cleanup
                    })
                }),
                Transaction::Revoke { complete, .. } => *complete && settled,
                Transaction::Shutdown(_) => false,
            };
            if complete {
                finish(transaction);
            } else {
                pending.push(transaction);
            }
        }
        self.transactions = pending;
        Ok(())
    }
    fn spawn(&mut self, work: Work, quota: OwnedSemaphorePermit, permission: Option<Permit>) {
        let key = match work {
            Work::Activate(key) | Work::Deactivate(key) | Work::Close(key) => key,
            Work::Revoke => unreachable!(),
        };
        let owner = self.devices.owner(key).expect("retained device owner");
        let resources = self.resources.clone();
        self.jobs.spawn(async move {
            let errors = tokio::task::spawn_blocking(move || {
                let _quota = quota;
                match work {
                    Work::Activate(_) => {
                        let permission = permission.expect("permission");
                        if permission.is_open() {
                            resources.activate_owner(owner, &permission)
                        } else {
                            Vec::new()
                        }
                    }
                    Work::Deactivate(_) => resources.deactivate_owner(owner),
                    Work::Close(_) => resources.close_owner(owner),
                    Work::Revoke => unreachable!(),
                }
            })
            .await
            .expect("device owner worker panicked");
            Completion { work, errors }
        });
    }
    fn complete(&mut self, mut completion: Completion) -> io::Result<()> {
        if let Work::Activate(key) = completion.work
            && self.bindings.get(&key).is_some_and(|binding| {
                binding
                    .permission
                    .as_ref()
                    .is_none_or(|permission| !permission.is_open())
            })
        {
            // A lifetime predicate can close between the precheck and the
            // resource mutex. Its explicit admission denial is not an ioctl
            // failure. Mark active below so normal progress MUST withdraw any
            // earlier successful activations before completing the transaction.
            completion
                .errors
                .retain(|error| error.raw_os_error() != Some(libc::EACCES));
        }
        if !completion.errors.is_empty() {
            return Err(io::Error::other(
                completion
                    .errors
                    .into_iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }
        match completion.work {
            Work::Activate(key) | Work::Deactivate(key) => {
                let binding = self.bindings.get_mut(&key).expect("job owner");
                binding.job = false;
                binding.active = matches!(completion.work, Work::Activate(_));
            }
            Work::Close(key) => {
                self.devices.cleaned(key);
                let binding = self.bindings.get_mut(&key).expect("job owner");
                binding.job = false;
                binding.active = false;
                self.connections.cleanup_completed(key, None);
                if self.connections[&key].gone {
                    self.devices.forget(key)?;
                    self.connections.remove(key)?;
                    self.bindings.remove(&key);
                    // The policy source is deliberately retired before bounded
                    // all-resource shutdown. Its handle bookkeeping is no longer
                    // required; actual originals/jobs still settle here.
                    if !self.stopping && !*self.emergency.borrow() {
                        self.events
                            .try_send(Event::Gone(key))
                            .map_err(|_| io::Error::other("required lifecycle input overflow"))?;
                    }
                }
            }
            Work::Revoke => {
                if let Some(Transaction::Revoke {
                    running, complete, ..
                }) = self.transactions.iter_mut().find(|t| {
                    matches!(
                        t,
                        Transaction::Revoke {
                            running: true,
                            complete: false,
                            ..
                        }
                    )
                }) {
                    *running = false;
                    *complete = true;
                }
            }
        }
        Ok(())
    }
    fn device_reply(&mut self, reply: crate::devices::Reply<ConnectionKey>) -> io::Result<()> {
        if self.devices.owner(reply.connection) != Some(reply.owner) {
            return Err(io::Error::other("stale resource completion"));
        }
        if let Some(error) = reply.error {
            return Err(io::Error::other(error));
        }
        if let (Some(output), Some((slot, permission))) =
            (reply.output.as_ref(), reply.publication.as_ref())
            && output.fd.is_some()
        {
            let key = reply.connection;
            let event = Event::Publish {
                key,
                slot: *slot,
                permission: permission.clone(),
                output: reply.output.expect("FD output"),
                done: reply.done,
            };
            if self.events.try_send(event).is_err() {
                self.connections.close(key);
            }
            return Ok(());
        }
        if let Some(output) = reply.output
            && let Some(entry) = self.connections.get(&reply.connection)
        {
            entry.send(output);
        }
        if reply.disconnect {
            self.connections.close(reply.connection);
        }
        if let Some(done) = reply.done {
            let _ = done.send(());
        }
        Ok(())
    }
    fn stop(&mut self) {
        self.stopping = true;
        self.resources.fence();
        for key in self.connections.keys().collect::<Vec<_>>() {
            self.connections.close(key);
        }
    }
}
impl Drop for Broker {
    fn drop(&mut self) {
        self.resources.fence();
    }
}
fn finish(transaction: Transaction) {
    let reply = match transaction {
        Transaction::Allow(_, reply)
        | Transaction::Withdraw(_, reply)
        | Transaction::Shutdown(reply) => Some(reply),
        Transaction::Revoke { reply, .. } => reply,
    };
    if let Some(reply) = reply {
        let _ = reply.send(Ok(()));
    }
}
fn stopped() -> io::Error {
    io::Error::from_raw_os_error(libc::ESHUTDOWN)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn shutdown_settles_transports_after_policy_capture_is_retired() {
        let resources = Arc::new(Resources::new(16).unwrap());
        let (broker, control, events) = Broker::new(
            "seat-test".into(),
            false,
            resources.clone(),
            Arc::new(Semaphore::new(2)),
        );
        let driver = tokio::spawn(broker.run());
        let (endpoint, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        control.add_connection(endpoint.into(), None).await.unwrap();
        control.emergency_stop();
        drop(events);
        tokio::time::timeout(Duration::from_secs(1), driver)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(resources.pending(), 0);
    }
}
