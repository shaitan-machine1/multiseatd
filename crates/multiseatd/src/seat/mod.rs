//! One serialized controller per seat. Context selection never follows socket
//! arrival/EOF; independent transports share only their context's policy.

mod broker;
pub mod connection;
mod grants;
pub mod policy;
mod terminal;

use crate::daemon::{Shutdown, ShutdownPhase};
use crate::registry::Registration;
use crate::resources::{ConnectionKey, Permit, Resources};
use crate::seatd::protocol as wire;
use libmultiseatd::contract::{ConnectionRow, ContextRow, ErrorKind, SeatRow};
use libmultiseatd::{ConnectionId, ContextId};
use seat_udev::SeatName;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant, interval};

type Reply = oneshot::Sender<Result<(), ErrorKind>>;

pub enum Command {
    Stop,
    PreparePolicy {
        policy: policy::Policy,
        reply: Reply,
    },
    CommitPolicy,
    Grant {
        context: ContextId,
        uid: u32,
        grant: bool,
        reply: Reply,
    },
    Register {
        context: ContextId,
        lifetime: Registration,
        reply: Reply,
    },
    Remove {
        context: ContextId,
        reply: Reply,
    },
    Activate {
        context: ContextId,
        reply: Reply,
    },
    Deactivate {
        context: ContextId,
        reply: Reply,
    },
    CreateConnection {
        context: ContextId,
        reply: oneshot::Sender<Result<ConnectionPublication, ErrorKind>>,
    },
    RemoveConnection {
        context: ContextId,
        connection: ConnectionId,
        reply: Reply,
    },
}

#[derive(Clone)]
pub struct Budget {
    connections: Arc<Semaphore>,
    workers: Arc<Semaphore>,
    descriptors: Arc<Semaphore>,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            connections: Arc::new(Semaphore::new(4096)),
            workers: Arc::new(Semaphore::new(64)),
            descriptors: Arc::new(Semaphore::new(1024)),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Status {
    pub seat: SeatRow,
    pub contexts: BTreeMap<ContextId, ContextRow>,
    pub connections: BTreeMap<ConnectionId, ConnectionRow>,
}

#[derive(Clone)]
pub struct Port {
    commands: mpsc::Sender<Command>,
    pub status: watch::Receiver<Status>,
    policy_gate: watch::Sender<Permit>,
}
impl Port {
    pub async fn prepare_policy(
        &self,
        policy: policy::Policy,
    ) -> Result<oneshot::Receiver<Result<(), ErrorKind>>, ErrorKind> {
        self.policy_gate.borrow().fence();
        let (reply, receiver) = oneshot::channel();
        self.commands
            .send(Command::PreparePolicy { policy, reply })
            .await
            .map_err(|_| ErrorKind::BackendFailure)?;
        Ok(receiver)
    }
    pub async fn commit_policy(&self) -> Result<(), ErrorKind> {
        self.commands
            .send(Command::CommitPolicy)
            .await
            .map_err(|_| ErrorKind::BackendFailure)
    }
    pub fn send(&self, command: Command) -> Result<(), ErrorKind> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ErrorKind::LimitExceeded,
                mpsc::error::TrySendError::Closed(_) => ErrorKind::BackendFailure,
            })
    }
}

pub struct ConnectionPublication {
    id: ConnectionId,
    #[cfg(test)]
    resource_owner: ConnectionKey,
    fd: Option<OwnedFd>,
    close: connection::Close,
    lifetime: Registration,
    committed: bool,
}
impl ConnectionPublication {
    pub fn id(&self) -> ConnectionId {
        self.id
    }
    pub fn publish<T>(
        mut self,
        send: impl FnOnce(ConnectionId, OwnedFd) -> io::Result<T>,
    ) -> io::Result<T> {
        if self.committed || !self.lifetime.is_live() || self.close.is_closed() {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        let fd = self
            .fd
            .take()
            .ok_or_else(|| io::Error::other("connection endpoint already consumed"))?;
        let result = send(self.id, fd)?;
        self.committed = true;
        Ok(result)
    }
}
impl Drop for ConnectionPublication {
    fn drop(&mut self) {
        if !self.committed {
            self.close.signal();
        }
    }
}

struct ContextState {
    grants: BTreeSet<u32>,
    lifetime: Registration,
    phase: &'static str,
    connections: BTreeSet<ConnectionId>,
    epoch: Option<Permit>,
    dirty: bool,
    revoking: bool,
    preparing: bool,
    prepared: bool,
    removing: bool,
    retry: Instant,
    error: String,
    removed: Vec<Reply>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Membership {
    Connected,
    Disabled,
    Enabled,
    PendingDisable,
}
impl Membership {
    fn name(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
            Self::PendingDisable => "pending-disable",
        }
    }
}

struct Client {
    resource_owner: ConnectionKey,
    slots: BTreeMap<i32, broker::Slot>,
    next_slot: i32,
    operations: usize,
    context: ContextId,
    membership: Membership,
    port: connection::Port,
    epoch: Option<Permit>,
    gone: bool,
    closing: bool,
    cleanup: bool,
    cleanup_running: bool,
    retry: Instant,
    error: String,
    enabled_tag: Option<u64>,
    close_seat: Option<oneshot::Sender<()>>,
    removed: Vec<Reply>,
    _quota: OwnedSemaphorePermit,
}

struct Mutation {
    grant: Option<(u32, bool)>,
    context: ContextId,
    activate: bool,
    reply: Reply,
}
struct Transition {
    requested: ContextId,
    activate: bool,
    target: Option<ContextId>,
    withdrawing: BTreeSet<ContextId>,
    pending_disable: BTreeSet<ConnectionId>,
    pending_enable: BTreeSet<ConnectionId>,
    deadline: Instant,
    enabling: bool,
    replies: Vec<Reply>,
    failure: Option<ErrorKind>,
}

#[derive(Clone, Copy)]
enum Job {
    Revoke(ContextId),
    Prepare(ContextId),
    Close(ConnectionId),
    Access(ContextId),
    IdleAccess,
}
struct Completion {
    job: Job,
    error: Option<String>,
}

pub struct Controller {
    name: SeatName,
    commands: mpsc::Receiver<Command>,
    status: watch::Sender<Status>,
    contexts: BTreeMap<ContextId, ContextState>,
    clients: BTreeMap<ConnectionId, Client>,
    requests: mpsc::Receiver<connection::Request>,
    request_sender: mpsc::Sender<connection::Request>,
    events: mpsc::Receiver<connection::Event>,
    event_sender: mpsc::Sender<connection::Event>,
    transports: JoinSet<(ConnectionId, io::Result<()>)>,
    jobs: JoinSet<Completion>,
    resources: Arc<Resources>,
    inventory: dev_broker::inventory::Inventory,
    access: Option<grants::Change>,
    idle_access: bool,
    policy: policy::Policy,
    policy_pending: Option<policy::Policy>,
    policy_replies: Vec<Reply>,
    policy_gate: watch::Sender<Permit>,
    topology_paused: bool,
    resume_policy: bool,
    device_jobs: JoinSet<broker::Completion>,
    budget: Budget,
    mutations: VecDeque<Mutation>,
    transition: Option<Transition>,
    selected: Option<ContextId>,
    effective: Option<ContextId>,
    tag: u64,
    vt: Option<crate::vt::Port>,
    vt_facts: Option<watch::Receiver<crate::vt::Facts>>,
    vt_generation: Option<u64>,
    vt_release_sent: Option<u64>,
    vt_requested: bool,
    vt_suspended: bool,
    switches: JoinSet<terminal::SwitchCompletion>,
}

impl Controller {
    pub fn new(name: SeatName, resources: Arc<Resources>, budget: Budget) -> (Self, Port) {
        let (commands, receiver) = mpsc::channel(256);
        let (policy_gate, _) = watch::channel(Permit::new());
        let (request_sender, requests) = mpsc::channel(256);
        let (event_sender, events) = mpsc::channel(256);
        let (status, snapshot) = watch::channel(Status {
            seat: (
                name.to_string(),
                0,
                true,
                String::new(),
                String::new(),
                "idle".into(),
                String::new(),
            ),
            contexts: BTreeMap::new(),
            connections: BTreeMap::new(),
        });
        (
            Self {
                name,
                commands: receiver,
                status,
                contexts: BTreeMap::new(),
                clients: BTreeMap::new(),
                requests,
                request_sender,
                events,
                event_sender,
                transports: JoinSet::new(),
                jobs: JoinSet::new(),
                resources,
                inventory: dev_broker::inventory::Inventory::new(),
                policy: policy::Policy::default(),
                access: None,
                idle_access: false,
                policy_pending: None,
                policy_replies: Vec::new(),
                policy_gate: policy_gate.clone(),
                topology_paused: false,
                resume_policy: false,
                device_jobs: JoinSet::new(),
                budget,
                mutations: VecDeque::new(),
                transition: None,
                selected: None,
                effective: None,
                tag: 0,
                vt: None,
                vt_facts: None,
                vt_generation: None,
                vt_release_sent: None,
                vt_requested: false,
                vt_suspended: false,
                switches: JoinSet::new(),
            },
            Port {
                commands,
                status: snapshot,
                policy_gate,
            },
        )
    }

    pub async fn run(mut self, mut shutdown: Shutdown) -> io::Result<()> {
        let mut quiescing = false;
        let mut stopping = false;
        let mut tick = interval(Duration::from_millis(25));
        let mut reconcile = interval(Duration::from_secs(1));
        loop {
            self.update_vt()?;
            self.retry_slots();
            self.drive_access();
            self.drive()?;
            self.vt_progress()?;
            self.policy_progress();
            self.snapshot();
            if stopping
                && self.transports.is_empty()
                && self.jobs.is_empty()
                && self.device_jobs.is_empty()
                && self.switches.is_empty()
            {
                return Ok(());
            }
            tokio::select! {
                biased;
                phase = shutdown.reached(if quiescing { ShutdownPhase::RestoreTerminal } else { ShutdownPhase::Quiesce }), if !stopping => {
                    quiescing = true;
                    stopping = phase >= ShutdownPhase::RestoreTerminal;
                    let contexts: Vec<_> = self.contexts.keys().copied().collect();
                    for context in contexts { self.remove_context(context, None); }
                }
                command = self.commands.recv(), if !stopping => {
                    let Some(command) = command else { return Err(io::Error::other("seat routing owner disappeared")) };
                    if matches!(command, Command::Stop) {
                        if !self.contexts.is_empty() { return Err(io::Error::other("seat stopped before cleanup")) }
                        stopping = true;
                    } else { self.command(command, quiescing)?; }
                }
                joined = self.transports.join_next(), if !self.transports.is_empty() => {
                    let (id, _io_result) = joined.expect("transport exists").map_err(io::Error::other)?;
                    self.transport_gone(id);
                }
                joined = self.jobs.join_next(), if !self.jobs.is_empty() => {
                    self.complete(joined.expect("job exists").map_err(io::Error::other)?);
                }
                joined = self.device_jobs.join_next(), if !self.device_jobs.is_empty() => {
                    self.device_completed(joined.expect("device job exists").map_err(io::Error::other)?);
                }
                joined = self.switches.join_next(), if !self.switches.is_empty() => {
                    self.switch_completed(joined.expect("switch exists").map_err(io::Error::other)?);
                }
                changed = terminal::changed(&mut self.vt_facts) => { changed?; }
                event = self.events.recv() => if let Some(connection::Event::Delivered { connection, tag }) = event
                    && let Some(client) = self.clients.get_mut(&connection) && client.enabled_tag == Some(tag)
                {
                    client.enabled_tag = None;
                    if let Some(transition) = &mut self.transition { transition.pending_enable.remove(&connection); }
                },
                _ = tick.tick() => {},
                _ = reconcile.tick() => self.reconcile_access(),
                request = self.requests.recv(), if !stopping => if let Some(request) = request { self.packet(request)?; },
            }
        }
    }

    fn command(&mut self, command: Command, quiescing: bool) -> io::Result<()> {
        match command {
            Command::Stop => unreachable!(),
            Command::PreparePolicy { policy, reply } => self.pause_policy(policy, reply),
            Command::CommitPolicy => self.commit_policy(),
            Command::Grant {
                context,
                uid,
                grant,
                reply,
            } => self.grant_request(context, uid, grant, reply, quiescing),
            Command::Register {
                context,
                lifetime,
                reply,
            } => {
                let result = if !quiescing && lifetime.is_live() {
                    self.contexts.entry(context).or_insert(ContextState {
                        grants: BTreeSet::new(),
                        lifetime,
                        phase: "inactive",
                        connections: BTreeSet::new(),
                        epoch: None,
                        dirty: false,
                        revoking: false,
                        preparing: false,
                        prepared: false,
                        removing: false,
                        retry: Instant::now(),
                        error: String::new(),
                        removed: Vec::new(),
                    });
                    Ok(())
                } else {
                    Err(ErrorKind::ContextRemoving)
                };
                self.snapshot();
                let _ = reply.send(result);
            }
            Command::Remove { context, reply } => self.remove_context(context, Some(reply)),
            Command::Activate { context, reply } => self.mutate(context, true, reply, quiescing),
            Command::Deactivate { context, reply } => self.mutate(context, false, reply, quiescing),
            Command::CreateConnection { context, reply } => {
                let result = if quiescing {
                    Err(ErrorKind::ContextRemoving)
                } else {
                    self.create_connection(context)
                };
                self.snapshot();
                let _ = reply.send(result);
            }
            Command::RemoveConnection {
                context,
                connection,
                reply,
            } => {
                if let Some(client) = self
                    .clients
                    .get_mut(&connection)
                    .filter(|client| client.context == context)
                {
                    client.removed.retain(|sender| !sender.is_closed());
                    if client.removed.len() == 64 {
                        let _ = reply.send(Err(ErrorKind::LimitExceeded));
                    } else {
                        client.removed.push(reply);
                        self.close_connection(connection);
                    }
                } else {
                    let _ = reply.send(Err(ErrorKind::UnknownConnection));
                }
            }
        }
        Ok(())
    }

    fn mutate(&mut self, context: ContextId, activate: bool, reply: Reply, quiescing: bool) {
        if !quiescing
            && !self.foreground()
            && self.mutations.len() < 256
            && self
                .contexts
                .get(&context)
                .is_some_and(|state| !state.removing && state.lifetime.is_live())
        {
            if activate || self.selected == Some(context) {
                let selected = activate.then_some(context);
                self.selected = selected;
                self.vt_requested = false;
                if let Some(transition) = &mut self.transition
                    && transition.target != selected
                {
                    transition.failure = Some(ErrorKind::TransitionPending);
                }
                let mut retained = VecDeque::new();
                for mutation in self.mutations.drain(..) {
                    if mutation.grant.is_none() {
                        let _ = mutation.reply.send(Err(ErrorKind::TransitionPending));
                    } else {
                        retained.push_back(mutation);
                    }
                }
                self.mutations = retained;
            } else if self.contexts[&context].phase == "inactive"
                && self.effective != Some(context)
                && !self
                    .mutations
                    .iter()
                    .any(|mutation| mutation.context == context)
            {
                let _ = reply.send(Ok(()));
                return;
            }
        }
        if quiescing
            || !self
                .contexts
                .get(&context)
                .is_some_and(|state| !state.removing && state.lifetime.is_live())
        {
            let _ = reply.send(Err(ErrorKind::ContextRemoving));
        } else if self.mutations.is_empty()
            && let Some(transition) = &mut self.transition
            && transition.requested == context
            && transition.activate == activate
        {
            transition.replies.retain(|reply| !reply.is_closed());
            if transition.replies.len() == 64 {
                let _ = reply.send(Err(ErrorKind::LimitExceeded));
            } else {
                transition.replies.push(reply);
            }
        } else if self.mutations.len() == 256 {
            let _ = reply.send(Err(ErrorKind::LimitExceeded));
        } else {
            self.mutations.push_back(Mutation {
                grant: None,
                context,
                activate,
                reply,
            });
        }
    }

    fn create_connection(
        &mut self,
        context: ContextId,
    ) -> Result<ConnectionPublication, ErrorKind> {
        let state = self
            .contexts
            .get(&context)
            .ok_or(ErrorKind::UnknownContext)?;
        if state.removing || !state.lifetime.is_live() {
            return Err(ErrorKind::ContextRemoving);
        }
        if state.connections.len() == 64 {
            return Err(ErrorKind::LimitExceeded);
        }
        let quota = self
            .budget
            .connections
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorKind::LimitExceeded)?;
        let (server, endpoint) = UnixStream::pair().map_err(|_| ErrorKind::BackendFailure)?;
        let id = ConnectionId::generate();
        if self.clients.contains_key(&id) {
            return Err(ErrorKind::BackendFailure);
        }
        let lifetime = state.lifetime.clone();
        let resource_owner = ConnectionKey::generate();
        let (port, output, closed) = connection::channel();
        let close = port.close.clone();
        let requests = self.request_sender.clone();
        let events = self.event_sender.clone();
        self.transports.spawn(async move {
            (
                id,
                connection::run(id, server.into(), output, closed, requests, events).await,
            )
        });
        self.clients.insert(
            id,
            Client {
                resource_owner,
                slots: BTreeMap::new(),
                next_slot: 1,
                operations: 0,
                context,
                membership: Membership::Connected,
                port,
                epoch: None,
                gone: false,
                closing: false,
                cleanup: false,
                cleanup_running: false,
                retry: Instant::now(),
                error: String::new(),
                enabled_tag: None,
                close_seat: None,
                removed: Vec::new(),
                _quota: quota,
            },
        );
        self.contexts
            .get_mut(&context)
            .expect("context")
            .connections
            .insert(id);
        Ok(ConnectionPublication {
            id,
            #[cfg(test)]
            resource_owner,
            fd: Some(endpoint.into()),
            close,
            lifetime,
            committed: false,
        })
    }

    fn send(&self, id: ConnectionId, bytes: Vec<u8>, tag: Option<u64>) -> bool {
        self.clients.get(&id).is_some_and(|client| {
            client.port.send(connection::Output {
                bytes,
                fd: None,
                tag,
                quota: None,
            })
        })
    }

    fn enable(&mut self, id: ConnectionId) -> io::Result<bool> {
        self.tag = self
            .tag
            .checked_add(1)
            .ok_or_else(|| io::Error::other("output generation exhaustion"))?;
        let client = self.clients.get_mut(&id).expect("connection");
        client.membership = Membership::Enabled;
        client.enabled_tag = Some(self.tag);
        let context = &self.contexts[&client.context];
        client.epoch = context
            .epoch
            .as_ref()
            .map(|epoch| epoch.gated(client.port.close.gate()));
        Ok(self.send(id, wire::empty(wire::SERVER_ENABLE_SEAT), Some(self.tag)))
    }

    fn fence_context(&mut self, id: ContextId, pending: &mut BTreeSet<ConnectionId>) {
        let Some(context) = self.contexts.get_mut(&id) else {
            return;
        };
        if let Some(epoch) = &context.epoch {
            epoch.fence();
        }
        context.phase = if context.removing {
            "removing"
        } else {
            "deactivating"
        };
        context.prepared = false;
        let connections: Vec<_> = context.connections.iter().copied().collect();
        self.retire_inputs(id);
        for connection in connections {
            let client = self
                .clients
                .get_mut(&connection)
                .expect("context connection");
            if let Some(epoch) = &client.epoch {
                epoch.fence();
            }
            if client.membership == Membership::Enabled {
                client.membership = Membership::PendingDisable;
                pending.insert(connection);
                self.send(connection, wire::empty(wire::SERVER_DISABLE_SEAT), None);
            }
        }
    }

    fn remove_context(&mut self, id: ContextId, reply: Option<Reply>) {
        let Some(context) = self.contexts.get_mut(&id) else {
            if let Some(reply) = reply {
                let _ = reply.send(Ok(()));
            }
            return;
        };
        context.removing = true;
        context.grants.clear();
        context.phase = "removing";
        if let Some(epoch) = &context.epoch {
            epoch.fence();
        }
        if let Some(reply) = reply {
            context.removed.retain(|sender| !sender.is_closed());
            if context.removed.len() < 64 {
                context.removed.push(reply);
            } else {
                let _ = reply.send(Err(ErrorKind::LimitExceeded));
            }
        }
        let connections: Vec<_> = context.connections.iter().copied().collect();
        for connection in connections {
            self.close_connection(connection);
        }
        if self.selected == Some(id) {
            self.selected = None;
        }
        if self.effective == Some(id) {
            self.effective = None;
        }
        if let Some(transition) = &mut self.transition {
            if transition.target == Some(id) {
                transition.target = None;
                transition.failure = Some(ErrorKind::ContextRemoving);
            }
            if self.contexts[&id].dirty {
                transition.withdrawing.insert(id);
            }
        }
    }

    fn close_connection(&mut self, id: ConnectionId) {
        if let Some(client) = self.clients.get_mut(&id) {
            client.closing = true;
            client.port.close.signal();
            if let Some(epoch) = &client.epoch {
                epoch.fence();
            }
        }
    }

    fn transport_gone(&mut self, id: ConnectionId) {
        let Some(client) = self.clients.get_mut(&id) else {
            return;
        };
        client.gone = true;
        client.closing = true;
        client.cleanup = true;
        if let Some(epoch) = &client.epoch {
            epoch.fence();
        }
        if let Some(transition) = &mut self.transition {
            transition.pending_disable.remove(&id);
            if transition.pending_enable.remove(&id) {
                transition.failure = Some(ErrorKind::BackendFailure);
            }
        }
    }

    fn job(&mut self, job: Job) -> bool {
        let Ok(quota) = self.budget.workers.clone().try_acquire_owned() else {
            return false;
        };
        let resources = self.resources.clone();
        let owners: Vec<(ConnectionKey, Option<Permit>)> = match job {
            Job::Revoke(id) => self.contexts[&id]
                .connections
                .iter()
                .map(|owner| (self.clients[owner].resource_owner, None))
                .collect(),
            Job::Prepare(id) => {
                let context = &self.contexts[&id];
                let epoch = context.epoch.as_ref().expect("activation epoch").clone();
                context
                    .connections
                    .iter()
                    .filter_map(|id| {
                        let client = self.clients.get_mut(id).expect("context connection");
                        if client.gone
                            || client.closing
                            || client.port.close.is_closed()
                            || client.membership == Membership::Connected
                        {
                            return None;
                        }
                        let permit = epoch.gated(client.port.close.gate());
                        client.epoch = Some(permit.clone());
                        Some((client.resource_owner, Some(permit)))
                    })
                    .collect()
            }
            Job::Close(id) => vec![(self.clients[&id].resource_owner, None)],
            Job::Access(_) | Job::IdleAccess => Vec::new(),
        };
        let (nodes, users, node_permit) = match job {
            Job::Revoke(_) | Job::IdleAccess => {
                (self.policy.nodes.clone(), BTreeSet::new(), Permit::new())
            }
            Job::Prepare(id) => (
                self.policy.nodes.clone(),
                self.contexts[&id].grants.clone(),
                self.contexts[&id].epoch.clone().expect("activation permit"),
            ),
            Job::Access(id) => {
                let state = &self.contexts[&id];
                let permit = state.epoch.clone().unwrap_or_default();
                let users = if self.effective == Some(id) && !state.removing && permit.is_open() {
                    state.grants.clone()
                } else {
                    BTreeSet::new()
                };
                (self.policy.nodes.clone(), users, permit)
            }
            Job::Close(_) => (BTreeSet::new(), BTreeSet::new(), Permit::new()),
        };
        self.jobs.spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let _quota = quota;
                let mut errors = Vec::new();
                for (owner, permit) in owners {
                    errors.extend(match job {
                        Job::Revoke(_) => resources.deactivate_owner(owner),
                        Job::Prepare(_) => resources
                            .activate_owner(owner, permit.as_ref().expect("activation epoch")),
                        Job::Close(_) => resources.close_owner(owner),
                        Job::Access(_) | Job::IdleAccess => Vec::new(),
                    });
                }
                for node in nodes {
                    if let Err(error) = resources.apply(node, &users, &node_permit) {
                        errors.push(error);
                    }
                }
                Completion {
                    job,
                    error: errors.first().map(ToString::to_string),
                }
            })
            .await;
            match result {
                Ok(result) => result,
                Err(error) => std::panic::resume_unwind(if error.is_panic() {
                    error.into_panic()
                } else {
                    Box::new("blocking owner cancelled")
                }),
            }
        });
        true
    }

    fn complete(&mut self, completion: Completion) {
        match completion.job {
            Job::IdleAccess => {
                self.idle_access = false;
                if let Some(error) = completion.error {
                    tracing::warn!(%error, seat = %self.name, "idle ACL reconciliation failed");
                }
            }
            Job::Access(id) => self.access_completed(id, completion.error),
            Job::Revoke(id) => {
                if let Some(context) = self.contexts.get_mut(&id) {
                    context.revoking = false;
                    if let Some(error) = completion.error {
                        context.error = error;
                        context.retry = Instant::now() + Duration::from_secs(1);
                    } else {
                        context.dirty = false;
                        context.error.clear();
                        context.phase = if context.removing {
                            "removing"
                        } else {
                            "inactive"
                        };
                    }
                }
            }
            Job::Prepare(id) => {
                if let Some(context) = self.contexts.get_mut(&id) {
                    context.preparing = false;
                    if let Some(error) = completion.error {
                        context.error = error;
                        if let Some(transition) = &mut self.transition {
                            transition.failure = Some(ErrorKind::BackendFailure);
                        }
                    } else {
                        context.prepared = true;
                    }
                }
            }
            Job::Close(id) => {
                let Some(client) = self.clients.get_mut(&id) else {
                    return;
                };
                client.cleanup_running = false;
                if let Some(error) = completion.error {
                    client.error = error;
                    client.retry = Instant::now() + Duration::from_secs(1);
                } else {
                    client.cleanup = false;
                    client.slots.clear();
                    client.error.clear();
                    if let Some(done) = client.close_seat.take() {
                        self.send(id, wire::empty(wire::SERVER_SEAT_CLOSED), None);
                        let _ = done.send(());
                    }
                }
            }
        }
    }

    fn drive(&mut self) -> io::Result<()> {
        let dead: Vec<_> = self
            .contexts
            .iter()
            .filter(|(_, state)| !state.removing && !state.lifetime.is_live())
            .map(|(id, _)| *id)
            .collect();
        for id in dead {
            self.remove_context(id, None);
        }
        let cleanup: Vec<_> = self
            .clients
            .iter()
            .filter(|(_, client)| {
                client.cleanup
                    && !client.cleanup_running
                    && client.operations == 0
                    && client.retry <= Instant::now()
            })
            .map(|(id, _)| *id)
            .collect();
        for id in cleanup {
            if self.job(Job::Close(id)) {
                self.clients.get_mut(&id).expect("client").cleanup_running = true;
            }
        }
        let removed: Vec<_> = self
            .clients
            .iter()
            .filter(|(_, client)| client.gone && !client.cleanup && !client.cleanup_running)
            .map(|(id, _)| *id)
            .collect();
        for id in removed {
            let client = self.clients.remove(&id).expect("client");
            if let Some(context) = self.contexts.get_mut(&client.context) {
                context.connections.remove(&id);
            }
            for reply in client.removed {
                let _ = reply.send(Ok(()));
            }
        }
        if !self.topology_paused
            && self.access.is_none()
            && !self.idle_access
            && self.transition.is_none()
            && let Some(mutation) = self.mutations.pop_front()
        {
            if let Some((uid, grant)) = mutation.grant {
                self.begin_grant(mutation.context, uid, grant, mutation.reply);
            } else if !self
                .contexts
                .get(&mutation.context)
                .is_some_and(|state| !state.removing && state.lifetime.is_live())
            {
                let _ = mutation.reply.send(Err(ErrorKind::ContextRemoving));
            } else if (mutation.activate && self.effective == Some(mutation.context))
                || (!mutation.activate
                    && self.selected != Some(mutation.context)
                    && self.effective != Some(mutation.context))
            {
                let _ = mutation.reply.send(Ok(()));
            } else {
                let target = mutation.activate.then_some(mutation.context);
                self.selected = target;
                // Removal clears the effective reference immediately, but it
                // does not erase its resource barrier. Include every retained
                // predecessor, not just the last effective-context pointer.
                let mut withdrawing: BTreeSet<_> = self
                    .contexts
                    .iter()
                    .filter(|(id, state)| {
                        Some(**id) != target
                            && (state.dirty
                                || state.revoking
                                || state.preparing
                                || self.context_operations(**id))
                    })
                    .map(|(id, _)| *id)
                    .collect();
                let mut pending_disable = BTreeSet::new();
                if let Some(old) = self.effective.take() {
                    withdrawing.insert(old);
                }
                for old in &withdrawing {
                    self.fence_context(*old, &mut pending_disable);
                }
                if let Some(id) = target {
                    let epoch = self.epoch(id);
                    let state = self.contexts.get_mut(&id).expect("target");
                    state.phase = "activating";
                    state.epoch = Some(epoch);
                    state.prepared = false;
                }
                self.transition = Some(Transition {
                    requested: mutation.context,
                    activate: mutation.activate,
                    target,
                    withdrawing,
                    pending_disable,
                    pending_enable: BTreeSet::new(),
                    deadline: Instant::now() + Duration::from_secs(2),
                    enabling: false,
                    replies: vec![mutation.reply],
                    failure: None,
                });
            }
        }
        let revoke: Vec<_> = self
            .contexts
            .iter()
            .filter(|(_, state)| {
                state.dirty
                    && !state.revoking
                    && !state.preparing
                    && state.retry <= Instant::now()
                    && matches!(state.phase, "deactivating" | "removing")
            })
            .map(|(id, _)| *id)
            .collect();
        for id in revoke {
            if self.job(Job::Revoke(id)) {
                self.contexts.get_mut(&id).expect("context").revoking = true;
            }
        }
        if let Some(mut transition) = self.transition.take() {
            transition.pending_disable.retain(|id| {
                self.clients.get(id).is_some_and(|client| {
                    !client.gone && client.membership == Membership::PendingDisable
                })
            });
            if Instant::now() >= transition.deadline {
                for id in &transition.pending_disable {
                    self.close_connection(*id);
                }
            }
            if transition.failure.is_some()
                && let Some(target) = transition.target.take()
            {
                if !self.topology_paused && !self.vt_suspended && self.foreground() {
                    self.selected = None;
                }
                self.effective = None;
                transition.withdrawing.insert(target);
                transition.pending_enable.clear();
                transition.enabling = false;
                transition.deadline = Instant::now() + Duration::from_secs(2);
                self.fence_context(target, &mut transition.pending_disable);
            }
            let withdrawn = transition.withdrawing.iter().all(|id| {
                self.contexts
                    .get(id)
                    .is_none_or(|state| !state.dirty && !state.revoking && !state.preparing)
                    && !self.context_operations(*id)
                    && !self.access_pending(*id)
            });
            if withdrawn && transition.pending_disable.is_empty() {
                for id in &transition.withdrawing {
                    if let Some(state) = self.contexts.get_mut(id)
                        && !state.removing
                    {
                        state.phase = "inactive";
                    }
                }
                if let Some(target) = transition.target.filter(|_| self.foreground()) {
                    if !self.contexts[&target].prepared && !self.contexts[&target].preparing {
                        let epoch = self.epoch(target);
                        self.contexts.get_mut(&target).expect("target").epoch = Some(epoch);
                    }
                    let state = self.contexts.get_mut(&target).expect("target");
                    if !state.prepared && !state.preparing {
                        state.dirty = true;
                        if self.job(Job::Prepare(target)) {
                            self.contexts.get_mut(&target).expect("target").preparing = true;
                        }
                    } else if state.prepared && !transition.enabling {
                        self.effective = Some(target);
                        transition.enabling = true;
                        let members: Vec<_> = state
                            .connections
                            .iter()
                            .copied()
                            .filter(|id| {
                                self.clients.get(id).is_some_and(|client| {
                                    client.membership == Membership::Disabled && !client.closing
                                })
                            })
                            .collect();
                        for id in members {
                            transition.pending_enable.insert(id);
                            if !self.enable(id)? {
                                transition.failure = Some(ErrorKind::BackendFailure);
                            }
                        }
                    }
                    if transition.enabling
                        && transition.pending_enable.is_empty()
                        && transition.failure.is_none()
                    {
                        self.contexts.get_mut(&target).expect("target").phase = "active";
                        for reply in transition.replies {
                            let _ = reply.send(Ok(()));
                        }
                    } else {
                        self.transition = Some(transition);
                    }
                } else if let Some(target) = transition.target {
                    self.request_foreground(target)?;
                    self.transition = Some(transition);
                } else {
                    for reply in transition.replies {
                        let _ = reply.send(transition.failure.map_or(Ok(()), Err));
                    }
                }
            } else {
                self.transition = Some(transition);
            }
        }
        let removed: Vec<_> = self
            .contexts
            .iter()
            .filter(|(id, state)| {
                state.removing
                    && state.connections.is_empty()
                    && !state.dirty
                    && !state.preparing
                    && !state.revoking
                    && !self.access_pending(**id)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in removed {
            let state = self.contexts.remove(&id).expect("context");
            for reply in state.removed {
                let _ = reply.send(Ok(()));
            }
        }
        Ok(())
    }

    fn packet(&mut self, request: connection::Request) -> io::Result<()> {
        let connection::Request {
            connection: id,
            packet,
            done,
        } = request;
        let Some(client) = self.clients.get(&id) else {
            return Ok(());
        };
        if client.closing
            || client.port.close.is_closed()
            || !self.contexts[&client.context].lifetime.is_live()
        {
            self.close_connection(id);
            return Ok(());
        }
        let member = client.membership != Membership::Connected;
        let valid = match packet.opcode {
            wire::CLIENT_OPEN_SEAT
            | wire::CLIENT_CLOSE_SEAT
            | wire::CLIENT_DISABLE_SEAT
            | wire::CLIENT_PING => wire::parse_empty(&packet.payload),
            wire::CLIENT_OPEN_DEVICE => wire::parse_path(&packet.payload).map(|_| ()),
            wire::CLIENT_CLOSE_DEVICE | wire::CLIENT_SWITCH_SESSION => {
                wire::parse_i32(&packet.payload).map(|_| ())
            }
            _ => Err(libc::EBADMSG),
        };
        if valid.is_err()
            || (packet.opcode != wire::CLIENT_OPEN_SEAT
                && packet.opcode != wire::CLIENT_PING
                && !member)
            || (packet.opcode == wire::CLIENT_OPEN_SEAT && member)
        {
            self.close_connection(id);
            return Ok(());
        }
        match packet.opcode {
            wire::CLIENT_PING => {
                self.send(id, wire::empty(wire::SERVER_PONG), None);
            }
            wire::CLIENT_OPEN_SEAT => {
                if self.clients[&id].cleanup {
                    self.send(id, wire::error(libc::EBUSY), None);
                } else {
                    self.clients.get_mut(&id).expect("client").membership = Membership::Disabled;
                    self.send(id, wire::seat_opened(self.name.as_str())?, None);
                    let context = self.clients[&id].context;
                    if self.effective == Some(context) {
                        let delivered = self.enable(id)?;
                        if let Some(transition) = &mut self.transition
                            && transition.target == Some(context)
                            && transition.enabling
                        {
                            transition.pending_enable.insert(id);
                            if !delivered {
                                transition.failure = Some(ErrorKind::BackendFailure);
                            }
                        }
                    }
                }
            }
            wire::CLIENT_CLOSE_SEAT => {
                let client = self.clients.get_mut(&id).expect("client");
                client.membership = Membership::Connected;
                client.cleanup = true;
                client.close_seat = Some(done);
                if let Some(epoch) = &client.epoch {
                    epoch.fence();
                }
                if let Some(transition) = &mut self.transition {
                    transition.pending_disable.remove(&id);
                    transition.pending_enable.remove(&id);
                }
                return Ok(());
            }
            wire::CLIENT_DISABLE_SEAT => {
                if self.clients[&id].membership == Membership::PendingDisable
                    || self.clients[&id].membership == Membership::Disabled
                {
                    self.clients.get_mut(&id).expect("client").membership = Membership::Disabled;
                    self.send(id, wire::empty(wire::SERVER_SEAT_DISABLED), None);
                } else {
                    self.close_connection(id);
                }
            }
            wire::CLIENT_OPEN_DEVICE => {
                self.open_device(
                    id,
                    wire::parse_path(&packet.payload).expect("validated path"),
                    done,
                );
                return Ok(());
            }
            wire::CLIENT_CLOSE_DEVICE => {
                self.close_device(
                    id,
                    wire::parse_i32(&packet.payload).expect("validated ID"),
                    done,
                );
                return Ok(());
            }
            wire::CLIENT_SWITCH_SESSION => {
                self.switch_protocol(
                    id,
                    wire::parse_i32(&packet.payload).expect("validated target"),
                    done,
                );
                return Ok(());
            }
            _ => unreachable!(),
        }
        let _ = done.send(());
        Ok(())
    }

    fn snapshot(&self) {
        let contexts = self
            .contexts
            .iter()
            .map(|(id, context)| {
                (
                    *id,
                    (
                        id.to_string(),
                        self.name.to_string(),
                        context.phase.into(),
                        context.grants.iter().copied().collect::<Vec<_>>(),
                        context
                            .connections
                            .iter()
                            .map(ToString::to_string)
                            .collect(),
                        self.selected == Some(*id),
                        self.effective == Some(*id),
                        context.error.clone(),
                    ),
                )
            })
            .collect();
        let connections = self
            .clients
            .iter()
            .map(|(id, client)| {
                (
                    *id,
                    (
                        id.to_string(),
                        client.context.to_string(),
                        self.name.to_string(),
                        client.membership.name().into(),
                        client.error.clone(),
                    ),
                )
            })
            .collect();
        self.status.send_replace(Status {
            seat: (
                self.name.to_string(),
                self.vt_facts
                    .as_ref()
                    .map(|facts| facts.borrow().terminal)
                    .unwrap_or(0),
                self.foreground(),
                self.selected.map(|id| id.to_string()).unwrap_or_default(),
                self.effective.map(|id| id.to_string()).unwrap_or_default(),
                if self.topology_paused {
                    "topology"
                } else if self.transition.is_some() {
                    "transition"
                } else {
                    "idle"
                }
                .into(),
                self.contexts
                    .values()
                    .find(|context| !context.error.is_empty())
                    .map(|context| context.error.clone())
                    .unwrap_or_default(),
            ),
            contexts,
            connections,
        });
    }
}

#[cfg(test)]
mod tests;
