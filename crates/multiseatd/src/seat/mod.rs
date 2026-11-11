//! Parent-owned callable seat. One State lock owns policy, catalog and ACL effects.
#[cfg(all(test, not(feature = "vt")))]
mod tests;
#[cfg(all(test, feature = "vt", feature = "test-support"))]
mod vt_tests;
use crate::{
    authority::{Authorities, AuthorityError, Registration},
    catalog::{DeviceCatalog, NODE_LIMIT},
    discovery::{self, Snapshot},
    fatal::{Budget, Error, Fatal, Result},
};
use dev_acl::AclRegistry;
use dev_broker::{broker, connection, permit::Permit, resources::ConnectionKey};
use libmultiseatd::{ContextId, ContextInfo, ErrorKind};
use seat_udev::{PhysicalHint, SeatName};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard, Semaphore, watch};
use tokio::time::{Instant, timeout_at};

const CONTEXT_LIMIT: usize = 128;
const CONNECTION_LIMIT: usize = 64;
struct Connection {
    handle: u32,
    close: connection::Close,
}
struct Context {
    #[cfg(feature = "vt")]
    vt: u32,
    grants: BTreeSet<u32>,
    connections: BTreeMap<ConnectionKey, Connection>,
    lifetime: Registration,
}
struct Applied {
    context: ContextId,
    permission: Permit,
}
#[cfg(feature = "vt")]
struct Foreground {
    observed: Option<u32>,
    available: bool,
}
#[cfg(feature = "vt")]
struct ForegroundWait {
    context: ContextId,
    deadline: Instant,
    alive: Arc<std::sync::atomic::AtomicBool>,
    started: Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(feature = "vt")]
struct WaitLifetime(Arc<std::sync::atomic::AtomicBool>);
#[cfg(feature = "vt")]
impl Drop for WaitLifetime {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}
struct State {
    catalog: DeviceCatalog,
    acl: AclRegistry,
    authorities: Authorities,
    contexts: BTreeMap<ContextId, Context>,
    applied: Option<Applied>,
    sequence: u64,
    #[cfg(not(feature = "vt"))]
    active: Option<ContextId>,
    #[cfg(feature = "vt")]
    active: BTreeMap<u32, ContextId>,
    #[cfg(feature = "vt")]
    foreground: Foreground,
    #[cfg(feature = "vt")]
    foreground_waits: Vec<ForegroundWait>,
}
pub struct Seat {
    name: SeatName,
    state: RwLock<State>,
    fatal: Fatal,
    broker: broker::Control,
    discovery: discovery::Control,
    changed: watch::Sender<u64>,
    #[cfg(feature = "vt")]
    vt: linux_vt::Control,
    #[cfg(feature = "vt")]
    configured_vts: BTreeSet<u32>,
}
/// A cancelled or panicking admitted operation fences BEFORE its guard unlocks.
struct Write<'a> {
    guard: RwLockWriteGuard<'a, State>,
    fatal: &'a Fatal,
    deadline: Instant,
    armed: bool,
    watch_token: u64,
}
impl Deref for Write<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        &self.guard
    }
}
impl DerefMut for Write<'_> {
    fn deref_mut(&mut self) -> &mut State {
        &mut self.guard
    }
}
impl Write<'_> {
    fn arm(&mut self) {
        if !self.armed {
            self.deadline = self
                .deadline
                .min(Instant::now() + crate::fatal::EFFECT_LIMIT);
            self.watch_token = self.fatal.begin_effect(self.deadline);
        }
        self.armed = true;
    }
    #[cfg(feature = "vt")]
    fn shorten_deadline(&mut self, deadline: Instant) {
        if deadline < self.deadline {
            self.deadline = deadline;
            if self.armed {
                self.watch_token = self.fatal.begin_effect(deadline);
            }
        }
    }
    fn settle<T>(mut self, result: Result<T>) -> Result<T> {
        let result = if result.is_ok() && self.armed && Instant::now() > self.deadline {
            Err(self
                .fatal
                .fail("State effects did not settle before the cumulative deadline"))
        } else {
            result
        };
        self.armed = false;
        self.fatal.end_effect(self.watch_token);
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                self.fatal.check()?;
                Ok(value)
            }
        }
    }
}
impl Drop for Write<'_> {
    fn drop(&mut self) {
        if self.armed || std::thread::panicking() {
            self.fatal
                .fail("admitted State operation cancelled or panicked before settlement");
        }
        self.fatal.end_effect(self.watch_token);
    }
}
struct Read<'a> {
    guard: RwLockReadGuard<'a, State>,
    fatal: &'a Fatal,
}
impl Deref for Read<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        &self.guard
    }
}
impl Drop for Read<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.fatal
                .fail("read operation panicked before State unlock");
        }
    }
}
impl Seat {
    pub fn new(
        name: SeatName,
        broker: broker::Control,
        discovery: discovery::Control,
        fatal: Fatal,
        workers: Arc<Semaphore>,
        #[cfg(feature = "vt")] vt: linux_vt::Control,
        #[cfg(feature = "vt")] configured_vts: BTreeSet<u32>,
    ) -> io::Result<Self> {
        let (changed, _) = watch::channel(0);
        let mut acl = AclRegistry::new(NODE_LIMIT, workers)?;
        let alive = fatal.gate();
        acl.set_lifetime(move || alive.load(std::sync::atomic::Ordering::Acquire));
        Ok(Self {
            state: RwLock::new(State {
                catalog: DeviceCatalog::new(name.clone()),
                acl,
                authorities: Authorities::new(CONTEXT_LIMIT, 1024).map_err(io::Error::other)?,
                contexts: BTreeMap::new(),
                applied: None,
                sequence: 0,
                #[cfg(not(feature = "vt"))]
                active: None,
                #[cfg(feature = "vt")]
                active: BTreeMap::new(),
                #[cfg(feature = "vt")]
                foreground: Foreground {
                    observed: None,
                    available: false,
                },
                #[cfg(feature = "vt")]
                foreground_waits: Vec::new(),
            }),
            name,
            fatal,
            broker,
            discovery,
            changed,
            #[cfg(feature = "vt")]
            vt,
            #[cfg(feature = "vt")]
            configured_vts,
        })
    }
    #[cfg(feature = "test-support")]
    pub fn inject_acl_fault(&self, fault: dev_acl::TestFault) -> io::Result<()> {
        self.state
            .try_write()
            .map_err(|_| io::Error::other("fixture injection requires exclusive startup"))?
            .acl
            .inject_fault(fault);
        Ok(())
    }
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }
    pub fn fatal(&self) -> &Fatal {
        &self.fatal
    }
    fn changed(&self) {
        self.changed.send_modify(|revision| {
            *revision = revision.checked_add(1).expect("revision exhaustion")
        });
    }
    async fn read(&self, budget: Budget) -> Result<Read<'_>> {
        self.fatal.check()?;
        let guard = timeout_at(budget.reply, self.state.read())
            .await
            .map_err(|_| Error::new(ErrorKind::Busy, "State read admission expired"))?;
        self.fatal.check()?;
        Ok(Read {
            guard,
            fatal: &self.fatal,
        })
    }
    async fn write(&self, budget: Budget) -> Result<Write<'_>> {
        self.fatal.check()?;
        let guard = timeout_at(budget.admission(), self.state.write())
            .await
            .map_err(|_| Error::new(ErrorKind::Busy, "State mutation admission expired"))?;
        self.fatal.check()?;
        budget.effect_deadline()?;
        Ok(Write {
            guard,
            fatal: &self.fatal,
            deadline: budget.admission(),
            armed: false,
            watch_token: 0,
        })
    }
    async fn source_write(&self) -> Result<Write<'_>> {
        self.fatal.check()?;
        let guard = self.state.write().await;
        self.fatal.check()?;
        Ok(Write {
            guard,
            fatal: &self.fatal,
            deadline: Instant::now() + crate::fatal::EFFECT_LIMIT,
            armed: false,
            watch_token: 0,
        })
    }
    async fn required<T>(
        &self,
        deadline: Instant,
        stage: &str,
        work: impl Future<Output = io::Result<T>>,
    ) -> Result<T> {
        match timeout_at(deadline, work).await {
            Ok(Ok(value)) if Instant::now() <= deadline => Ok(value),
            Ok(Ok(_)) => Err(self.fatal.fail(format!(
                "{stage}: required settlement arrived after the cumulative deadline"
            ))),
            Ok(Err(error)) => Err(self.fatal.fail(format!("{stage}: {error}"))),
            Err(_) => Err(self.fatal.fail(format!(
                "{stage}: cumulative required-effect deadline expired; started work remains owned"
            ))),
        }
    }
    fn authority_error(&self, error: AuthorityError) -> Error {
        match error {
            AuthorityError::AccessDenied => Error::new(ErrorKind::NotAuthorized, error.to_string()),
            AuthorityError::LimitExceeded => {
                Error::new(ErrorKind::LimitExceeded, error.to_string())
            }
            _ => self.fatal.fail(error.to_string()),
        }
    }
    fn live(&self, state: &State, id: ContextId) -> Result<()> {
        let context = state
            .contexts
            .get(&id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "context not found"))?;
        if context
            .lifetime
            .is_alive()
            .map_err(|error| self.fatal.fail(format!("context lifetime: {error}")))?
        {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::NotAuthorized,
                "context lifetime ended",
            ))
        }
    }
    fn eligible(&self, state: &State) -> Result<Option<ContextId>> {
        #[cfg(not(feature = "vt"))]
        let id = state.active;
        #[cfg(feature = "vt")]
        let id = state
            .foreground
            .observed
            .filter(|_| state.foreground.available)
            .and_then(|vt| state.active.get(&vt).copied());
        match id {
            None => Ok(None),
            Some(id) => match self.live(state, id) {
                Ok(()) => Ok(Some(id)),
                Err(error) if error.kind == ErrorKind::NotAuthorized => Ok(None),
                Err(error) => Err(error),
            },
        }
    }
    fn is_active(state: &State, id: ContextId) -> bool {
        #[cfg(not(feature = "vt"))]
        {
            state.active == Some(id)
        }
        #[cfg(feature = "vt")]
        {
            state
                .contexts
                .get(&id)
                .is_some_and(|context| state.active.get(&context.vt) == Some(&id))
        }
    }
    fn clear_active(state: &mut State, id: ContextId) {
        #[cfg(not(feature = "vt"))]
        if state.active == Some(id) {
            state.active = None;
        }
        #[cfg(feature = "vt")]
        if let Some(context) = state.contexts.get(&id)
            && state.active.get(&context.vt) == Some(&id)
        {
            state.active.remove(&context.vt);
        }
    }
    fn set_acl_target(&self, state: &mut State, target: &BTreeSet<u32>) -> Result<()> {
        let removed: Vec<_> = state
            .acl
            .desired_users()
            .difference(target)
            .copied()
            .collect();
        for uid in removed {
            state.acl.remove_acl_grant(uid);
        }
        for &uid in target {
            state
                .acl
                .add_acl_grant(uid)
                .map_err(|error| self.fatal.fail(format!("validated ACL target: {error}")))?;
        }
        Ok(())
    }
    async fn reconcile(
        &self,
        state: &mut State,
        deadline: Instant,
        force_acl: bool,
        exclude: Option<ContextId>,
    ) -> Result<()> {
        let candidate = self.eligible(state)?.filter(|id| Some(*id) != exclude);
        let same = state.applied.as_ref().is_some_and(|applied| {
            Some(applied.context) == candidate && applied.permission.is_open()
        });
        if state.applied.is_some() && !same {
            let previous = state.applied.as_ref().expect("applied");
            previous.permission.fence();
            let keys = state
                .contexts
                .get(&previous.context)
                .map(|context| context.connections.keys().copied().collect())
                .unwrap_or_default();
            self.set_acl_target(state, &BTreeSet::new())?;
            let State { catalog, acl, .. } = state;
            tokio::try_join!(
                self.required(
                    deadline,
                    "context broker withdrawal",
                    self.broker.withdraw_connections(keys, false)
                ),
                self.required(deadline, "context ACL withdrawal", async {
                    acl.clear_obsolete_device_acls(&catalog.view()).await
                }),
            )?;
            state.applied = None;
        }
        let Some(candidate) = candidate else {
            return Ok(());
        };
        if !same {
            let context = &state.contexts[&candidate];
            let lifetime = context.lifetime.clone();
            let permission = Permit::with_lifetime(move || lifetime.is_alive().unwrap_or(false))
                .gated(self.fatal.gate());
            let keys = context.connections.keys().copied().collect();
            let target = context.grants.clone();
            self.set_acl_target(state, &target)?;
            let acl_permission = permission.clone();
            state.acl.set_lifetime(move || acl_permission.is_open());
            let State { catalog, acl, .. } = state;
            tokio::try_join!(
                async {
                    match timeout_at(
                        deadline,
                        self.broker.allow_connections(keys, permission.clone()),
                    )
                    .await
                    {
                        Ok(Err(error))
                            if error.raw_os_error() == Some(libc::EACCES)
                                && !permission.is_open() =>
                        {
                            Ok(false)
                        }
                        Ok(Ok(())) => Ok(true),
                        Ok(Err(error)) => Err(self
                            .fatal
                            .fail(format!("context broker application: {error}"))),
                        Err(_) => Err(self
                            .fatal
                            .fail("context broker application deadline expired")),
                    }
                },
                self.required(deadline, "context ACL application", async {
                    acl.refresh_device_acls(&catalog.view()).await
                }),
            )?;
            // Failure fences and returns immediately, never waiting for the
            // other lane. Original resources/jobs remain owned for cleanup.
            state.applied = Some(Applied {
                context: candidate,
                permission,
            });
        } else if force_acl {
            let target = state.contexts[&candidate].grants.clone();
            self.set_acl_target(state, &target)?;
            let State { catalog, acl, .. } = state;
            self.required(
                deadline,
                "current context ACL application",
                acl.refresh_device_acls(&catalog.view()),
            )
            .await?;
        }
        // A lifetime may end while kernel work is running. Settle the real
        // effects before unlocking; it never selects a replacement context.
        if self.eligible(state)? != Some(candidate) {
            if let Some(applied) = &state.applied {
                applied.permission.fence();
            }
            let keys = state.contexts[&candidate]
                .connections
                .keys()
                .copied()
                .collect();
            self.set_acl_target(state, &BTreeSet::new())?;
            let State { catalog, acl, .. } = state;
            tokio::try_join!(
                self.required(
                    deadline,
                    "lost lifetime broker withdrawal",
                    self.broker.withdraw_connections(keys, false)
                ),
                self.required(deadline, "lost lifetime ACL withdrawal", async {
                    acl.clear_obsolete_device_acls(&catalog.view()).await
                }),
            )?;
            state.applied = None;
        }
        Ok(())
    }
    pub async fn initialize(&self) -> Result<()> {
        let mut op = self.write(Budget::new()).await?;
        let Snapshot { sequence, scan } = timeout_at(op.deadline, self.discovery.scan())
            .await
            .map_err(|_| Error::new(ErrorKind::NotReady, "initial scan deadline expired"))?
            .map_err(|error| Error::new(ErrorKind::NotReady, error.to_string()))?;
        if op.deadline <= Instant::now() + crate::fatal::MIN_EFFECT_WINDOW {
            return Err(Error::new(
                ErrorKind::NotReady,
                "no startup effect window remains",
            ));
        }
        if scan.nodes.len() > NODE_LIMIT {
            return Err(Error::new(ErrorKind::LimitExceeded, "initial node limit"));
        }
        op.arm();
        let deadline = op.deadline;
        let result = async {
            op.catalog
                .initialize(scan)
                .map_err(|error| self.fatal.fail(format!("initial catalog: {error}")))?;
            op.sequence = sequence;
            #[cfg(feature = "vt")]
            {
                let current = self
                    .required(deadline, "initial native foreground", self.vt.foreground())
                    .await?;
                op.foreground = Foreground {
                    observed: self.configured_vts.contains(&current).then_some(current),
                    available: true,
                };
            }
            let State { catalog, acl, .. } = &mut *op;
            self.required(
                deadline,
                "initial exact ACL cleanup",
                acl.refresh_device_acls(&catalog.view()),
            )
            .await
        }
        .await;
        op.settle(result)
    }
    pub async fn create_context(&self, vt: u32, budget: Budget) -> Result<(OwnedFd, ContextId)> {
        #[cfg(not(feature = "vt"))]
        if vt != 0 {
            return Err(Error::invalid("non-VT seat accepts binding zero only"));
        }
        #[cfg(feature = "vt")]
        if !self.configured_vts.contains(&vt) {
            return Err(Error::invalid(
                "binding is not in the configured startup VT set",
            ));
        }
        let mut op = self.write(budget).await?;
        if op.contexts.len() == CONTEXT_LIMIT {
            return Err(Error::new(ErrorKind::LimitExceeded, "context limit"));
        }
        let issued = op
            .authorities
            .issue()
            .map_err(|error| self.authority_error(error))?;
        op.arm();
        let lifetime = op
            .authorities
            .registration(issued.context)
            .map_err(|error| self.authority_error(error))?;
        op.contexts.insert(
            issued.context,
            Context {
                #[cfg(feature = "vt")]
                vt,
                grants: BTreeSet::new(),
                connections: BTreeMap::new(),
                lifetime,
            },
        );
        self.changed();
        op.settle(Ok((issued.endpoint, issued.context)))
    }
    pub async fn activate_context(&self, id: ContextId, budget: Budget) -> Result<()> {
        let mut op = self.write(budget).await?;
        self.live(&op, id)?;
        #[cfg(not(feature = "vt"))]
        let occupied = op.active.is_some();
        #[cfg(feature = "vt")]
        let occupied = op.active.contains_key(&op.contexts[&id].vt);
        if occupied {
            return Err(Error::new(
                ErrorKind::Busy,
                "binding is occupied, including by this same context",
            ));
        }
        op.arm();
        let deadline = op.deadline;
        #[cfg(not(feature = "vt"))]
        {
            op.active = Some(id);
        }
        #[cfg(feature = "vt")]
        {
            let vt = op.contexts[&id].vt;
            op.active.insert(vt, id);
        }
        let result = async {
            self.reconcile(&mut op, deadline, false, None).await?;
            self.finish_live(&mut op, id, deadline).await
        }
        .await;
        self.changed();
        op.settle(result)
    }
    pub async fn deactivate_context(&self, id: ContextId, budget: Budget) -> Result<()> {
        let mut op = self.write(budget).await?;
        self.live(&op, id)?;
        if !Self::is_active(&op, id) {
            return Ok(());
        }
        op.arm();
        let deadline = op.deadline;
        let result = self.reconcile(&mut op, deadline, false, Some(id)).await;
        if result.is_ok() {
            Self::clear_active(&mut op, id);
            self.changed();
        }
        op.settle(result)
    }
    async fn remove_locked(
        &self,
        state: &mut State,
        id: ContextId,
        deadline: Instant,
    ) -> Result<()> {
        if !state.contexts.contains_key(&id) {
            return Ok(());
        }
        state.authorities.invalidate(id);
        self.reconcile(state, deadline, false, Some(id)).await?;
        let keys = state.contexts[&id].connections.keys().copied().collect();
        self.required(
            deadline,
            "removed context connection retirement",
            self.broker.withdraw_connections(keys, true),
        )
        .await?;
        Self::clear_active(state, id);
        state.contexts.remove(&id);
        self.changed();
        Ok(())
    }
    async fn finish_live(&self, state: &mut State, id: ContextId, deadline: Instant) -> Result<()> {
        match self.live(state, id) {
            Err(error) if error.kind == ErrorKind::NotAuthorized => {
                self.remove_locked(state, id, deadline).await?;
                Err(error)
            }
            result => result,
        }
    }
    pub async fn remove_context(&self, authority: BorrowedFd<'_>, budget: Budget) -> Result<()> {
        let mut op = self.write(budget).await?;
        let id = op
            .authorities
            .resolve_removal(authority)
            .map_err(|error| self.authority_error(error))?;
        op.arm();
        let deadline = op.deadline;
        let result = self.remove_locked(&mut op, id, deadline).await;
        op.settle(result)
    }
    pub async fn remove_context_by_id(&self, id: ContextId, budget: Budget) -> Result<()> {
        let mut op = self.write(budget).await?;
        op.arm();
        let deadline = op.deadline;
        let result = self.remove_locked(&mut op, id, deadline).await;
        op.settle(result)
    }
    pub async fn set_grant(
        &self,
        authority: BorrowedFd<'_>,
        uid: u32,
        add: bool,
        budget: Budget,
    ) -> Result<()> {
        if uid == u32::MAX {
            return Err(Error::invalid("invalid UID"));
        }
        let mut op = self.write(budget).await?;
        let id = op
            .authorities
            .resolve(authority)
            .map_err(|error| self.authority_error(error))?;
        let context = &op.contexts[&id];
        if add && context.grants.len() == 64 && !context.grants.contains(&uid) {
            return Err(Error::new(ErrorKind::LimitExceeded, "context UID limit"));
        }
        op.arm();
        let deadline = op.deadline;
        if add {
            op.contexts
                .get_mut(&id)
                .expect("context")
                .grants
                .insert(uid);
        } else {
            op.contexts
                .get_mut(&id)
                .expect("context")
                .grants
                .remove(&uid);
        }
        let force = self.eligible(&op)? == Some(id);
        let result = async {
            self.reconcile(&mut op, deadline, force, None).await?;
            self.finish_live(&mut op, id, deadline).await
        }
        .await;
        self.changed();
        op.settle(result)
    }
    pub async fn create_connection(
        &self,
        authority: BorrowedFd<'_>,
        budget: Budget,
    ) -> Result<(OwnedFd, u32)> {
        let mut op = self.write(budget).await?;
        let id = op
            .authorities
            .resolve(authority)
            .map_err(|error| self.authority_error(error))?;
        if op.contexts[&id].connections.len() == CONNECTION_LIMIT {
            return Err(Error::new(
                ErrorKind::LimitExceeded,
                "context connection limit",
            ));
        }
        let (server, endpoint) = UnixStream::pair()
            .map_err(|error| Error::new(ErrorKind::LimitExceeded, error.to_string()))?;
        let permission = op
            .applied
            .as_ref()
            .filter(|applied| applied.context == id && applied.permission.is_open())
            .map(|applied| applied.permission.clone());
        op.arm();
        let deadline = op.deadline;
        let result = async {
            let registered = match timeout_at(
                deadline,
                self.broker.add_connection(server.into(), permission),
            )
            .await
            {
                Ok(Ok(registered)) => registered,
                Ok(Err(error))
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::EAGAIN)
                    ) =>
                {
                    return Err(Error::new(
                        ErrorKind::LimitExceeded,
                        format!("connection registration rejected before effects: {error}"),
                    ));
                }
                Ok(Err(error)) => {
                    return Err(self
                        .fatal
                        .fail(format!("broker connection registration: {error}")));
                }
                Err(_) => {
                    return Err(self
                        .fatal
                        .fail("broker registration timed out; ownership remains with the broker"));
                }
            };
            let handle = registered.handle;
            op.contexts
                .get_mut(&id)
                .expect("context")
                .connections
                .insert(
                    registered.key,
                    Connection {
                        handle,
                        close: registered.close,
                    },
                );
            self.finish_live(&mut op, id, deadline).await?;
            self.changed();
            Ok((endpoint.into(), handle))
        }
        .await;
        op.settle(result)
    }
    fn info(&self, state: &State, id: ContextId) -> Result<ContextInfo> {
        let context = &state.contexts[&id];
        let effective = self.eligible(state)? == Some(id)
            && state
                .applied
                .as_ref()
                .is_some_and(|applied| applied.context == id && applied.permission.is_open());
        #[cfg(not(feature = "vt"))]
        let (vt, foreground) = (0, false);
        #[cfg(feature = "vt")]
        let (vt, foreground) = (
            context.vt,
            state.foreground.observed == Some(context.vt) && state.foreground.available,
        );
        let mut handles: Vec<_> = context
            .connections
            .values()
            .filter(|connection| !connection.close.is_closed())
            .map(|connection| connection.handle)
            .collect();
        handles.sort_unstable();
        Ok(ContextInfo {
            id,
            vt,
            desired_uids: context.grants.iter().copied().collect(),
            connection_handles: handles,
            active: Self::is_active(state, id),
            foreground,
            effective,
        })
    }
    pub async fn get_context(
        &self,
        authority: BorrowedFd<'_>,
        budget: Budget,
    ) -> Result<ContextInfo> {
        let state = self.read(budget).await?;
        let id = state
            .authorities
            .resolve(authority)
            .map_err(|error| self.authority_error(error))?;
        self.info(&state, id)
    }
    pub async fn seat_metadata(
        &self,
        authority: BorrowedFd<'_>,
        budget: Budget,
    ) -> Result<(String, u32)> {
        let state = self.read(budget).await?;
        let id = state
            .authorities
            .resolve(authority)
            .map_err(|error| self.authority_error(error))?;
        #[cfg(not(feature = "vt"))]
        {
            let _ = id;
            Ok((self.name.as_str().into(), 0))
        }
        #[cfg(feature = "vt")]
        {
            Ok((self.name.as_str().into(), state.contexts[&id].vt))
        }
    }
    pub async fn list_contexts(&self, budget: Budget) -> Result<Vec<ContextInfo>> {
        let state = self.read(budget).await?;
        state
            .contexts
            .keys()
            .map(|id| self.info(&state, *id))
            .collect()
    }
    pub async fn prune_authorities(&self) -> Result<()> {
        let mut op = self.write(Budget::new()).await?;
        let retired = op
            .authorities
            .retire_ready()
            .map_err(|error| self.authority_error(error))?;
        if retired.is_empty() {
            return Ok(());
        }
        op.arm();
        let deadline = op.deadline;
        let result = async {
            for event in retired {
                self.remove_locked(&mut op, event.context, deadline).await?;
            }
            Ok(())
        }
        .await;
        op.settle(result)
    }
    pub async fn connection_gone(&self, key: ConnectionKey) -> Result<()> {
        let mut op = self.source_write().await?;
        op.arm();
        for context in op.contexts.values_mut() {
            if context.connections.remove(&key).is_some() {
                self.changed();
                break;
            }
        }
        op.settle(Ok(()))
    }
    pub async fn refresh_devices(&self, addition: bool, budget: Budget) -> Result<()> {
        let category = if addition {
            ErrorKind::DeviceAdditionFailed
        } else {
            ErrorKind::DeviceRemovalFailed
        };
        let mut op = self.write(budget).await.map_err(|error| {
            if error.kind == ErrorKind::Busy {
                Error::new(category, error.text)
            } else {
                error
            }
        })?;
        let snapshot = timeout_at(budget.admission(), self.discovery.scan())
            .await
            .map_err(|_| {
                Error::new(
                    category,
                    "fresh enumeration expired before mutation admission",
                )
            })?
            .map_err(|error| Error::new(category, format!("fresh enumeration: {error}")))?;
        op.catalog
            .validate_update(&snapshot.scan)
            .map_err(|error| Error::new(category, error.to_string()))?;
        if snapshot.scan.nodes.len() > NODE_LIMIT {
            return Err(Error::new(
                category,
                "fresh node capacity exceeded before effects",
            ));
        }
        let mut batch = op.catalog.removal_batch(&snapshot.scan);
        // Candidate validation must precede effects; additions cannot silently
        // withdraw an obsolete admission. Catalog validates before mutating.
        if addition {
            op.catalog
                .validate_additions(&snapshot.scan)
                .map_err(|error| Error::new(category, error.to_string()))?;
        }
        let deadline = budget
            .effect_deadline()
            .map_err(|error| Error::new(category, error.text))?;
        op.arm();
        let deadline = deadline.min(op.deadline);
        let result = async {
            op.sequence = snapshot.sequence;
            if addition {
                op.catalog
                    .publish_additions(snapshot.scan)
                    .map_err(|error| self.fatal.fail(format!("validated addition: {error}")))?;
                let keep = op.catalog.broker_batch();
                let State { catalog, acl, .. } = &mut *op;
                tokio::try_join!(
                    self.required(
                        deadline,
                        "replaced assigned device withdrawal",
                        self.broker.revoke_unlisted_devices(keep)
                    ),
                    self.required(deadline, "obsolete assigned node ACL withdrawal", async {
                        acl.clear_obsolete_device_acls(&catalog.view()).await
                    }),
                )?;
                self.required(
                    deadline,
                    "assigned device ACL application",
                    acl.refresh_device_acls(&catalog.view()),
                )
                .await?;
            } else {
                op.catalog
                    .publish_removals(&snapshot.scan)
                    .map_err(|error| self.fatal.fail(format!("validated removal: {error}")))?;
                batch.settle_admissions(&op.catalog);
                let keep = op.catalog.broker_batch();
                tokio::try_join!(
                    self.required(
                        deadline,
                        "unassigned broker withdrawal",
                        self.broker.revoke_unlisted_devices(keep)
                    ),
                    self.required(
                        deadline,
                        "unassigned ACL withdrawal",
                        op.acl.clear_obsolete_device_acls(&batch)
                    ),
                )?;
            }
            self.changed();
            Ok(())
        }
        .await;
        op.settle(result)
    }
    pub async fn physical_event(&self, event: discovery::Event) -> Result<()> {
        let mut op = self.source_write().await?;
        if event.sequence <= op.sequence {
            return Ok(());
        }
        let path = match &event.hint {
            PhysicalHint::Add { syspath, .. } | PhysicalHint::Remove { syspath } => syspath.clone(),
        };
        let current = match timeout_at(op.deadline, self.discovery.current(path.clone())).await {
            Ok(Ok(current)) => current,
            Ok(Err(error))
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::EAGAIN)
                ) =>
            {
                self.discovery.refresh_needed();
                return Ok(());
            }
            Ok(Err(error)) => {
                return Err(self
                    .fatal
                    .fail(format!("physical hint revalidation: {error}")));
            }
            Err(_) => {
                return Err(self
                    .fatal
                    .fail("physical hint owner did not revalidate within its bound"));
            }
        };
        let key = path.to_string_lossy();
        match event.hint {
            PhysicalHint::Add { identity, .. } => {
                let Some(node) = current.filter(|node| node.identity.same_inode(identity)) else {
                    return Ok(());
                };
                if !op.catalog.can_add_node(&node) {
                    self.discovery.refresh_needed();
                    return Ok(());
                }
                op.arm();
                let deadline = op.deadline;
                op.catalog.device_added(node);
                let keep = op.catalog.broker_batch();
                let result = async {
                    let State { catalog, acl, .. } = &mut *op;
                    tokio::try_join!(
                        self.required(
                            deadline,
                            "replaced physical broker withdrawal",
                            self.broker.revoke_unlisted_devices(keep)
                        ),
                        self.required(deadline, "replaced physical ACL withdrawal", async {
                            acl.clear_obsolete_device_acls(&catalog.view()).await
                        }),
                    )?;
                    self.required(
                        deadline,
                        "physical node ACL application",
                        acl.refresh_device_acls(&catalog.view()),
                    )
                    .await
                }
                .await;
                self.changed();
                op.settle(result)
            }
            PhysicalHint::Remove { .. } => {
                let Some(previous) = op.catalog.live_node(&key).cloned() else {
                    return Ok(());
                };
                if current
                    .as_ref()
                    .is_some_and(|node| node.identity == previous.identity)
                {
                    return Ok(());
                }
                op.arm();
                let deadline = op.deadline;
                op.catalog.device_removed(&key, previous.identity);
                let keep = op.catalog.broker_batch();
                let State { catalog, acl, .. } = &mut *op;
                let result = tokio::try_join!(
                    self.required(
                        deadline,
                        "removed physical broker withdrawal",
                        self.broker.revoke_unlisted_devices(keep)
                    ),
                    self.required(deadline, "removed physical ACL withdrawal", async {
                        acl.clear_obsolete_device_acls(&catalog.view()).await
                    }),
                )
                .map(|_| ());
                self.changed();
                op.settle(result)
            }
        }
    }
    pub async fn broker_open(
        &self,
        key: ConnectionKey,
        path: PathBuf,
        permission: Permit,
        done: tokio::sync::oneshot::Sender<()>,
    ) -> Result<()> {
        let budget = Budget::new();
        let state = self.read(budget).await?;
        let admission = if permission.is_open() {
            state.catalog.lookup_broker_node(&path, &permission)
        } else {
            None
        };
        let (start, waiting) = tokio::sync::oneshot::channel();
        let result = self
            .required(
                budget.admission(),
                "broker open registration",
                self.broker.register_open(key, admission, waiting, done),
            )
            .await;
        drop(state); // The actual resource registration is complete before unlock.
        if result.is_ok() {
            let _ = start.send(());
        }
        result
    }
    pub async fn publish_device(
        &self,
        key: ConnectionKey,
        slot: i32,
        permission: Permit,
        output: connection::Output,
        done: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<()> {
        let state = self.read(Budget::new()).await?;
        let owner = state
            .contexts
            .iter()
            .find(|(_, context)| context.connections.contains_key(&key))
            .map(|(id, _)| *id);
        let context = owner.and_then(|id| state.contexts.get(&id));
        let permitted = permission.is_open()
            && owner.is_some()
            && owner == self.eligible(&state)?
            && state.applied.as_ref().is_some_and(|applied| {
                Some(applied.context) == owner && applied.permission.is_open()
            });
        if permitted {
            match timeout_at(
                Instant::now() + crate::fatal::FLUSH_LIMIT,
                self.broker.publish(key, output),
            )
            .await
            {
                Ok(Ok(())) => {}
                _ => {
                    if let Some(context) = context {
                        context.connections[&key].close.signal();
                    }
                }
            }
        } else {
            self.broker
                .reject_publication(key, slot)
                .await
                .map_err(|error| self.fatal.fail(format!("reject stale descriptor: {error}")))?;
        }
        drop(state);
        if let Some(done) = done {
            let _ = done.send(());
        }
        Ok(())
    }
    #[cfg(not(feature = "vt"))]
    pub async fn move_to_foreground(&self, _id: ContextId, _budget: Budget) -> Result<()> {
        Err(Error::invalid(
            "foreground is inapplicable on a non-VT seat",
        ))
    }
    #[cfg(feature = "vt")]
    fn foreground_deadline(
        &self,
        state: &mut State,
        deadline: Instant,
        context: Option<ContextId>,
    ) -> Instant {
        use std::sync::atomic::Ordering;
        state
            .foreground_waits
            .retain(|wait| wait.alive.load(Ordering::Acquire));
        let mut deadline = deadline;
        for wait in &state.foreground_waits {
            if context.is_none() || context == Some(wait.context) {
                wait.started.store(true, Ordering::Release);
                deadline = deadline.min(wait.deadline);
            }
        }
        deadline
    }
    #[cfg(feature = "vt")]
    pub async fn release_requested(&self) -> Result<()> {
        let mut op = self.source_write().await?;
        op.arm();
        let own_deadline = op.deadline;
        let deadline = self.foreground_deadline(&mut op, own_deadline, None);
        op.shorten_deadline(deadline);
        op.foreground.available = false;
        let result = async {
            self.reconcile(&mut op, deadline, false, None).await?;
            // An empty active/foreground association never suppresses native ACK.
            self.required(
                deadline,
                "native release acknowledgement",
                self.vt.acknowledge_release(),
            )
            .await?;
            self.changed();
            Ok(())
        }
        .await;
        op.settle(result)
    }
    #[cfg(feature = "vt")]
    pub async fn foreground_observed(&self) -> Result<()> {
        let mut op = self.source_write().await?;
        op.arm();
        let own_deadline = op.deadline;
        let result = async {
            // Query AFTER State admission, never replay a historical signal VT.
            let current = self
                .required(
                    own_deadline,
                    "current native foreground",
                    self.vt.foreground(),
                )
                .await?;
            op.foreground = Foreground {
                observed: self.configured_vts.contains(&current).then_some(current),
                available: self.configured_vts.contains(&current),
            };
            let candidate = self.eligible(&op)?;
            let deadline = self.foreground_deadline(&mut op, own_deadline, candidate);
            op.shorten_deadline(deadline);
            self.reconcile(&mut op, deadline, true, None).await?;
            self.required(
                deadline,
                "native acquisition acknowledgement",
                self.vt.acknowledge_acquisition(),
            )
            .await?;
            self.changed();
            Ok(())
        }
        .await;
        op.settle(result)
    }
    #[cfg(feature = "vt")]
    pub async fn move_to_foreground(&self, id: ContextId, budget: Budget) -> Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        let mut changes = self.changes();
        let mut op = self.write(budget).await.map_err(|error| {
            if error.kind == ErrorKind::Busy {
                Error::new(ErrorKind::VTActivationFailed, error.text)
            } else {
                error
            }
        })?;
        self.live(&op, id)?;
        if !Self::is_active(&op, id) {
            return Err(Error::new(
                ErrorKind::NotReady,
                "foreground requires an active context",
            ));
        }
        op.foreground_waits
            .retain(|wait| wait.alive.load(Ordering::Acquire));
        if op.foreground_waits.len() == 64 {
            return Err(Error::new(
                ErrorKind::LimitExceeded,
                "foreground wait capacity",
            ));
        }
        let vt = op.contexts[&id].vt;
        op.arm();
        let deadline = op.deadline;
        let current = self
            .required(
                deadline,
                "foreground request native observation",
                self.vt.foreground(),
            )
            .await?;
        if current == vt {
            op.foreground = Foreground {
                observed: Some(vt),
                available: true,
            };
            let result = self.reconcile(&mut op, deadline, true, None).await;
            self.changed();
            return op.settle(result);
        }
        let submitted = timeout_at(deadline, self.vt.request_switch(vt))
            .await
            .map_err(|_| {
                Error::new(
                    ErrorKind::VTActivationFailed,
                    "native switch submission expired; kernel progress may outlive this reply",
                )
            })
            .and_then(|result| {
                result.map_err(|error| {
                    Error::new(
                        ErrorKind::VTActivationFailed,
                        format!("native switch submission: {error}"),
                    )
                })
            });
        if let Err(error) = submitted {
            return op.settle(Err(error));
        }
        let alive = Arc::new(AtomicBool::new(true));
        let started = Arc::new(AtomicBool::new(false));
        let _lifetime = WaitLifetime(alive.clone());
        op.foreground_waits.push(ForegroundWait {
            context: id,
            deadline,
            alive,
            started: started.clone(),
        });
        op.settle(Ok(()))?; // No guard is held while waiting for a kernel switch.
        loop {
            self.fatal.check()?;
            let observed = self.read(Budget { reply: deadline }).await;
            if let Ok(state) = observed {
                if !state.contexts.contains_key(&id) || !Self::is_active(&state, id) {
                    return Err(Error::new(
                        ErrorKind::VTActivationFailed,
                        "context changed while waiting for foreground",
                    ));
                }
                if self.info(&state, id)?.effective
                    && state.foreground.observed == Some(vt)
                    && state.foreground.available
                {
                    return Ok(());
                }
            } else if self.fatal.stopping() {
                self.fatal.check()?;
            }
            if Instant::now() >= deadline {
                if started.load(Ordering::Acquire) {
                    return Err(self
                        .fatal
                        .fail("foreground request required-policy deadline expired"));
                }
                return Err(Error::new(
                    ErrorKind::VTActivationFailed,
                    "kernel foreground did not settle before the response deadline; no rollback claimed",
                ));
            }
            let _ = timeout_at(deadline, changes.changed()).await;
        }
    }
    pub async fn protocol_switch(
        &self,
        key: ConnectionKey,
        target: u32,
        permission: Permit,
    ) -> Result<()> {
        #[cfg(not(feature = "vt"))]
        {
            let _ = (key, target, permission);
            Err(Error::invalid("session switching requires a VT seat"))
        }
        #[cfg(feature = "vt")]
        {
            if !(1..=63).contains(&target) {
                return Err(Error::invalid("target VT is outside 1..63"));
            }
            let budget = Budget::new();
            let state = self.read(budget).await?;
            let owner = state
                .contexts
                .iter()
                .find(|(_, context)| context.connections.contains_key(&key))
                .map(|(id, _)| *id);
            if !permission.is_open() || owner.is_none() || owner != self.eligible(&state)? {
                return Err(Error::new(
                    ErrorKind::NotAuthorized,
                    "connection is no longer eligible",
                ));
            }
            timeout_at(budget.admission(), self.vt.request_switch(target))
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorKind::VTActivationFailed,
                        "protocol switch submission expired",
                    )
                })?
                .map_err(|error| Error::new(ErrorKind::VTActivationFailed, error.to_string()))
        }
    }
    /// Called after the reply barrier. This guard/future itself remains parent-
    /// owned if the independent cleanup deadline expires.
    /// Actual ACL settlement is separate from recorded operation/cleanup errors.
    pub async fn cleanup(&self) -> (bool, Vec<io::Error>) {
        let mut state = self.state.write().await;
        state.authorities.invalidate_all();
        if let Some(applied) = &state.applied {
            applied.permission.fence();
        }
        for context in state.contexts.values() {
            for connection in context.connections.values() {
                connection.close.signal();
            }
        }
        let errors = state.acl.shutdown().await;
        (
            !state.acl.has_started_work() && state.acl.retained() == 0,
            errors,
        )
    }
}
