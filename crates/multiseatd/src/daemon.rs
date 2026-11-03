//! Daemon-only runtime construction and cooperative critical-task supervision.
//!
//! The caller retains resource-cleanup ownership outside service tasks. Closing
//! transports or observing a panic is not device revocation. Drive quiesce,
//! resource revocation and terminal restoration explicitly, observing every join
//! result; never use JoinSet::shutdown (which would hide panics) as cleanup.

use crate::instance::InstanceLock;
use crate::registry::Registry;
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use seat_udev::SeatName;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::os::fd::AsFd;
use std::path::Path;
use std::rc::Rc;
use tokio::io::unix::AsyncFd;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::watch;
use tokio::task::{Id, JoinSet};

/// Field order matters: runtime workers/futures stop before the signal mask is
/// restored and before another instance can acquire the persistent lock inode.
/// Construct on the main thread before ANY worker or VT thread is created.
pub struct DaemonRuntime {
    runtime: Runtime,
    signals: ShutdownSignals,
    _instance: InstanceLock,
}

impl DaemonRuntime {
    pub fn acquire(lock_path: &Path) -> io::Result<Self> {
        let instance = InstanceLock::acquire(lock_path)?;
        let signals = ShutdownSignals::block()?;
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(4)
            .thread_name("multiseatd")
            .enable_io()
            .enable_time()
            .build()?;
        Ok(Self {
            runtime,
            signals,
            _instance: instance,
        })
    }

    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    pub fn shutdown_signals(&self) -> &ShutdownSignals {
        &self.signals
    }
}

pub struct ShutdownSignals {
    original: SigSet,
    shutdown: SignalFd,
    // Restoring another thread's signal mask would be incorrect. This also
    // prevents moving the enclosing runtime/lock lifetime to another thread.
    _thread_affine: PhantomData<Rc<()>>,
}

impl ShutdownSignals {
    fn block() -> io::Result<Self> {
        let original = SigSet::thread_get_mask()?;
        let mut mask = SigSet::empty();
        for signal in [
            Signal::SIGUSR1,
            Signal::SIGUSR2,
            Signal::SIGTERM,
            Signal::SIGINT,
        ] {
            mask.add(signal);
        }
        mask.thread_block()?;
        let mut shutdown_mask = SigSet::empty();
        shutdown_mask.add(Signal::SIGTERM);
        shutdown_mask.add(Signal::SIGINT);
        let shutdown = match SignalFd::with_flags(
            &shutdown_mask,
            SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK,
        ) {
            Ok(fd) => fd,
            Err(error) => {
                let _ = original.thread_set_mask();
                return Err(error.into());
            }
        };
        Ok(Self {
            original,
            shutdown,
            _thread_affine: PhantomData,
        })
    }

    /// One owner waits here. VT signals stay blocked and are NOT consumed by
    /// this signalfd; only the dedicated terminal-owner thread consumes them.
    pub async fn requested(&self) -> io::Result<Signal> {
        // SAFETY: self owns the signalfd and this borrow keeps its descriptor
        // open/unchanged until the local watch is dropped, also on cancellation.
        let watched = unsafe {
            AsyncFd::register_with_interest(self.shutdown.as_fd(), tokio::io::Interest::READABLE)
        }?;
        loop {
            let mut ready = watched.readable().await?;
            if let Some(info) = self.shutdown.read_signal()? {
                return Signal::try_from(info.ssi_signo as i32).map_err(Into::into);
            }
            ready.clear_ready();
        }
    }
}

impl Drop for ShutdownSignals {
    fn drop(&mut self) {
        if let Err(error) = self.original.thread_set_mask() {
            tracing::error!(%error, "could not restore main-thread signal mask");
        }
    }
}

/// These are ordered shutdown INTENTS, not claims that cleanup succeeded.
/// The outer owner advances only after each stage's actual barriers settle.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ShutdownPhase {
    Running,
    Quiesce,
    Revoke,
    RestoreTerminal,
    Stopped,
}

#[derive(Clone)]
pub struct Shutdown {
    phase: watch::Receiver<ShutdownPhase>,
}

impl Shutdown {
    pub fn phase(&self) -> ShutdownPhase {
        *self.phase.borrow()
    }

    /// Owner loss is fail-closed. Stopped here never certifies kernel cleanup.
    pub async fn reached(&mut self, target: ShutdownPhase) -> ShutdownPhase {
        loop {
            let current = self.phase();
            if current >= target {
                return current;
            }
            if self.phase.changed().await.is_err() {
                return ShutdownPhase::Stopped;
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CriticalRole {
    Registry,
    Bus,
    Topology,
    Seat(SeatName),
    ResourceExecutor,
    VtOwner,
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("critical-task limit reached")]
    LimitExceeded,
    #[error("daemon admission is closed")]
    Stopping,
    #[error("critical role already has a supervised owner")]
    DuplicateRole,
    #[error("invalid shutdown phase transition")]
    InvalidPhase,
    #[error("critical tasks have not all been joined")]
    TasksRemaining,
    #[error("context resource cleanup remains pending")]
    CleanupPending,
}

#[derive(Debug, thiserror::Error)]
pub enum TaskFailure {
    #[error("critical service exited while admission was open")]
    UnexpectedExit,
    #[error("critical operation failed: {0}")]
    Operation(#[source] io::Error),
    #[error("critical service panicked: {0}")]
    Panic(String),
    #[error("critical service was cancelled unexpectedly")]
    Cancelled,
}

#[derive(Debug)]
pub struct TaskExit {
    pub role: CriticalRole,
    pub failure: Option<TaskFailure>,
}

/// Every persistent critical service is supervised. Connection/job owners must
/// likewise observe their children; ordinary EOF is not a service failure, but
/// an unexpected child panic must reach this supervisor through its owner.
pub struct CriticalTasks {
    tasks: JoinSet<io::Result<()>>,
    roles: HashMap<Id, CriticalRole>,
    retiring: HashSet<Id>,
    phase: watch::Sender<ShutdownPhase>,
    limit: usize,
}

impl CriticalTasks {
    pub fn new(limit: usize) -> Result<Self, SupervisorError> {
        if limit == 0 {
            return Err(SupervisorError::LimitExceeded);
        }
        let (phase, _) = watch::channel(ShutdownPhase::Running);
        Ok(Self {
            tasks: JoinSet::new(),
            roles: HashMap::new(),
            retiring: HashSet::new(),
            phase,
            limit,
        })
    }

    pub fn subscribe(&self) -> Shutdown {
        Shutdown {
            phase: self.phase.subscribe(),
        }
    }

    pub fn phase(&self) -> ShutdownPhase {
        *self.phase.borrow()
    }

    pub fn spawn(
        &mut self,
        role: CriticalRole,
        future: impl Future<Output = io::Result<()>> + Send + 'static,
    ) -> Result<(), SupervisorError> {
        if self.phase() != ShutdownPhase::Running {
            return Err(SupervisorError::Stopping);
        }
        if self.roles.values().any(|existing| existing == &role) {
            return Err(SupervisorError::DuplicateRole);
        }
        if self.tasks.len() == self.limit {
            return Err(SupervisorError::LimitExceeded);
        }
        let handle = self.tasks.spawn(future);
        self.roles.insert(handle.id(), role);
        Ok(())
    }

    pub fn retire_seat(&mut self, name: &SeatName) {
        for (id, role) in &self.roles {
            if role == &CriticalRole::Seat(name.clone()) {
                self.retiring.insert(*id);
            }
        }
    }

    pub fn quiesce(&mut self) {
        if self.phase() == ShutdownPhase::Running {
            self.phase.send_replace(ShutdownPhase::Quiesce);
        }
    }

    pub fn advance(&mut self, next: ShutdownPhase) -> Result<(), SupervisorError> {
        let expected = match self.phase() {
            ShutdownPhase::Running => ShutdownPhase::Quiesce,
            ShutdownPhase::Quiesce => ShutdownPhase::Revoke,
            ShutdownPhase::Revoke => ShutdownPhase::RestoreTerminal,
            ShutdownPhase::RestoreTerminal => ShutdownPhase::Stopped,
            ShutdownPhase::Stopped => return Err(SupervisorError::InvalidPhase),
        };
        if next != expected {
            return Err(SupervisorError::InvalidPhase);
        }
        if next == ShutdownPhase::Stopped && !self.tasks.is_empty() {
            return Err(SupervisorError::TasksRemaining);
        }
        self.phase.send_replace(next);
        Ok(())
    }

    /// Cancel-safe JoinSet wait, suitable for the outer owner's select loop.
    /// Any failure closes service admission before it is returned to the owner.
    pub async fn next_exit(&mut self) -> Option<TaskExit> {
        let joined = self.tasks.join_next_with_id().await?;
        let (id, failure) = match joined {
            Ok((id, Ok(()))) => (
                id,
                (self.phase() == ShutdownPhase::Running && !self.retiring.contains(&id))
                    .then_some(TaskFailure::UnexpectedExit),
            ),
            Ok((id, Err(error))) => (id, Some(TaskFailure::Operation(error))),
            Err(error) => {
                let id = error.id();
                let failure = if error.is_panic() {
                    let payload = error.into_panic();
                    let message = if let Some(text) = payload.downcast_ref::<String>() {
                        text.clone()
                    } else if let Some(text) = payload.downcast_ref::<&str>() {
                        (*text).to_owned()
                    } else {
                        "non-string panic payload".to_owned()
                    };
                    TaskFailure::Panic(message)
                } else {
                    TaskFailure::Cancelled
                };
                (id, Some(failure))
            }
        };
        if failure.is_some() {
            self.quiesce();
        }
        self.retiring.remove(&id);
        let role = self
            .roles
            .remove(&id)
            .expect("every critical task has an owner");
        Some(TaskExit { role, failure })
    }

    /// Join cooperatively; do not abort tasks or suppress late cleanup panics.
    /// Advance stages separately so the VT owner can outlive resource cleanup.
    pub async fn drain(&mut self) -> Result<Vec<TaskExit>, SupervisorError> {
        if self.phase() == ShutdownPhase::Running {
            return Err(SupervisorError::InvalidPhase);
        }
        let mut exits = Vec::new();
        while let Some(exit) = self.next_exit().await {
            exits.push(exit);
        }
        Ok(exits)
    }
}

/// Serialized outer control owner. A critical exit fences the real registry as
/// well as task admission before another routed request can execute. Device and
/// topology owners must additionally settle their non-context resource barriers
/// before requesting terminal restoration.
pub struct Daemon {
    registry: Registry,
    tasks: CriticalTasks,
}

impl Daemon {
    pub fn new(registry: Registry, service_limit: usize) -> Result<Self, SupervisorError> {
        Ok(Self {
            registry,
            tasks: CriticalTasks::new(service_limit)?,
        })
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut Registry {
        &mut self.registry
    }

    pub fn subscribe(&self) -> Shutdown {
        self.tasks.subscribe()
    }

    pub fn spawn(
        &mut self,
        role: CriticalRole,
        future: impl Future<Output = io::Result<()>> + Send + 'static,
    ) -> Result<(), SupervisorError> {
        self.tasks.spawn(role, future)
    }

    pub fn retire_seat(&mut self, name: &SeatName) {
        self.tasks.retire_seat(name);
    }

    pub async fn changed(&mut self) -> io::Result<Option<TaskExit>> {
        tokio::select! {
            biased;
            exit = self.tasks.next_exit() => {
                if exit.as_ref().is_some_and(|exit| exit.failure.is_some()) { self.quiesce(); }
                Ok(exit)
            }
            result = self.registry.changed() => {
                result?;
                self.registry.reconcile_lifetimes().map_err(io::Error::other)?;
                Ok(None)
            }
        }
    }

    pub fn quiesce(&mut self) {
        self.registry.close_admission();
        self.tasks.quiesce();
    }

    pub async fn next_exit(&mut self) -> Option<TaskExit> {
        let exit = self.tasks.next_exit().await?;
        if exit.failure.is_some() {
            self.quiesce();
        }
        Some(exit)
    }

    pub fn advance(&mut self, next: ShutdownPhase) -> Result<(), SupervisorError> {
        if self.tasks.phase() == ShutdownPhase::Revoke
            && next == ShutdownPhase::RestoreTerminal
            && self.registry.retained_contexts() != 0
        {
            return Err(SupervisorError::CleanupPending);
        }
        self.tasks.advance(next)
    }

    pub async fn drain(&mut self) -> Result<Vec<TaskExit>, SupervisorError> {
        if self.tasks.phase() == ShutdownPhase::Running {
            return Err(SupervisorError::InvalidPhase);
        }
        let mut exits = Vec::new();
        while let Some(exit) = self.next_exit().await {
            exits.push(exit);
        }
        Ok(exits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::sync::oneshot;
    use tokio::time::{Duration, timeout};

    #[test]
    fn singleton_precedes_workers_and_signal_masks_are_inherited_and_restored() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("daemon.lock");
        let original = SigSet::thread_get_mask().unwrap();
        let runtime = DaemonRuntime::acquire(&path).unwrap();
        assert!(DaemonRuntime::acquire(&path).is_err());
        runtime.block_on(async {
            let signals = tokio::spawn(async { SigSet::thread_get_mask().unwrap() })
                .await
                .unwrap();
            let blocking = tokio::task::spawn_blocking(|| SigSet::thread_get_mask().unwrap())
                .await
                .unwrap();
            for signal in [
                Signal::SIGUSR1,
                Signal::SIGUSR2,
                Signal::SIGTERM,
                Signal::SIGINT,
            ] {
                assert!(signals.contains(signal));
                assert!(blocking.contains(signal));
            }
        });
        drop(runtime);
        for signal in [
            Signal::SIGUSR1,
            Signal::SIGUSR2,
            Signal::SIGTERM,
            Signal::SIGINT,
        ] {
            assert_eq!(
                SigSet::thread_get_mask().unwrap().contains(signal),
                original.contains(signal)
            );
        }
        assert!(path.exists());
        assert!(InstanceLock::acquire(&path).is_ok());
    }

    #[test]
    fn main_unwind_drops_runtime_futures_before_releasing_the_singleton() {
        use std::sync::atomic::{AtomicU8, Ordering};

        struct DropWitness {
            path: std::path::PathBuf,
            observed: Arc<AtomicU8>,
        }
        impl Drop for DropWitness {
            fn drop(&mut self) {
                let still_locked = InstanceLock::acquire(&self.path).is_err();
                self.observed
                    .store(if still_locked { 1 } else { 2 }, Ordering::Release);
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("daemon.lock");
        let observed = Arc::new(AtomicU8::new(0));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let runtime = DaemonRuntime::acquire(&path).unwrap();
            runtime.block_on(async {
                let witness = DropWitness {
                    path: path.clone(),
                    observed: observed.clone(),
                };
                let (started, ready) = oneshot::channel();
                tokio::spawn(async move {
                    let _witness = witness;
                    started.send(()).unwrap();
                    std::future::pending::<()>().await;
                });
                ready.await.unwrap();
                panic!("injected main-owner panic");
            });
        }));
        assert!(result.is_err());
        assert_eq!(observed.load(Ordering::Acquire), 1);
        assert!(InstanceLock::acquire(&path).is_ok());
    }

    #[tokio::test]
    async fn panic_closes_admission_and_does_not_abort_other_cleanup_owners() {
        let mut tasks = CriticalTasks::new(2).unwrap();
        let mut shutdown = tasks.subscribe();
        let log = Arc::new(Mutex::new(Vec::new()));
        let retained = log.clone();
        let (finished, done) = oneshot::channel();
        tasks
            .spawn(CriticalRole::ResourceExecutor, async move {
                shutdown.reached(ShutdownPhase::Quiesce).await;
                retained.lock().unwrap().push("resource owner quiesced");
                shutdown.reached(ShutdownPhase::Revoke).await;
                retained.lock().unwrap().push("resource cleanup attempted");
                finished.send(()).unwrap();
                Ok(())
            })
            .unwrap();
        tasks
            .spawn(CriticalRole::Registry, async {
                panic!("injected critical panic")
            })
            .unwrap();
        let exit = timeout(Duration::from_secs(2), tasks.next_exit())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(exit.role, CriticalRole::Registry);
        assert!(matches!(exit.failure, Some(TaskFailure::Panic(_))));
        assert_eq!(tasks.phase(), ShutdownPhase::Quiesce);
        assert!(matches!(
            tasks.spawn(CriticalRole::Bus, async { Ok(()) }),
            Err(SupervisorError::Stopping)
        ));
        assert!(matches!(
            tasks.advance(ShutdownPhase::Stopped),
            Err(SupervisorError::InvalidPhase)
        ));
        tasks.advance(ShutdownPhase::Revoke).unwrap();
        timeout(Duration::from_secs(2), done)
            .await
            .unwrap()
            .unwrap();
        let exits = tasks.drain().await.unwrap();
        assert_eq!(exits.len(), 1);
        assert!(exits[0].failure.is_none());
        assert_eq!(
            *log.lock().unwrap(),
            vec!["resource owner quiesced", "resource cleanup attempted"]
        );
        tasks.advance(ShutdownPhase::RestoreTerminal).unwrap();
        tasks.advance(ShutdownPhase::Stopped).unwrap();
    }

    #[tokio::test]
    async fn terminal_owner_survives_until_the_explicit_restore_stage() {
        let mut tasks = CriticalTasks::new(1).unwrap();
        let mut shutdown = tasks.subscribe();
        let (started, owner_ready) = oneshot::channel();
        let (restored, owner_restored) = oneshot::channel();
        tasks
            .spawn(CriticalRole::VtOwner, async move {
                started.send(()).unwrap();
                shutdown.reached(ShutdownPhase::RestoreTerminal).await;
                restored.send(()).unwrap();
                Ok(())
            })
            .unwrap();
        owner_ready.await.unwrap();
        tasks.quiesce();
        tasks.quiesce();
        tasks.advance(ShutdownPhase::Revoke).unwrap();
        assert!(
            timeout(Duration::from_millis(20), tasks.next_exit())
                .await
                .is_err()
        );
        tasks.advance(ShutdownPhase::RestoreTerminal).unwrap();
        assert!(matches!(
            tasks.advance(ShutdownPhase::Stopped),
            Err(SupervisorError::TasksRemaining)
        ));
        owner_restored.await.unwrap();
        let exits = tasks.drain().await.unwrap();
        assert!(exits[0].failure.is_none());
        tasks.advance(ShutdownPhase::Stopped).unwrap();
    }

    #[tokio::test]
    async fn normal_service_exit_and_backend_error_are_not_silently_accepted() {
        let mut tasks = CriticalTasks::new(1).unwrap();
        tasks.spawn(CriticalRole::Bus, async { Ok(()) }).unwrap();
        let exit = tasks.next_exit().await.unwrap();
        assert!(matches!(exit.failure, Some(TaskFailure::UnexpectedExit)));
        assert_eq!(tasks.phase(), ShutdownPhase::Quiesce);
        let mut tasks = CriticalTasks::new(1).unwrap();
        tasks
            .spawn(CriticalRole::Topology, async {
                Err(io::Error::other("monitor lost"))
            })
            .unwrap();
        let exit = tasks.next_exit().await.unwrap();
        assert!(matches!(exit.failure, Some(TaskFailure::Operation(_))));
        assert_eq!(tasks.phase(), ShutdownPhase::Quiesce);
    }

    #[tokio::test]
    async fn limits_duplicates_and_shutdown_transition_order_are_enforced() {
        assert!(CriticalTasks::new(0).is_err());
        let mut tasks = CriticalTasks::new(1).unwrap();
        let mut shutdown = tasks.subscribe();
        tasks
            .spawn(CriticalRole::Registry, async move {
                shutdown.reached(ShutdownPhase::Quiesce).await;
                Ok(())
            })
            .unwrap();
        assert!(matches!(
            tasks.spawn(CriticalRole::Registry, async { Ok(()) }),
            Err(SupervisorError::DuplicateRole)
        ));
        assert!(matches!(
            tasks.spawn(CriticalRole::Bus, async { Ok(()) }),
            Err(SupervisorError::LimitExceeded)
        ));
        assert!(tasks.drain().await.is_err());
        assert!(tasks.advance(ShutdownPhase::RestoreTerminal).is_err());
        tasks.quiesce();
        tasks.drain().await.unwrap();
        tasks.advance(ShutdownPhase::Revoke).unwrap();
        tasks.advance(ShutdownPhase::RestoreTerminal).unwrap();
        tasks.advance(ShutdownPhase::Stopped).unwrap();
        assert!(tasks.advance(ShutdownPhase::Running).is_err());
    }

    #[test]
    fn outer_owner_retains_lock_and_removal_routes_through_ordered_shutdown() {
        use crate::authority::AuthorityError;
        use crate::registry::Limits;
        use std::convert::Infallible;
        use std::os::fd::AsFd;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("daemon.lock");
        let runtime = DaemonRuntime::acquire(&path).unwrap();
        runtime.block_on(async {
            let mut registry = Registry::new(Limits::default()).unwrap();
            let seat: SeatName = "seat-fixture".parse().unwrap();
            registry.add_seat(seat).unwrap();
            let pending = registry
                .begin_context(&"seat-fixture".parse().unwrap())
                .unwrap();
            let context = pending.context();
            let authority = pending.publish(|_, fd| Ok::<_, Infallible>(fd)).unwrap();
            let mut daemon = Daemon::new(registry, 2).unwrap();
            let mut shutdown = daemon.subscribe();
            let (cleaned, cleanup_complete) = oneshot::channel();
            daemon
                .spawn(CriticalRole::ResourceExecutor, async move {
                    shutdown.reached(ShutdownPhase::Revoke).await;
                    // Disposable owner acknowledgement, not a real device ioctl.
                    cleaned.send(()).unwrap();
                    Ok(())
                })
                .unwrap();
            daemon
                .spawn(CriticalRole::Bus, async {
                    Err(io::Error::other("private bus lost"))
                })
                .unwrap();
            let exit = daemon.next_exit().await.unwrap();
            assert_eq!(exit.role, CriticalRole::Bus);
            assert!(exit.failure.is_some());
            assert!(matches!(
                daemon.registry().resolve(authority.as_fd()),
                Err(AuthorityError::AccessDenied)
            ));
            assert_eq!(daemon.registry().removals().count(), 1);
            assert!(InstanceLock::acquire(&path).is_err());
            daemon.advance(ShutdownPhase::Revoke).unwrap();
            assert!(matches!(
                daemon.advance(ShutdownPhase::RestoreTerminal),
                Err(SupervisorError::CleanupPending)
            ));
            cleanup_complete.await.unwrap();
            assert!(daemon.registry_mut().complete_removal(context));
            daemon.advance(ShutdownPhase::RestoreTerminal).unwrap();
            let exits = daemon.drain().await.unwrap();
            assert_eq!(exits.len(), 1);
            assert!(exits[0].failure.is_none());
            daemon.advance(ShutdownPhase::Stopped).unwrap();
            assert!(InstanceLock::acquire(&path).is_err());
        });
        drop(runtime);
        assert!(InstanceLock::acquire(&path).is_ok());
    }

    #[tokio::test]
    async fn cancelled_critical_service_is_reported_not_masked_as_shutdown() {
        let mut tasks = CriticalTasks::new(1).unwrap();
        tasks
            .spawn(CriticalRole::Bus, std::future::pending())
            .unwrap();
        tasks.tasks.abort_all(); // Fault injection; production shutdown never does this.
        let exit = tasks.next_exit().await.unwrap();
        assert!(matches!(exit.failure, Some(TaskFailure::Cancelled)));
        assert_eq!(tasks.phase(), ShutdownPhase::Quiesce);
    }

    #[tokio::test]
    async fn planned_seat_exit_is_expected_but_a_retiring_seat_panic_is_fatal() {
        let name: SeatName = "seat-hotplug".parse().unwrap();
        let mut tasks = CriticalTasks::new(1).unwrap();
        tasks
            .spawn(CriticalRole::Seat(name.clone()), async { Ok(()) })
            .unwrap();
        tasks.retire_seat(&name);
        assert!(tasks.next_exit().await.unwrap().failure.is_none());
        assert_eq!(tasks.phase(), ShutdownPhase::Running);
        tasks
            .spawn(CriticalRole::Seat(name.clone()), async {
                panic!("retirement panic")
            })
            .unwrap();
        tasks.retire_seat(&name);
        assert!(matches!(
            tasks.next_exit().await.unwrap().failure,
            Some(TaskFailure::Panic(_))
        ));
        assert_eq!(tasks.phase(), ShutdownPhase::Quiesce);
    }

    #[tokio::test]
    async fn late_panic_is_reported_even_after_shutdown_has_started() {
        let mut tasks = CriticalTasks::new(1).unwrap();
        let mut shutdown = tasks.subscribe();
        tasks
            .spawn(CriticalRole::ResourceExecutor, async move {
                shutdown.reached(ShutdownPhase::Revoke).await;
                panic!("injected cleanup panic");
            })
            .unwrap();
        tasks.quiesce();
        tasks.advance(ShutdownPhase::Revoke).unwrap();
        let exits = tasks.drain().await.unwrap();
        assert!(matches!(exits[0].failure, Some(TaskFailure::Panic(_))));
        assert_eq!(tasks.phase(), ShutdownPhase::Revoke);
    }
}
