//! Executable lifecycle and bounded control-plane routing.

use crate::daemon::{CriticalRole, Daemon, ShutdownPhase, ShutdownSignals};
use crate::dbus::{
    manager,
    reactor::{BusIo, error_reply},
};
use crate::registry::{Limits, Registry};
use crate::resources::{CleanupGuard, Resources};
use crate::seat::policy::Policy;
use crate::seat::{Budget, Command, Controller, Port};
use crate::topology::Snapshot;
use crate::topology_transaction;
use libmultiseatd::ContextId;
use libmultiseatd::contract::ErrorKind;
use seat_udev::{Context, SeatName};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant, interval, timeout};

pub struct Configuration {
    pub session_bus: bool,
    pub test_only: bool,
    pub non_vt_only: bool,
    pub graphical_vt: Option<u32>,
    pub test_seats: Vec<SeatName>,
    pub test_direct_nodes: Vec<PathBuf>,
    pub test_null_device: bool,
}

pub async fn run(config: Configuration, signals: &ShutdownSignals) -> io::Result<()> {
    let resources = Arc::new(Resources::new(16384, 16384)?);
    let _cleanup = CleanupGuard(resources.clone());
    let mut context = if config.test_only {
        None
    } else {
        Some(Context::new().map_err(io::Error::other)?)
    };
    let mut initial = if let Some(context) = &context {
        filtered(
            Snapshot::from_context(context, &[])?,
            config.non_vt_only,
            config.graphical_vt,
        )?
    } else {
        if config.test_seats.is_empty() || config.test_seats.contains(&SeatName::seat0()) {
            return Err(io::Error::other("test mode requires explicit non-VT seats"));
        }
        Snapshot {
            seats: config.test_seats.iter().cloned().collect(),
            direct: BTreeMap::from([(
                config.test_seats[0].clone(),
                config.test_direct_nodes.iter().cloned().collect(),
            )]),
            ..Snapshot::default()
        }
    };
    if config.test_only {
        for path in &config.test_direct_nodes {
            if !std::fs::symlink_metadata(path)?.file_type().is_file() {
                return Err(io::Error::other("test ACL fixtures must be regular files"));
            }
        }
    }
    if config.test_null_device {
        if !config.test_only || !cfg!(feature = "test-support") {
            return Err(io::Error::other(
                "synthetic device requires test-only and test-support",
            ));
        }
        use std::os::unix::fs::MetadataExt;
        initial.brokered.insert(
            config.test_seats[0].clone(),
            vec![crate::device::AllowedDevice::canonicalized(
                crate::device::DeviceId::new("test-only:null"),
                "/dev/null",
                std::fs::metadata("/dev/null")?.rdev(),
                crate::device::DeviceKind::Evdev,
            )?],
        );
    }
    // Stale named-user ACLs must be cleared before controllers/name publication.
    let initial = topology_transaction::initialize(resources.clone(), initial).await?;
    let mut policies = initial.policies;
    let initial = initial.snapshot;
    let mut paused = BTreeSet::new();
    let mut daemon = Daemon::new(
        Registry::new(Limits::default()).map_err(io::Error::other)?,
        258,
    )
    .map_err(io::Error::other)?;
    let mut vt_owner = if let Some(terminal) = config.graphical_vt {
        if config.test_only {
            return Err(io::Error::other(
                "synthetic fixtures cannot claim a real VT",
            ));
        }
        Some(
            crate::vt::Owner::start(
                terminal,
                resources.clone(),
                initial.seats.contains(&SeatName::seat0()),
            )
            .await?,
        )
    } else {
        None
    };
    let vt = vt_owner.as_ref().map(crate::vt::Owner::port);
    if let Some(port) = vt.clone() {
        let mut shutdown = daemon.subscribe();
        daemon.spawn(CriticalRole::VtOwner, async move {
            tokio::select! { biased; _ = shutdown.reached(ShutdownPhase::RestoreTerminal) => Ok(()), failure = port.failed() => failure }
        }).map_err(io::Error::other)?;
    }
    let budget = Budget::default();
    let mut seats = BTreeMap::new();
    add_seats(
        &initial,
        &mut daemon,
        &mut seats,
        &resources,
        &budget,
        &policies,
        vt.as_ref(),
    )?;
    let watched = context
        .as_ref()
        .map(|context| {
            let fd = context.monitor_fd().try_clone_to_owned()?;
            // SAFETY: owned duplicate stays open/unchanged until watch destruction.
            unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)
        })
        .transpose()?;
    let (bus, mut incoming, replies) = BusIo::connect(config.session_bus)?;
    let (ready, started) = oneshot::channel();
    daemon
        .spawn(CriticalRole::Bus, bus.run(daemon.subscribe(), ready))
        .map_err(io::Error::other)?;
    let mut requests = JoinSet::new();
    let mut removals = JoinSet::new();
    let mut removing = BTreeSet::new();
    let mut removal_retry = BTreeMap::new();
    let mut retiring = BTreeSet::new();
    let mut stopped = BTreeSet::new();
    let mut topology = JoinSet::new();
    let mut desired = None;
    let mut generation = 0u64;
    let mut prepared_generation = 0u64;
    let mut prepared = initial;
    let mut revision = 0u64;
    let mut inventory = Vec::new();
    let mut retry = interval(Duration::from_millis(100));
    let mut audit = interval(Duration::from_secs(1));
    // startup notification is diagnostic; service failure is always supervised.
    tokio::pin!(started);
    let mut startup_observed = false;
    let result: io::Result<()> = async {
        loop {
            queue_removals(&mut daemon, &seats, &mut removing, &mut removal_retry, &mut removals);
            for name in &retiring {
                if topology.is_empty() && desired.is_none() && !stopped.contains(name) && !daemon.registry().removals().any(|(_, seat)| seat == name)
                    && let Some(port) = seats.get(name)
                {
                    daemon.retire_seat(name);
                    if port.send(Command::Stop).is_ok() { stopped.insert(name.clone()); }
                }
            }
            if topology.is_empty() && let Some((revision, snapshot)) = desired.take() {
                let resources = resources.clone();
                let previous = policies.clone();
                let ports = seats.clone();
                let touched = paused.clone();
                let shutdown = daemon.subscribe();
                let terminal = vt.clone();
                topology.spawn(async move { (revision, topology_transaction::reconcile(resources, snapshot, previous, ports, touched, shutdown, terminal).await) });
            }
            tokio::select! {
                biased;
                signal = signals.requested() => { signal?; break Ok(()) },
                event = daemon.changed() => {
                    if let Some(exit) = event? {
                        if let Some(failure) = exit.failure { break Err(io::Error::other(failure)) }
                        if let CriticalRole::Seat(name) = exit.role {
                            seats.remove(&name); retiring.remove(&name); stopped.remove(&name);
                        }
                    }
                }
                joined = removals.join_next(), if !removals.is_empty() => {
                    let (id, result) = joined.expect("nonempty removal set").map_err(io::Error::other)?;
                    removing.remove(&id);
                    if result.is_ok() {
                        daemon.registry_mut().complete_removal(id);
                        removal_retry.remove(&id);
                    } else {
                        removal_retry.insert(id, Instant::now() + Duration::from_secs(1));
                    }
                }
                joined = requests.join_next(), if !requests.is_empty() => { joined.expect("nonempty request set").map_err(io::Error::other)?; }
                joined = topology.join_next(), if !topology.is_empty() => {
                    let (revision, snapshot) = joined.expect("nonempty topology set").map_err(io::Error::other)?;
                    let Some(update) = snapshot? else { continue };
                    paused.extend(update.affected.iter().cloned());
                    if revision == generation {
                        for name in &paused {
                            if let Some(port) = seats.get(name) { port.commit_policy().await.map_err(|error| io::Error::other(format!("topology commit: {error:?}")))?; }
                        }
                        prepared = update.snapshot;
                        policies = update.policies;
                        paused.clear();
                        prepared_generation = revision;
                        add_seats(&prepared, &mut daemon, &mut seats, &resources, &budget, &policies, vt.as_ref())?;
                    }
                }
                _ = retry.tick() => {
                    if prepared_generation == generation { add_seats(&prepared, &mut daemon, &mut seats, &resources, &budget, &policies, vt.as_ref())?; }
                    let current: Vec<_> = seats.values().map(|port| port.status.borrow().clone()).collect();
                    if current != inventory {
                        inventory = current;
                        revision = revision.checked_add(1).ok_or_else(|| io::Error::other("inventory revision exhaustion"))?;
                        replies.state_changed(revision);
                    }
                }
                _ = audit.tick(), if topology.is_empty() && desired.is_none() => {
                    let snapshot = if let Some(context) = &context { filtered(Snapshot::from_context(context, &[])?, config.non_vt_only, config.graphical_vt)? } else { prepared.clone() };
                    generation = generation.checked_add(1).ok_or_else(|| io::Error::other("topology generation exhaustion"))?;
                    desired = Some((generation, snapshot));
                }
                result = &mut started, if !startup_observed => {
                    result.map_err(|_| io::Error::other("bus startup failed"))?;
                    startup_observed = true;
                    tracing::info!("context manager is ready");
                }
                // Fair selection between fresh calls and topology facts. Other
                // control/cleanup branches above cannot be starved by clients.
                event = async {
                    tokio::select! {
                        request = incoming.recv() => Input::Request(request),
                        ready = monitor_ready(watched.as_ref()) => Input::Topology(ready),
                    }
                } => match event {
                    Input::Request(Some(request)) => {
                        if requests.len() == 64 { let _ = replies.send(error_reply(&request.message, ErrorKind::LimitExceeded, "request wait limit reached")); }
                        else { requests.spawn(manager::dispatch(request, daemon.registry_mut(), &seats, replies.clone())); }
                    }
                    Input::Request(None) => break Err(io::Error::other("D-Bus request pump stopped")),
                    Input::Topology(result) => {
                        let mut ready = result?;
                        let context = context.as_mut().expect("monitor context");
                        let mut count = 0;
                        while count < 64 && context.receive().map_err(io::Error::other)?.is_some() { count += 1; }
                        if count < 64 { ready.clear_ready(); } else { ready.retain_ready(); }
                        let snapshot = filtered(Snapshot::from_context(context, &[])?, config.non_vt_only, config.graphical_vt)?;
                        for name in seats.keys().filter(|name| !snapshot.seats.contains(*name)) {
                            daemon.registry_mut().withdraw_seat(name);
                            retiring.insert(name.clone());
                        }
                        generation = generation.checked_add(1).ok_or_else(|| io::Error::other("topology generation exhaustion"))?;
                        desired = Some((generation, snapshot));
                    }
                }
            }
        }
    }.await;
    daemon.quiesce();
    resources.fence();
    let mut shutdown_failed = false;
    // Drain pending publications, including registration replies already queued
    // in controllers. Guards cannot resurrect any now-invalidated context.
    while let Some(joined) = requests.join_next().await {
        if let Err(error) = joined {
            shutdown_failed = true;
            tracing::error!(%error, "request task failed during shutdown");
        }
    }
    // A topology worker must settle before global cleanup takes its snapshot.
    while let Some(joined) = topology.join_next().await {
        match joined {
            Ok((_, Ok(_))) => {}
            Ok((_, Err(error))) => {
                shutdown_failed = true;
                tracing::error!(%error, "topology preparation failed during shutdown");
            }
            Err(error) => {
                shutdown_failed = true;
                tracing::error!(%error, "topology task failed during shutdown");
            }
        }
    }
    daemon
        .advance(ShutdownPhase::Revoke)
        .map_err(io::Error::other)?;
    let cleanup_resources = resources.clone();
    let cleanup_errors = tokio::task::spawn_blocking(move || cleanup_resources.cleanup())
        .await
        .map_err(io::Error::other)?;
    if cleanup_errors.is_empty() {
        // The outer resource owner can acknowledge teardown even if a critical
        // seat owner failed: all indexed originals/inodes and started mutations
        // have now settled under their actual resource locks.
        let ids: Vec<_> = daemon.registry().removals().map(|(id, _)| id).collect();
        for id in ids {
            daemon.registry_mut().complete_removal(id);
        }
        while let Some(joined) = removals.join_next().await {
            if let Err(error) = joined {
                shutdown_failed = true;
                tracing::error!(%error, "removal task panicked during shutdown");
            }
        }
        daemon
            .advance(ShutdownPhase::RestoreTerminal)
            .map_err(io::Error::other)?;
    } else {
        for error in cleanup_errors {
            tracing::error!(%error, "resource cleanup incomplete");
        }
        return Err(io::Error::other("resource cleanup incomplete"));
    }
    let exits = daemon.drain().await.map_err(io::Error::other)?;
    let failed = exits.iter().any(|exit| exit.failure.is_some());
    if let Some(owner) = &mut vt_owner {
        owner.finish()?;
    }
    daemon
        .advance(ShutdownPhase::Stopped)
        .map_err(io::Error::other)?;
    drop(replies);
    result?;
    if failed || shutdown_failed {
        return Err(io::Error::other("critical service failed during shutdown"));
    }
    Ok(())
}

enum Input<'a> {
    Request(Option<crate::dbus::reactor::Request>),
    Topology(io::Result<AsyncFdReadyGuard<'a, OwnedFd>>),
}

async fn monitor_ready(
    watched: Option<&AsyncFd<OwnedFd>>,
) -> io::Result<AsyncFdReadyGuard<'_, OwnedFd>> {
    match watched {
        Some(watched) => watched.readable().await,
        None => std::future::pending().await,
    }
}

fn filtered(
    mut snapshot: Snapshot,
    non_vt_only: bool,
    graphical_vt: Option<u32>,
) -> io::Result<Snapshot> {
    if snapshot.seats.contains(&SeatName::seat0()) {
        if !non_vt_only && graphical_vt.is_none() {
            return Err(io::Error::other(
                "seat0 requires an explicitly configured graphical VT; use --non-vt-only only to leave seat0 unmanaged",
            ));
        }
        if non_vt_only {
            snapshot.seats.remove(&SeatName::seat0());
            snapshot.direct.remove(&SeatName::seat0());
            snapshot.brokered.remove(&SeatName::seat0());
        }
    }
    Ok(snapshot)
}

fn add_seats(
    snapshot: &Snapshot,
    daemon: &mut Daemon,
    seats: &mut BTreeMap<SeatName, Port>,
    resources: &Arc<Resources>,
    budget: &Budget,
    policies: &BTreeMap<SeatName, Policy>,
    vt: Option<&crate::vt::Port>,
) -> io::Result<()> {
    for name in &snapshot.seats {
        if seats.contains_key(name) {
            continue;
        }
        match daemon.registry_mut().add_seat(name.clone()) {
            Ok(()) => {}
            Err(crate::registry::RegistryError::CleanupPending) => continue,
            Err(error) => return Err(io::Error::other(error)),
        }
        let (mut controller, port) =
            Controller::new(name.clone(), resources.clone(), budget.clone());
        controller.set_initial_policy(policies.get(name).cloned().unwrap_or_default());
        if name == &SeatName::seat0()
            && let Some(port) = vt
        {
            controller.attach_vt(port.clone());
        }
        daemon
            .spawn(
                CriticalRole::Seat(name.clone()),
                controller.run(daemon.subscribe()),
            )
            .map_err(io::Error::other)?;
        seats.insert(name.clone(), port);
    }
    Ok(())
}

type Removal = (ContextId, Result<(), ErrorKind>);
fn queue_removals(
    daemon: &mut Daemon,
    seats: &BTreeMap<SeatName, Port>,
    removing: &mut BTreeSet<ContextId>,
    retry: &mut BTreeMap<ContextId, Instant>,
    jobs: &mut JoinSet<Removal>,
) {
    for (id, name) in daemon.registry().removals() {
        if jobs.len() == 64 {
            break;
        }
        if removing.contains(&id)
            || retry
                .get(&id)
                .is_some_and(|deadline| *deadline > Instant::now())
        {
            continue;
        }
        if let Some(port) = seats.get(name) {
            let (sender, receiver) = oneshot::channel();
            if port
                .send(Command::Remove {
                    context: id,
                    reply: sender,
                })
                .is_ok()
            {
                removing.insert(id);
                jobs.spawn(async move {
                    (
                        id,
                        timeout(Duration::from_secs(10), receiver)
                            .await
                            .ok()
                            .and_then(Result::ok)
                            .unwrap_or(Err(ErrorKind::CleanupPending)),
                    )
                });
            }
        }
    }
}
