//! Source-first topology publication. A queued snapshot is not authorization.
use crate::daemon::{Shutdown, ShutdownPhase};
use crate::resources::{Permit, Resources};
use crate::seat::{
    Port,
    policy::{self, Policy},
};
use crate::topology::Snapshot;
use seat_udev::SeatName;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::Arc;

pub struct Prepared {
    pub snapshot: Snapshot,
    pub policies: BTreeMap<SeatName, Policy>,
    pub affected: BTreeSet<SeatName>,
}

pub async fn initialize(resources: Arc<Resources>, snapshot: Snapshot) -> io::Result<Prepared> {
    let policies = stage(resources.clone(), snapshot.clone()).await?;
    clear(
        resources,
        policies.clone(),
        BTreeMap::new(),
        policies.keys().cloned().collect(),
    )
    .await?;
    Ok(Prepared {
        snapshot,
        policies,
        affected: BTreeSet::new(),
    })
}

async fn stage(
    resources: Arc<Resources>,
    snapshot: Snapshot,
) -> io::Result<BTreeMap<SeatName, Policy>> {
    tokio::task::spawn_blocking(move || policy::prepare(&resources, &snapshot))
        .await
        .map_err(io::Error::other)?
}

pub async fn reconcile(
    resources: Arc<Resources>,
    snapshot: Snapshot,
    previous: BTreeMap<SeatName, Policy>,
    ports: BTreeMap<SeatName, Port>,
    mut affected: BTreeSet<SeatName>,
    mut shutdown: Shutdown,
    terminal: Option<crate::vt::Port>,
) -> io::Result<Option<Prepared>> {
    let policies = stage(resources.clone(), snapshot.clone()).await?;
    for seat in previous.keys().chain(policies.keys()) {
        if previous.get(seat) != policies.get(seat) {
            affected.insert(seat.clone());
        }
    }
    // Fence every affected source before waiting for any one source. Destination
    // publication happens only after all actual transport/resource barriers.
    let mut replies = Vec::new();
    for seat in &affected {
        if let Some(port) = ports.get(seat) {
            replies.push(
                port.prepare_policy(policies.get(seat).cloned().unwrap_or_default())
                    .await
                    .map_err(|error| io::Error::other(format!("source admission: {error:?}")))?,
            );
        }
    }
    for reply in replies {
        tokio::select! {
            biased;
            _ = shutdown.reached(ShutdownPhase::Quiesce) => return Ok(None),
            result = reply => {
                result.map_err(io::Error::other)?.map_err(|error| io::Error::other(format!("source cleanup: {error:?}")))?;
            }
        }
    }
    if shutdown.phase() >= ShutdownPhase::Quiesce {
        return Ok(None);
    }
    if let Some(terminal) = terminal {
        terminal
            .presence_after_cleanup(snapshot.seats.contains(&SeatName::seat0()))
            .await?;
    }
    clear(resources, policies.clone(), previous, affected.clone()).await?;
    Ok(Some(Prepared {
        snapshot,
        policies,
        affected,
    }))
}

async fn clear(
    resources: Arc<Resources>,
    policies: BTreeMap<SeatName, Policy>,
    previous: BTreeMap<SeatName, Policy>,
    affected: BTreeSet<SeatName>,
) -> io::Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut errors = Vec::new();
        for seat in &affected {
            if let Some(policy) = policies.get(seat) {
                for identity in &policy.nodes {
                    if let Err(error) = resources.apply(*identity, &BTreeSet::new(), &Permit::new())
                    {
                        errors.push(error);
                    }
                }
            }
        }
        let retained: BTreeSet<_> = policies
            .values()
            .flat_map(|policy| policy.nodes.iter().copied())
            .collect();
        let old: BTreeSet<_> = previous
            .values()
            .flat_map(|policy| policy.nodes.iter().copied())
            .collect();
        for identity in old.difference(&retained) {
            if let Err(error) = resources.clear(*identity) {
                errors.push(error);
            }
        }
        errors.into_iter().next().map_or(Ok(()), Err)
    })
    .await
    .map_err(io::Error::other)?
}
