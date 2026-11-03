//! Immutable, prepared authorization for one topology generation.
use super::*;
use crate::acl::NodeIdentity;
use crate::device::{AllowedDevice, DeviceId, DeviceKind};
use crate::resources::Resources;
use crate::topology::Snapshot;
use seat_udev::SeatName;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Policy {
    pub ready: bool,
    pub synthetic: bool,
    pub devices: Arc<BTreeMap<PathBuf, AllowedDevice>>,
    pub nodes: BTreeSet<NodeIdentity>,
}

impl Controller {
    pub fn set_initial_policy(&mut self, policy: Policy) {
        assert!(self.contexts.is_empty());
        self.policy = policy;
    }

    pub(super) fn pause_policy(&mut self, policy: Policy, reply: Reply) {
        self.policy_gate.borrow().fence();
        self.topology_paused = true;
        self.retire_outdated(&policy);
        self.policy_pending = Some(policy);
        self.policy_replies.retain(|reply| !reply.is_closed());
        if self.policy_replies.len() == 64 {
            let _ = reply.send(Err(ErrorKind::LimitExceeded));
        } else {
            self.policy_replies.push(reply);
        }
        if let Some(transition) = &mut self.transition {
            transition.failure = Some(ErrorKind::TransitionPending);
        } else if let Some(old) = self.effective.take() {
            let mut pending_disable = BTreeSet::new();
            self.fence_context(old, &mut pending_disable);
            self.transition = Some(Transition {
                requested: old,
                activate: false,
                target: None,
                withdrawing: BTreeSet::from([old]),
                pending_disable,
                pending_enable: BTreeSet::new(),
                deadline: Instant::now() + Duration::from_secs(2),
                enabling: false,
                replies: Vec::new(),
                failure: None,
            });
        }
    }

    pub(super) fn commit_policy(&mut self) {
        if !self.policy_replies.is_empty() {
            return;
        }
        if let Some(policy) = self.policy_pending.take() {
            self.policy = policy;
            self.policy_gate.send_replace(Permit::new());
            self.topology_paused = false;
            self.vt_requested = false;
            self.resume_policy = true;
        }
    }

    pub(super) fn policy_progress(&mut self) {
        if self.topology_paused
            && self.access.is_none()
            && self.transition.is_none()
            && self.jobs.is_empty()
            && self.device_jobs.is_empty()
            && self.contexts.iter().all(|(id, context)| {
                !context.dirty
                    && !context.preparing
                    && !context.revoking
                    && !self.context_operations(*id)
            })
        {
            for reply in self.policy_replies.drain(..) {
                let _ = reply.send(Ok(()));
            }
        }
        if self.resume_policy
            && self.foreground()
            && self.access.is_none()
            && !self.topology_paused
            && self.transition.is_none()
            && self.mutations.is_empty()
        {
            self.resume_policy = false;
            if let Some(context) = self.selected
                && self.effective != Some(context)
            {
                let (reply, _) = oneshot::channel();
                self.mutate(context, true, reply, false);
            }
        }
    }
}

pub fn prepare(
    resources: &Resources,
    snapshot: &Snapshot,
) -> io::Result<BTreeMap<SeatName, Policy>> {
    let mut policies = BTreeMap::<SeatName, Policy>::new();
    let mut numbers = BTreeMap::new();
    for (seat, devices) in &snapshot.brokered {
        for device in devices {
            if device.id.as_str() == "test-only:null" {
                if !cfg!(feature = "test-support")
                    || device.path != std::path::Path::new("/dev/null")
                    || device.kind != DeviceKind::Evdev
                {
                    return Err(io::Error::other("invalid synthetic device"));
                }
                policies.entry(seat.clone()).or_default().synthetic = true;
            }
            if numbers
                .insert(device.device_number, seat)
                .is_some_and(|previous| previous != seat)
            {
                return Err(io::Error::other("device authorized on multiple seats"));
            }
            let kind = device.kind;
            let device = match AllowedDevice::canonicalized(
                DeviceId::new(device.id.as_str()),
                &device.path,
                device.device_number,
                kind,
            ) {
                Ok(device) => device,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if snapshot
                .identities
                .get(&device.path)
                .is_some_and(|expected| !device.same_inode(*expected))
            {
                continue;
            }
            Arc::make_mut(&mut policies.entry(seat.clone()).or_default().devices)
                .insert(device.path.clone(), device);
        }
    }
    let mut identities = BTreeMap::new();
    for (seat, paths) in &snapshot.direct {
        for path in paths {
            let identity =
                match resources.pin_expected(path, snapshot.identities.get(path).copied()) {
                    Ok(Some(identity)) => identity,
                    Ok(None) => continue,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                };
            if identities
                .insert(identity, seat)
                .is_some_and(|previous| previous != seat)
            {
                return Err(io::Error::other("ACL inode authorized on multiple seats"));
            }
            policies
                .entry(seat.clone())
                .or_default()
                .nodes
                .insert(identity);
        }
    }
    for seat in &snapshot.seats {
        policies.entry(seat.clone()).or_default().ready = true;
    }
    Ok(policies)
}
