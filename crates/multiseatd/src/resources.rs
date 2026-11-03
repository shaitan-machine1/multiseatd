//! Outer cleanup ownership for broker descriptions and pinned ACL inodes.
//!
//! Register before starting a mutation. Blocking jobs borrow these retained
//! records; cancellation/unwinding cannot discard the only revocation handle.
//! Actual operations on a kernel device key or ACL inode are serialized. No
//! global index lock is held over an ioctl, xattr operation or await.

use crate::acl::{NodeIdentity, PinnedNode};
use crate::device::{AllowedDevice, DeviceKind, DeviceOps, KernelDeviceOps};
use libmultiseatd::ConnectionId;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

type DeviceKey = u64;
type DeviceRecords = BTreeMap<HandleId, Arc<Mutex<DeviceRecord>>>;
type CardKeys = BTreeMap<DeviceKey, Arc<Mutex<KeyState>>>;

#[derive(Default)]
struct KeyState {
    master: Option<HandleId>,
    blocked: BTreeSet<HandleId>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HandleId(u64);

/// One activation generation. A fence never reopens; resumption creates a new
/// permit. Old queued jobs cannot become current by observing a reused boolean.
#[derive(Clone)]
pub struct Permit {
    open: Arc<AtomicBool>,
    parents: Vec<Arc<AtomicBool>>,
    lifetime: Option<crate::registry::Registration>,
}

impl Default for Permit {
    fn default() -> Self {
        Self::new()
    }
}

impl Permit {
    pub fn new() -> Self {
        Self {
            open: Arc::new(AtomicBool::new(true)),
            parents: Vec::new(),
            lifetime: None,
        }
    }
    pub fn for_context(lifetime: crate::registry::Registration) -> Self {
        Self {
            lifetime: Some(lifetime),
            ..Self::new()
        }
    }

    pub fn gated(&self, gate: Arc<AtomicBool>) -> Self {
        let mut child = self.child();
        child.parents.push(gate);
        child
    }

    pub fn child(&self) -> Self {
        let mut parents = self.parents.clone();
        parents.push(self.open.clone());
        Self {
            open: Arc::new(AtomicBool::new(true)),
            parents,
            lifetime: self.lifetime.clone(),
        }
    }

    pub fn gate(&self) -> Arc<AtomicBool> {
        self.open.clone()
    }

    pub fn fence(&self) {
        self.open.store(false, Ordering::Release);
    }
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
            && self
                .parents
                .iter()
                .all(|parent| parent.load(Ordering::Acquire))
            && self
                .lifetime
                .as_ref()
                .is_none_or(crate::registry::Registration::is_live)
    }
}

struct DeviceRecord {
    owner: ConnectionId,
    device: AllowedDevice,
    key: Arc<Mutex<KeyState>>,
    fd: Option<OwnedFd>,
    active: bool,
    retired: bool,
    ops: Box<dyn DeviceOps>,
}

impl DeviceRecord {
    fn resume(&mut self) -> io::Result<()> {
        let fd = self.fd.as_ref().ok_or_else(stopped)?;
        // If activation fails/panics, conservatively retain revocation work.
        self.active = true;
        self.ops.activate(self.device.kind, fd)
    }

    fn revoke(&mut self) -> io::Result<()> {
        if self.active {
            self.ops.deactivate(
                self.device.kind,
                self.fd.as_ref().expect("active description"),
            )?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for DeviceRecord {
    fn drop(&mut self) {
        // Last-resort unwinding protection, not normal resource reconciliation.
        if let Err(error) = attempt(|| self.revoke()) {
            tracing::error!(%error, "final brokered description revocation failed");
        }
    }
}

struct NodeRecord {
    pinned: PinnedNode,
    retired: bool,
}

pub struct Resources {
    devices: Mutex<DeviceRecords>,
    keys: Mutex<CardKeys>,
    nodes: Mutex<BTreeMap<NodeIdentity, Arc<Mutex<NodeRecord>>>>,
    #[cfg(test)]
    acl_failures: Mutex<BTreeMap<NodeIdentity, usize>>,
    #[cfg(test)]
    open_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    closing: AtomicBool,
    next: AtomicU64,
    device_limit: usize,
    node_limit: usize,
}

impl Resources {
    pub fn new(device_limit: usize, node_limit: usize) -> io::Result<Self> {
        if device_limit == 0 || node_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource limits must be nonzero",
            ));
        }
        Ok(Self {
            devices: Mutex::new(BTreeMap::new()),
            keys: Mutex::new(BTreeMap::new()),
            nodes: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            acl_failures: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            open_hook: Mutex::new(None),
            closing: AtomicBool::new(false),
            next: AtomicU64::new(1),
            device_limit,
            node_limit,
        })
    }

    pub fn reserve(&self, owner: ConnectionId, device: AllowedDevice) -> io::Result<HandleId> {
        self.reserve_with(owner, device, Box::<KernelDeviceOps>::default())
    }

    pub(crate) fn reserve_with(
        &self,
        owner: ConnectionId,
        device: AllowedDevice,
        ops: Box<dyn DeviceOps>,
    ) -> io::Result<HandleId> {
        let mut records = lock(&self.devices);
        if self.closing.load(Ordering::Acquire) {
            return Err(stopped());
        }
        if records.len() == self.device_limit {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "broker handle limit reached",
            ));
        }
        // The device-index lock serializes allocation (including overflow).
        let value = self.next.load(Ordering::Relaxed);
        self.next.store(
            value
                .checked_add(1)
                .ok_or_else(|| io::Error::other("handle ID exhaustion"))?,
            Ordering::Relaxed,
        );
        let id = HandleId(value);
        let key = lock(&self.keys)
            .entry(device.device_number)
            .or_default()
            .clone();
        records.insert(
            id,
            Arc::new(Mutex::new(DeviceRecord {
                owner,
                device,
                key,
                fd: None,
                active: false,
                retired: false,
                ops,
            })),
        );
        Ok(id)
    }

    fn record(&self, id: HandleId) -> io::Result<Arc<Mutex<DeviceRecord>>> {
        lock(&self.devices)
            .get(&id)
            .cloned()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
    }

    /// Run in an admitted blocking worker. A result FD is only a duplicate;
    /// the server's original is retained before any caller can receive it.
    pub fn open(&self, id: HandleId, permit: &Permit) -> io::Result<OwnedFd> {
        let record = self.record(id)?;
        let mut record = lock(&record);
        let key = record.key.clone();
        let mut master = lock(&key);
        if record.retired || self.closing.load(Ordering::Acquire) || !permit.is_open() {
            return Err(stopped());
        }
        if !master.blocked.is_empty() {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        if record.fd.is_none() {
            if record.device.kind == DeviceKind::DrmPrimary && master.master.is_some() {
                return Err(io::Error::from_raw_os_error(libc::EBUSY));
            }
            #[cfg(test)]
            {
                let hook = lock(&self.open_hook).clone();
                if let Some(hook) = hook {
                    hook();
                }
            }
            let device = record.device.clone();
            let fd = record.ops.open(&device)?;
            record.fd = Some(fd);
            record.active = true;
            if record.device.kind == DeviceKind::DrmPrimary {
                master.master = Some(id);
            }
        } else if !record.active {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        // Fencing during a started open cannot publish a late description.
        // Leave its original retained for the cleanup barrier, even on error.
        if self.closing.load(Ordering::Acquire) || !permit.is_open() {
            return Err(stopped());
        }
        record.fd.as_ref().expect("opened description").try_clone()
    }

    /// Ordinary disable preserves primary-node descriptions for master resume.
    /// Input descriptions are permanently revoked and never reused.
    pub fn deactivate(&self, id: HandleId) -> io::Result<()> {
        let record = match self.record(id) {
            Ok(record) => record,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
            Err(error) => return Err(error),
        };
        let mut entry = lock(&record);
        let key = entry.key.clone();
        let mut state = lock(&key);
        state.blocked.insert(id);
        entry.revoke()?;
        state.blocked.remove(&id);
        if state.master == Some(id) {
            state.master = None;
        }
        if entry.device.kind != DeviceKind::DrmPrimary {
            entry.retired = true;
            entry.fd.take();
        }
        Ok(())
    }

    pub fn activate(&self, id: HandleId, permit: &Permit) -> io::Result<()> {
        let record = self.record(id)?;
        let mut entry = lock(&record);
        let key = entry.key.clone();
        let mut state = lock(&key);
        if entry.retired || self.closing.load(Ordering::Acquire) || !permit.is_open() {
            return Err(stopped());
        }
        if entry.device.kind != DeviceKind::DrmPrimary || entry.fd.is_none() {
            return Ok(());
        }
        if !state.blocked.is_empty() || state.master.is_some_and(|owner| owner != id) {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        if !entry.active {
            state.master = Some(id);
            entry.resume()?;
        }
        Ok(())
    }

    fn owner_records(&self, owner: ConnectionId) -> Vec<HandleId> {
        let records: Vec<_> = lock(&self.devices)
            .iter()
            .map(|(id, entry)| (*id, entry.clone()))
            .collect();
        records
            .into_iter()
            .filter_map(|(id, entry)| (lock(&entry).owner == owner).then_some(id))
            .collect()
    }

    pub fn deactivate_owner(&self, owner: ConnectionId) -> Vec<io::Error> {
        self.owner_records(owner)
            .into_iter()
            .filter_map(|id| self.deactivate(id).err())
            .collect()
    }

    pub fn activate_owner(&self, owner: ConnectionId, permit: &Permit) -> Vec<io::Error> {
        self.owner_records(owner)
            .into_iter()
            .filter_map(|id| {
                let record = self.record(id).ok()?;
                let eligible = {
                    let entry = lock(&record);
                    !entry.retired
                        && entry.device.kind == DeviceKind::DrmPrimary
                        && entry.fd.is_some()
                };
                if eligible {
                    self.activate(id, permit).err()
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn close_owner(&self, owner: ConnectionId) -> Vec<io::Error> {
        self.owner_records(owner)
            .into_iter()
            .filter_map(|id| self.close(id).err())
            .collect()
    }

    pub fn owner(&self, id: HandleId) -> io::Result<ConnectionId> {
        let record = self.record(id)?;
        let owner = lock(&record).owner;
        Ok(owner)
    }

    /// Irreversible record close. Failure keeps its original and master claim,
    /// independently of a deleted membership, so conflicting access stays shut.
    pub fn close(&self, id: HandleId) -> io::Result<()> {
        let record = match self.record(id) {
            Ok(record) => record,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
            Err(error) => return Err(error),
        };
        let mut entry = lock(&record);
        let key = entry.key.clone();
        let mut master = lock(&key);
        entry.retired = true;
        // Install the conflict fence BEFORE the ioctl, including unwind paths.
        master.blocked.insert(id);
        entry.revoke()?;
        entry.fd.take();
        master.blocked.remove(&id);
        if master.master == Some(id) {
            master.master = None;
        }
        drop(master);
        drop(entry);
        lock(&self.devices).remove(&id);
        // Only remove a key when no other reserved description references it.
        // This keeps physical-key serialization stable across generations.
        lock(&self.keys).retain(|_, key| Arc::strong_count(key) > 1);
        Ok(())
    }

    pub fn pin(&self, path: &Path) -> io::Result<NodeIdentity> {
        self.pin_expected(path, None)?
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))
    }

    pub fn pin_expected(
        &self,
        path: &Path,
        expected: Option<(u64, u64)>,
    ) -> io::Result<Option<NodeIdentity>> {
        let pinned = PinnedNode::open(path)?;
        let identity = pinned.identity();
        if expected.is_some_and(|expected| !identity.same_inode(expected)) {
            return Ok(None);
        }
        let mut nodes = lock(&self.nodes);
        if self.closing.load(Ordering::Acquire) {
            return Err(stopped());
        }
        if nodes.contains_key(&identity) {
            return Ok(Some(identity));
        }
        if nodes.len() == self.node_limit {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "ACL inode limit reached",
            ));
        }
        nodes.insert(
            identity,
            Arc::new(Mutex::new(NodeRecord {
                pinned,
                retired: false,
            })),
        );
        Ok(Some(identity))
    }

    pub fn apply(
        &self,
        identity: NodeIdentity,
        users: &BTreeSet<u32>,
        permit: &Permit,
    ) -> io::Result<()> {
        self.apply_then(identity, users, permit, || {})
    }

    #[cfg(all(test, feature = "test-support"))]
    pub(crate) fn set_open_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *lock(&self.open_hook) = hook;
    }

    #[cfg(test)]
    pub(crate) fn fail_acl_writes(&self, identity: NodeIdentity, count: usize) {
        lock(&self.acl_failures).insert(identity, count);
    }

    pub(crate) fn apply_then(
        &self,
        identity: NodeIdentity,
        users: &BTreeSet<u32>,
        permit: &Permit,
        after: impl FnOnce(),
    ) -> io::Result<()> {
        let record = lock(&self.nodes).get(&identity).cloned();
        let Some(record) = record else {
            return if users.is_empty() {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(libc::ENOENT))
            };
        };
        let record = lock(&record);
        if !users.is_empty()
            && (record.retired || self.closing.load(Ordering::Acquire) || !permit.is_open())
        {
            return Err(stopped());
        }
        #[cfg(test)]
        if let Some(count) = lock(&self.acl_failures).get_mut(&identity)
            && *count != 0
        {
            *count -= 1;
            return Err(io::Error::other("injected ACL write failure"));
        }
        record.pinned.apply(users)?;
        after();
        Ok(())
    }

    /// Forget a pinned inode only after an actual successful empty ACL write.
    pub fn clear(&self, identity: NodeIdentity) -> io::Result<()> {
        let record = lock(&self.nodes).get(&identity).cloned();
        if let Some(record) = record {
            let mut entry = lock(&record);
            entry.retired = true;
            entry.pinned.apply(&BTreeSet::new())?;
            drop(entry);
            lock(&self.nodes).remove(&identity);
        }
        Ok(())
    }

    pub fn fence(&self) {
        self.closing.store(true, Ordering::Release);
    }

    pub fn pending(&self) -> (usize, usize) {
        (lock(&self.devices).len(), lock(&self.nodes).len())
    }

    /// Independent attempts; one ioctl failure or poisoned record does not skip
    /// ACL cleanup or another description. Started jobs settle under their own
    /// resource locks. Persistent kernel refusal remains owned for retry.
    pub fn cleanup(&self) -> Vec<io::Error> {
        self.fence();
        let devices: Vec<_> = lock(&self.devices).keys().copied().collect();
        let nodes: Vec<_> = lock(&self.nodes).keys().copied().collect();
        let mut errors = Vec::new();
        for id in devices {
            if let Err(error) = attempt(|| self.close(id)) {
                errors.push(error);
            }
        }
        for identity in nodes {
            if let Err(error) = attempt(|| self.clear(identity)) {
                errors.push(error);
            }
        }
        errors
    }
}

/// Keep outside all critical tasks and until blocking workers have settled.
/// Jobs clone Resources, not this guard. Owner panic fences/revokes while their
/// original descriptions and pinned inode handles are still available.
pub struct CleanupGuard(pub Arc<Resources>);

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        for error in self.0.cleanup() {
            tracing::error!(%error, "best-effort outer resource cleanup failed");
        }
    }
}

fn stopped() -> io::Error {
    io::Error::from_raw_os_error(libc::EACCES)
}
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn attempt(operation: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).unwrap_or_else(|_| {
        Err(io::Error::other(
            "resource cleanup panicked; retained for retry",
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::AtomicUsize;

    struct Fake {
        calls: Arc<AtomicUsize>,
        fail: Arc<AtomicBool>,
        opened: Arc<AtomicBool>,
    }
    impl DeviceOps for Fake {
        fn open(&mut self, _: &AllowedDevice) -> io::Result<OwnedFd> {
            self.opened.store(true, Ordering::Release);
            Ok(std::fs::File::open("/dev/null")?.into())
        }
        fn deactivate(&mut self, _: DeviceKind, fd: &OwnedFd) -> io::Result<()> {
            // Proves a real original FD survived, not merely a logical ID.
            assert!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } >= 0);
            self.calls.fetch_add(1, Ordering::AcqRel);
            if self.fail.load(Ordering::Acquire) {
                Err(io::Error::other("injected revoke failure"))
            } else {
                Ok(())
            }
        }
        fn activate(&mut self, _: DeviceKind, _: &OwnedFd) -> io::Result<()> {
            Ok(())
        }
    }
    fn device() -> AllowedDevice {
        use std::os::unix::fs::MetadataExt;
        AllowedDevice::canonicalized(
            crate::device::DeviceId::new("fixture"),
            "/dev/null",
            std::fs::metadata("/dev/null").unwrap().rdev(),
            DeviceKind::Evdev,
        )
        .unwrap()
    }
    fn fake() -> (Box<dyn DeviceOps>, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicBool::new(false));
        (
            Box::new(Fake {
                calls: calls.clone(),
                fail: fail.clone(),
                opened: Arc::new(AtomicBool::new(false)),
            }),
            calls,
            fail,
        )
    }

    #[test]
    fn outer_unwind_revokes_real_retained_descriptions_and_clears_pinned_acl() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let resources = Arc::new(Resources::new(4, 4).unwrap());
        let (ops, calls, _) = fake();
        let id = resources
            .reserve_with(ConnectionId::generate(), device(), ops)
            .unwrap();
        let permit = Permit::new();
        let client = resources.open(id, &permit).unwrap();
        let node = resources.pin(file.path()).unwrap();
        resources
            .apply(node, &BTreeSet::from([55555]), &permit)
            .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = CleanupGuard(resources.clone());
            // Poison the mutex AFTER the actual ACL change, before completion.
            resources
                .apply_then(node, &BTreeSet::from([55556]), &permit, || {
                    panic!("injected post-write panic")
                })
                .unwrap();
        }));
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(resources.pending(), (0, 0));
        assert!(!crate::acl::test_acl_text(file.path()).contains("user:5555"));
        assert!(
            unsafe { libc::fcntl(client.as_raw_fd(), libc::F_GETFD) } >= 0,
            "closing a server socket alone was not our revocation mechanism"
        );
        assert!(
            resources
                .reserve(ConnectionId::generate(), device())
                .is_err()
        );
    }

    #[test]
    fn failed_revocation_retains_original_but_does_not_skip_other_handles_or_acls() {
        let resources = Resources::new(4, 4).unwrap();
        let (ops, calls, fail) = fake();
        fail.store(true, Ordering::Release);
        let id = resources
            .reserve_with(ConnectionId::generate(), device(), ops)
            .unwrap();
        let _client = resources.open(id, &Permit::new()).unwrap();
        let (other, other_calls, _) = fake();
        let other_id = resources
            .reserve_with(ConnectionId::generate(), device(), other)
            .unwrap();
        let _other_client = resources.open(other_id, &Permit::new()).unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        let node = resources.pin(file.path()).unwrap();
        resources
            .apply(node, &BTreeSet::from([55555]), &Permit::new())
            .unwrap();
        assert_eq!(resources.cleanup().len(), 1);
        assert_eq!(resources.pending(), (1, 0));
        assert_eq!(other_calls.load(Ordering::Acquire), 1);
        assert!(!crate::acl::test_acl_text(file.path()).contains("user:55555"));
        fail.store(false, Ordering::Release);
        assert!(resources.cleanup().is_empty());
        assert_eq!(calls.load(Ordering::Acquire), 2);
        assert_eq!(resources.pending(), (0, 0));
    }

    #[test]
    fn primary_claim_survives_failed_close_and_blocks_a_sibling_description() {
        let resources = Resources::new(4, 1).unwrap();
        let (first_ops, _, fail) = fake();
        let mut primary = device();
        primary.kind = DeviceKind::DrmPrimary;
        let first = resources
            .reserve_with(ConnectionId::generate(), primary.clone(), first_ops)
            .unwrap();
        let (second_ops, _, _) = fake();
        let second = resources
            .reserve_with(ConnectionId::generate(), primary, second_ops)
            .unwrap();
        let _client = resources.open(first, &Permit::new()).unwrap();
        assert_eq!(
            resources
                .open(second, &Permit::new())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBUSY)
        );
        fail.store(true, Ordering::Release);
        assert!(resources.close(first).is_err());
        assert!(
            resources.open(first, &Permit::new()).is_err(),
            "retired records cannot reopen"
        );
        assert!(resources.open(second, &Permit::new()).is_err());
        fail.store(false, Ordering::Release);
        resources.close(first).unwrap();
        assert!(resources.open(second, &Permit::new()).is_ok());
        assert!(resources.cleanup().is_empty());
    }

    #[test]
    fn failed_input_revoke_blocks_conflicting_reclassification_by_kernel_number() {
        let resources = Resources::new(2, 1).unwrap();
        let (ops, _, fail) = fake();
        let first = resources
            .reserve_with(ConnectionId::generate(), device(), ops)
            .unwrap();
        let _client = resources.open(first, &Permit::new()).unwrap();
        fail.store(true, Ordering::Release);
        assert!(resources.close(first).is_err());
        let mut reclassified = device();
        reclassified.kind = DeviceKind::Hidraw;
        let (ops, _, _) = fake();
        let successor = resources
            .reserve_with(ConnectionId::generate(), reclassified, ops)
            .unwrap();
        assert_eq!(
            resources
                .open(successor, &Permit::new())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBUSY)
        );
        fail.store(false, Ordering::Release);
        resources.close(first).unwrap();
        assert!(resources.open(successor, &Permit::new()).is_ok());
        assert!(resources.cleanup().is_empty());
    }

    #[test]
    fn a_started_late_open_stays_owned_and_cannot_publish_after_fencing() {
        struct Paused {
            started: std::sync::mpsc::SyncSender<()>,
            release: std::sync::mpsc::Receiver<()>,
            calls: Arc<AtomicUsize>,
        }
        impl DeviceOps for Paused {
            fn open(&mut self, _: &AllowedDevice) -> io::Result<OwnedFd> {
                self.started.send(()).unwrap();
                self.release.recv().unwrap();
                Ok(std::fs::File::open("/dev/null")?.into())
            }
            fn deactivate(&mut self, _: DeviceKind, fd: &OwnedFd) -> io::Result<()> {
                assert!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } >= 0);
                self.calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
            fn activate(&mut self, _: DeviceKind, _: &OwnedFd) -> io::Result<()> {
                Ok(())
            }
        }
        let resources = Arc::new(Resources::new(1, 1).unwrap());
        let (started, entered) = std::sync::mpsc::sync_channel(1);
        let (release, blocked) = std::sync::mpsc::sync_channel(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let id = resources
            .reserve_with(
                ConnectionId::generate(),
                device(),
                Box::new(Paused {
                    started,
                    release: blocked,
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let permit = Permit::new();
        let worker_resources = resources.clone();
        let worker_permit = permit.clone();
        let job = std::thread::spawn(move || worker_resources.open(id, &worker_permit));
        entered.recv().unwrap();
        permit.fence();
        let cleanup_resources = resources.clone();
        let cleanup = std::thread::spawn(move || cleanup_resources.cleanup());
        release.send(()).unwrap();
        assert!(job.join().unwrap().is_err());
        assert!(cleanup.join().unwrap().is_empty());
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(resources.pending(), (0, 0));
    }

    #[test]
    fn fenced_queued_work_cannot_open_or_recreate_a_grant() {
        let resources = Resources::new(1, 1).unwrap();
        let id = resources
            .reserve(ConnectionId::generate(), device())
            .unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        let node = resources.pin(file.path()).unwrap();
        let permit = Permit::new();
        permit.fence();
        assert!(resources.open(id, &permit).is_err());
        assert!(
            resources
                .apply(node, &BTreeSet::from([55555]), &permit)
                .is_err()
        );
        assert!(resources.cleanup().is_empty());
        assert!(!crate::acl::test_acl_text(file.path()).contains("user:55555"));
    }

    #[test]
    fn inode_replacement_cleanup_never_retargets_the_new_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node");
        let old = directory.path().join("old");
        std::fs::write(&path, b"").unwrap();
        let resources = Resources::new(1, 2).unwrap();
        let pinned = resources.pin(&path).unwrap();
        resources
            .apply(pinned, &BTreeSet::from([55555]), &Permit::new())
            .unwrap();
        std::fs::rename(&path, &old).unwrap();
        std::fs::write(&path, b"").unwrap();
        let replacement = PinnedNode::open(&path).unwrap();
        replacement.apply(&BTreeSet::from([55556])).unwrap();
        assert!(resources.cleanup().is_empty());
        assert!(!crate::acl::test_acl_text(&old).contains("user:55555"));
        assert!(crate::acl::test_acl_text(&path).contains("user:55556"));
    }
}
