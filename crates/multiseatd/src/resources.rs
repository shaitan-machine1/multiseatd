//! Outer cleanup ownership for broker descriptions and pinned ACL inodes.
//!
//! Register before starting a mutation. Blocking jobs borrow these retained
//! records; cancellation/unwinding cannot discard the only revocation handle.
//! Actual operations on a kernel device key or ACL inode are serialized. No
//! global index lock is held over an ioctl, xattr operation or await.

use crate::acl::{NodeIdentity, PinnedNode};
use crate::device::AllowedDevice;
#[cfg(test)]
use crate::device::DeviceKind;
#[cfg(any(test, feature = "test-support"))]
use crate::device::DeviceOps;
#[cfg(test)]
use ConnectionKey as ConnectionId;
use dev_broker::resources::Resources as BrokerResources;
pub use dev_broker::{
    permit::Permit,
    resources::{ConnectionKey, HandleId},
};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

struct NodeRecord {
    pinned: PinnedNode,
    retired: bool,
}

pub struct Resources {
    broker: BrokerResources,
    nodes: Mutex<BTreeMap<NodeIdentity, Arc<Mutex<NodeRecord>>>>,
    #[cfg(test)]
    acl_failures: Mutex<BTreeMap<NodeIdentity, usize>>,
    closing: AtomicBool,
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
            broker: BrokerResources::new(device_limit)?,
            nodes: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            acl_failures: Mutex::new(BTreeMap::new()),
            closing: AtomicBool::new(false),
            node_limit,
        })
    }

    pub fn reserve(&self, owner: ConnectionKey, device: AllowedDevice) -> io::Result<HandleId> {
        self.broker.reserve(owner, device)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn reserve_with(
        &self,
        owner: ConnectionKey,
        device: AllowedDevice,
        ops: Box<dyn DeviceOps>,
    ) -> io::Result<HandleId> {
        self.broker.reserve_with(owner, device, ops)
    }

    pub fn open(&self, id: HandleId, permit: &Permit) -> io::Result<OwnedFd> {
        self.broker.open(id, permit)
    }

    pub fn deactivate(&self, id: HandleId) -> io::Result<()> {
        self.broker.deactivate(id)
    }

    pub fn activate(&self, id: HandleId, permit: &Permit) -> io::Result<()> {
        self.broker.activate(id, permit)
    }

    pub fn deactivate_owner(&self, owner: ConnectionKey) -> Vec<io::Error> {
        self.broker.deactivate_owner(owner)
    }

    pub fn activate_owner(&self, owner: ConnectionKey, permit: &Permit) -> Vec<io::Error> {
        self.broker.activate_owner(owner, permit)
    }

    pub fn close_owner(&self, owner: ConnectionKey) -> Vec<io::Error> {
        self.broker.close_owner(owner)
    }

    pub fn owner(&self, id: HandleId) -> io::Result<ConnectionKey> {
        self.broker.owner(id)
    }

    pub fn close(&self, id: HandleId) -> io::Result<()> {
        self.broker.close(id)
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
        self.broker.set_open_hook(hook);
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
        self.broker.fence();
    }

    pub fn pending(&self) -> (usize, usize) {
        (self.broker.pending(), lock(&self.nodes).len())
    }

    /// Independent attempts; one ioctl failure or poisoned record does not skip
    /// ACL cleanup or another description. Started jobs settle under their own
    /// resource locks. Persistent kernel refusal remains owned for retry.
    pub fn cleanup(&self) -> Vec<io::Error> {
        self.fence();
        let nodes: Vec<_> = lock(&self.nodes).keys().copied().collect();
        let mut errors = self.broker.cleanup();
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
