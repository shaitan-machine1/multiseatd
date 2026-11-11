//! Callable ACL state. The caller owns policy, the State guard, deadlines and runtime.
//! No context, VT, D-Bus, discovery listener, executor or retry scheduler lives here.
mod linux;
pub use linux::{AclOps, ApplyFailure, LibAcl, NodeIdentity, PinnedNode};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeSpec {
    pub key: String,
    pub path: PathBuf,
    pub identity: NodeIdentity,
    /// Discovery pins the incarnation before publishing its description. Owned
    /// worker inputs keep it alive through queues, unlink and inode reuse.
    pub pin: Arc<PinnedNode>,
    pub admitted: bool,
    /// Broker-only nodes are inspected/cleared, never given named grants.
    pub grant_eligible: bool,
}
/// A single borrowed catalog view per operation, not a retained source reference.
pub trait DeviceView {
    fn current_nodes(&self) -> Vec<NodeSpec>;
    fn contains(&self, node: &NodeSpec) -> bool;
}
struct Managed {
    node: NodeSpec,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy)]
pub enum TestFault {
    AfterWriteError,
    AfterWritePanic,
    AfterWriteStall(std::time::Duration),
}

struct NodeJob {
    identity: NodeIdentity,
    task: JoinHandle<io::Result<bool>>,
}
struct ClearBatch {
    identities: BTreeSet<NodeIdentity>,
    task: JoinHandle<Vec<(NodeIdentity, io::Result<bool>)>>,
}
pub struct AclRegistry {
    desired: BTreeSet<u32>,
    managed: BTreeMap<NodeIdentity, Managed>,
    uncertain: BTreeMap<NodeIdentity, Arc<PinnedNode>>,
    applying: Option<NodeJob>,
    finalizing: Option<ClearBatch>,
    workers: Arc<Semaphore>,
    limit: usize,
    stopping: bool,
    epoch: Arc<AtomicBool>,
    lifetime: Arc<dyn Fn() -> bool + Send + Sync>,
    #[cfg(feature = "test-support")]
    fault: Option<TestFault>,
}
impl AclRegistry {
    pub fn new(limit: usize, workers: Arc<Semaphore>) -> io::Result<Self> {
        if limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero ACL pin limit",
            ));
        }
        Ok(Self {
            desired: BTreeSet::new(),
            managed: BTreeMap::new(),
            uncertain: BTreeMap::new(),
            applying: None,
            finalizing: None,
            workers,
            limit,
            stopping: false,
            epoch: Arc::new(AtomicBool::new(true)),
            lifetime: Arc::new(|| true),
            #[cfg(feature = "test-support")]
            fault: None,
        })
    }
    #[cfg(feature = "test-support")]
    pub fn inject_fault(&mut self, fault: TestFault) {
        self.fault = Some(fault);
    }
    fn next_epoch(&mut self) {
        self.epoch.store(false, Ordering::Release);
        self.epoch = Arc::new(AtomicBool::new(true));
    }
    /// Opaque irreversible access/lifetime predicate; no context policy is known.
    pub fn set_lifetime(&mut self, check: impl Fn() -> bool + Send + Sync + 'static) {
        self.next_epoch();
        self.lifetime = Arc::new(check);
    }
    pub fn desired_users(&self) -> &BTreeSet<u32> {
        &self.desired
    }
    pub fn retained(&self) -> usize {
        self.managed.len()
            + self
                .uncertain
                .keys()
                .filter(|id| !self.managed.contains_key(id))
                .count()
    }
    pub fn has_started_work(&self) -> bool {
        self.applying.is_some() || self.finalizing.is_some()
    }
    pub fn add_acl_grant(&mut self, uid: u32) -> io::Result<()> {
        if self.stopping {
            return Err(stopped());
        }
        if uid == u32::MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid UID"));
        }
        if self.desired.len() == 64 && !self.desired.contains(&uid) {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "UID limit"));
        }
        if self.desired.insert(uid) {
            self.next_epoch();
        }
        Ok(())
    }
    pub fn remove_acl_grant(&mut self, uid: u32) {
        if self.desired.remove(&uid) {
            self.next_epoch();
        }
    }
    pub async fn clear_obsolete_device_acls(&mut self, view: &impl DeviceView) -> io::Result<()> {
        let obsolete: Vec<_> = self
            .managed
            .iter()
            .filter(|(_, row)| !view.contains(&row.node))
            .map(|(id, _)| *id)
            .collect();
        let nodes = view.current_nodes();
        for identity in obsolete {
            self.clear_device_acl(identity).await?;
        }
        // Scan coverage is independent of remembered successful pins.
        for node in nodes {
            let users = if node.admitted && node.grant_eligible {
                self.desired.clone()
            } else {
                BTreeSet::new()
            };
            self.apply_node(node, users, true).await?;
        }
        Ok(())
    }
    pub async fn refresh_device_acls(&mut self, view: &impl DeviceView) -> io::Result<()> {
        let nodes = view.current_nodes();
        for node in nodes.into_iter().filter(|node| node.admitted) {
            let users = if node.grant_eligible {
                self.desired.clone()
            } else {
                BTreeSet::new()
            };
            self.apply_node(node, users, false).await?;
        }
        Ok(())
    }
    pub async fn refresh_device_acl(
        &mut self,
        view: &impl DeviceView,
        key: &str,
    ) -> io::Result<()> {
        let node = view
            .current_nodes()
            .into_iter()
            .find(|node| node.key == key && node.admitted);
        if let Some(node) = node {
            let users = if node.grant_eligible {
                self.desired.clone()
            } else {
                BTreeSet::new()
            };
            self.apply_node(node, users, false).await?;
        }
        Ok(())
    }
    async fn quota(&self) -> io::Result<OwnedSemaphorePermit> {
        self.workers
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| stopped())
    }
    async fn apply_node(
        &mut self,
        node: NodeSpec,
        users: BTreeSet<u32>,
        removal_only: bool,
    ) -> io::Result<()> {
        if self.stopping && !users.is_empty() {
            return Err(stopped());
        }
        if self.has_started_work() {
            return Err(io::Error::other(
                "unsettled ACL job; fatal cleanup required",
            ));
        }
        if self.retained() == self.limit && !self.managed.contains_key(&node.identity) {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "ACL pin limit"));
        }
        let pin = node.pin.clone();
        if pin.identity() != node.identity {
            return Ok(());
        }
        // Never reopen a path here: that could write a same-number replacement
        // after the original inode was recycled while this work was queued.
        // This distinct ownership exists BEFORE any worker can write.
        self.uncertain.insert(node.identity, pin.clone());
        let quota = self.quota().await?;
        let empty = users.is_empty();
        let epoch = self.epoch.clone();
        let lifetime = self.lifetime.clone();
        let worker_epoch = epoch.clone();
        let worker_lifetime = lifetime.clone();
        let worker_pin = pin.clone();
        #[cfg(feature = "test-support")]
        let fault = self.fault;
        self.applying = Some(NodeJob {
            identity: node.identity,
            task: tokio::task::spawn_blocking(move || {
                let _quota = quota;
                let allowed = || worker_epoch.load(Ordering::Acquire) && worker_lifetime();
                let target = if users.is_empty() || allowed() {
                    &users
                } else {
                    &BTreeSet::new()
                };
                let applied = apply(&worker_pin, target, removal_only)?;
                #[cfg(feature = "test-support")]
                if applied && !target.is_empty() {
                    match fault {
                        Some(TestFault::AfterWriteError) => {
                            return Err(io::Error::from_raw_os_error(libc::EIO));
                        }
                        Some(TestFault::AfterWritePanic) => {
                            panic!("injected panic after actual ACL write")
                        }
                        Some(TestFault::AfterWriteStall(delay)) => std::thread::sleep(delay),
                        None => {}
                    }
                }
                if !users.is_empty() && (!allowed() || target.is_empty()) {
                    // A queued grant never resurrects a dead period. A syscall
                    // already started is joined, then compensated on this same pin.
                    apply(&worker_pin, &BTreeSet::new(), false)?;
                    return Ok(false);
                }
                Ok(applied)
            }),
        });
        let result = (&mut self.applying.as_mut().expect("retained apply job").task).await;
        self.applying.take();
        let applied = result.map_err(io::Error::other)??;
        if applied && !empty && (!epoch.load(Ordering::Acquire) || !lifetime()) {
            self.clear_device_acl(node.identity).await?;
            return Ok(());
        }
        self.uncertain.remove(&node.identity);
        if applied && !empty {
            self.managed.insert(node.identity, Managed { node });
        } else {
            self.managed.remove(&node.identity);
        }
        Ok(())
    }
    pub async fn clear_device_acl(&mut self, identity: NodeIdentity) -> io::Result<()> {
        let pin = self
            .managed
            .get(&identity)
            .map(|row| row.node.pin.clone())
            .or_else(|| self.uncertain.get(&identity).cloned());
        let Some(pin) = pin else { return Ok(()) };
        if self.has_started_work() {
            return Err(io::Error::other("ACL worker still active"));
        }
        self.uncertain.insert(identity, pin.clone());
        let quota = self.quota().await?;
        self.applying = Some(NodeJob {
            identity,
            task: tokio::task::spawn_blocking(move || {
                let _quota = quota;
                apply(&pin, &BTreeSet::new(), false)
            }),
        });
        let result = (&mut self.applying.as_mut().expect("retained clear job").task).await;
        self.applying.take();
        result.map_err(io::Error::other)??;
        self.managed.remove(&identity);
        self.uncertain.remove(&identity);
        Ok(())
    }
    /// Best effort after fencing. The caller imposes an independent finite bound.
    /// Actual jobs/pins remain here if that bound expires; no future-drop fiction.
    pub async fn shutdown(&mut self) -> Vec<io::Error> {
        self.stopping = true;
        self.epoch.store(false, Ordering::Release);
        self.desired.clear();
        let mut errors = Vec::new();
        // Function-local remaining inputs, not a reconciliation/retry journal.
        // The one retained cleanup batch uses reserved caller blocking capacity,
        // not a regular-worker semaphore potentially held by the stalled write.
        let mut remaining: BTreeSet<_> = self
            .managed
            .keys()
            .chain(self.uncertain.keys())
            .copied()
            .collect();
        if let Some(batch) = &self.finalizing {
            remaining.retain(|id| !batch.identities.contains(id));
        }
        loop {
            if self.finalizing.is_none() {
                let running = self.applying.as_ref().map(|job| job.identity);
                let identities: BTreeSet<_> = remaining
                    .iter()
                    .filter(|id| Some(**id) != running)
                    .copied()
                    .take(32)
                    .collect();
                if !identities.is_empty() {
                    let pins: Vec<_> = identities
                        .iter()
                        .filter_map(|id| {
                            self.managed
                                .get(id)
                                .map(|row| row.node.pin.clone())
                                .or_else(|| self.uncertain.get(id).cloned())
                                .map(|pin| (*id, pin))
                        })
                        .collect();
                    for id in &identities {
                        remaining.remove(id);
                    }
                    self.finalizing = Some(ClearBatch {
                        identities,
                        task: tokio::task::spawn_blocking(move || {
                            pins.into_iter()
                                .map(|(id, pin)| (id, apply(&pin, &BTreeSet::new(), false)))
                                .collect()
                        }),
                    });
                }
            }
            if !self.has_started_work() {
                break;
            }
            tokio::select! {
                result=async {(&mut self.applying.as_mut().expect("retained original").task).await}, if self.applying.is_some() => {
                    self.applying.take();
                    match result {Ok(Ok(_))=>(),Ok(Err(error))=>errors.push(error),Err(error)=>errors.push(io::Error::other(error))}
                    // Its original pin remains in remaining until actual join;
                    // only now can a final clear touch that same incarnation.
                }
                result=async {(&mut self.finalizing.as_mut().expect("retained cleanup batch").task).await}, if self.finalizing.is_some() => {
                    self.finalizing.take();
                    match result {
                        Ok(results)=>for (id,result) in results {
                            match result {Ok(_)=>{self.managed.remove(&id);self.uncertain.remove(&id);},Err(error)=>errors.push(error)}
                        },
                        Err(error)=>errors.push(io::Error::other(error)),
                    }
                }
            }
        }
        errors
    }
}
fn apply(pin: &PinnedNode, users: &BTreeSet<u32>, removal_only: bool) -> io::Result<bool> {
    if pin.is_gone()? {
        return Ok(false);
    }
    let result = if removal_only {
        pin.retain_users(users)
    } else {
        pin.apply(users)
    };
    match result {
        Ok(()) => Ok(!pin.is_gone()?),
        Err(_) if pin.is_gone().unwrap_or(false) => Ok(false),
        Err(error) => Err(error),
    }
}
fn stopped() -> io::Error {
    io::Error::from_raw_os_error(libc::ESHUTDOWN)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct View(Vec<NodeSpec>);
    impl DeviceView for View {
        fn current_nodes(&self) -> Vec<NodeSpec> {
            self.0.clone()
        }
        fn contains(&self, node: &NodeSpec) -> bool {
            self.0.iter().any(|n| {
                n.admitted && n.grant_eligible && n.key == node.key && n.identity == node.identity
            })
        }
    }
    fn view(path: &std::path::Path, admitted: bool, grant_eligible: bool) -> View {
        View(vec![NodeSpec {
            key: "fixture".into(),
            path: path.into(),
            identity: NodeIdentity::observe(path).unwrap(),
            pin: Arc::new(PinnedNode::open(path).unwrap()),
            admitted,
            grant_eligible,
        }])
    }
    fn registry() -> AclRegistry {
        AclRegistry::new(16, Arc::new(Semaphore::new(1))).unwrap()
    }
    #[tokio::test]
    async fn fresh_removal_clears_unknown_named_entries_without_adding_grants() {
        let file = tempfile::NamedTempFile::new().unwrap();
        LibAcl
            .set_users(file.path(), &BTreeSet::from([424242]))
            .unwrap();
        let mut acl = registry();
        acl.add_acl_grant(424243).unwrap();
        acl.clear_obsolete_device_acls(&view(file.path(), false, true))
            .await
            .unwrap();
        assert!(!linux::test_acl_text(file.path()).contains("user:42424"));
        assert_eq!(acl.retained(), 0);
        acl.refresh_device_acls(&view(file.path(), true, true))
            .await
            .unwrap();
        assert!(linux::test_acl_text(file.path()).contains("user:424243:rw-"));
        assert_eq!(acl.managed.len(), 1);
        assert!(acl.shutdown().await.is_empty());
        assert!(!linux::test_acl_text(file.path()).contains("user:424243:"));
    }
    #[tokio::test]
    async fn broker_nodes_get_empty_targets_even_with_current_users() {
        let file = tempfile::NamedTempFile::new().unwrap();
        LibAcl
            .set_users(file.path(), &BTreeSet::from([424242]))
            .unwrap();
        let mut acl = registry();
        acl.add_acl_grant(424243).unwrap();
        acl.refresh_device_acls(&view(file.path(), true, false))
            .await
            .unwrap();
        assert!(!linux::test_acl_text(file.path()).contains("user:42424"));
    }
    #[tokio::test]
    async fn old_pin_cleanup_never_targets_a_same_path_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node");
        std::fs::write(&path, b"").unwrap();
        let mut acl = registry();
        acl.add_acl_grant(424242).unwrap();
        acl.refresh_device_acls(&view(&path, true, true))
            .await
            .unwrap();
        let old = dir.path().join("old");
        std::fs::rename(&path, &old).unwrap();
        std::fs::write(&path, b"").unwrap();
        LibAcl.set_users(&path, &BTreeSet::from([424243])).unwrap();
        acl.clear_obsolete_device_acls(&View(vec![])).await.unwrap();
        assert!(!linux::test_acl_text(&old).contains("user:424242:"));
        assert!(linux::test_acl_text(&path).contains("user:424243:"));
    }
    #[tokio::test]
    async fn a_queued_grant_cannot_resurrect_a_closed_lifetime() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let view = view(file.path(), true, true);
        let workers = Arc::new(Semaphore::new(1));
        let mut acl = AclRegistry::new(16, workers.clone()).unwrap();
        let alive = Arc::new(AtomicBool::new(true));
        let check = alive.clone();
        acl.set_lifetime(move || check.load(Ordering::Acquire));
        acl.add_acl_grant(424242).unwrap();
        let quota = workers.acquire().await.unwrap();
        let mut pending = Box::pin(acl.refresh_device_acls(&view));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), pending.as_mut())
                .await
                .is_err()
        );
        alive.store(false, Ordering::Release);
        drop(quota);
        pending.await.unwrap();
        assert_eq!(acl.retained(), 0);
        assert!(!linux::test_acl_text(file.path()).contains("user:424242:"));
    }
    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn a_started_real_write_is_joined_and_compensated_on_lifetime_loss() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let view = view(file.path(), true, true);
        let mut acl = registry();
        let alive = Arc::new(AtomicBool::new(true));
        let check = alive.clone();
        acl.set_lifetime(move || check.load(Ordering::Acquire));
        acl.add_acl_grant(424242).unwrap();
        acl.inject_fault(TestFault::AfterWriteStall(
            std::time::Duration::from_millis(200),
        ));
        let mut pending = Box::pin(acl.refresh_device_acls(&view));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), pending.as_mut())
                .await
                .is_err()
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !linux::test_acl_text(file.path()).contains("user:424242:") {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        alive.store(false, Ordering::Release);
        pending.await.unwrap();
        assert_eq!(acl.retained(), 0);
        assert!(!linux::test_acl_text(file.path()).contains("user:424242:"));
    }
    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn fatal_cleanup_clears_independent_pins_before_stalled_original_settles() {
        let first = tempfile::NamedTempFile::new().unwrap();
        let second = tempfile::NamedTempFile::new().unwrap();
        let a = view(first.path(), true, true);
        let b = view(second.path(), true, true);
        let mut acl = registry();
        acl.add_acl_grant(424242).unwrap();
        acl.refresh_device_acls(&a).await.unwrap();
        acl.refresh_device_acls(&b).await.unwrap();
        acl.add_acl_grant(424243).unwrap();
        acl.inject_fault(TestFault::AfterWriteStall(
            std::time::Duration::from_millis(500),
        ));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                acl.refresh_device_acls(&a)
            )
            .await
            .is_err()
        );
        let mut cleanup = Box::pin(acl.shutdown());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), cleanup.as_mut())
                .await
                .is_err()
        );
        assert!(
            !linux::test_acl_text(second.path()).contains("user:424242:"),
            "independent cleanup queued behind the original"
        );
        assert!(cleanup.await.is_empty());
        assert_eq!(acl.retained(), 0);
        assert!(!acl.has_started_work());
        assert!(!linux::test_acl_text(first.path()).contains("user:424242:"));
    }
    #[tokio::test]
    async fn obsolete_identity_is_skipped_not_recorded_as_success() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let stale = view(file.path(), true, true);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replacement");
        std::fs::write(&path, b"").unwrap();
        let mut node = stale.0[0].clone();
        node.pin = Arc::new(PinnedNode::open(&path).unwrap());
        node.path = path;
        let mut acl = registry();
        acl.add_acl_grant(424242).unwrap();
        acl.refresh_device_acls(&View(vec![node])).await.unwrap();
        assert_eq!(acl.retained(), 0);
    }
    #[tokio::test]
    async fn expired_queue_wait_keeps_pin_owned_for_fatal_cleanup() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let workers = Arc::new(Semaphore::new(1));
        let mut acl = AclRegistry::new(4, workers.clone()).unwrap();
        acl.add_acl_grant(424242).unwrap();
        let quota = workers.acquire().await.unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            acl.refresh_device_acls(&view(file.path(), true, true)),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(acl.managed.len(), 0);
        drop(quota);
        assert!(acl.shutdown().await.is_empty());
    }
}
