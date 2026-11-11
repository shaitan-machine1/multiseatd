//! Sole loaded assignment, effective admission and finite live-node catalog.
//! The enclosing Seat State lock is its only synchronization boundary.
use dev_acl::{DeviceView, NodeIdentity, NodeSpec, PinnedNode};
use dev_broker::{device::AllowedDevice, permit::Permit};
use seat_udev::SeatName;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const NODE_LIMIT: usize = 4096;
pub const ASSIGNMENT_LIMIT: usize = 8192;

fn classes(scan: &AssignmentScan) -> BTreeMap<AssignmentKey, BTreeSet<AccessClass>> {
    let mut classes: BTreeMap<AssignmentKey, BTreeSet<AccessClass>> = BTreeMap::new();
    for node in &scan.nodes {
        classes
            .entry(node.assignment.clone())
            .or_default()
            .insert(node.class);
    }
    classes
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AssignmentKey(pub String);
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AccessClass {
    Broker,
    Direct,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedNode {
    pub key: String,
    pub assignment: AssignmentKey,
    pub path: PathBuf,
    pub identity: NodeIdentity,
    pub pin: Arc<PinnedNode>,
    pub class: AccessClass,
    /// Synthetic transport-only fixtures never authorize host ACL writes.
    pub acl_managed: bool,
    pub broker: Option<AllowedDevice>,
}
/// Owned, temporary discovery output. Only startup/explicit RPCs load assignments.
#[derive(Default)]
pub struct AssignmentScan {
    pub assignments: BTreeMap<AssignmentKey, SeatName>,
    pub nodes: Vec<ObservedNode>,
}
struct Route {
    desired: SeatName,
    admitted: BTreeSet<AccessClass>,
}
struct LiveNode {
    description: ObservedNode,
    epoch: Permit,
}
pub struct DeviceCatalog {
    seat: SeatName,
    routes: BTreeMap<AssignmentKey, Route>,
    nodes: BTreeMap<String, LiveNode>,
    paths: BTreeMap<PathBuf, String>, // Indexes keys, never copied descriptions.
}
impl DeviceCatalog {
    pub fn new(seat: SeatName) -> Self {
        Self {
            seat,
            routes: BTreeMap::new(),
            nodes: BTreeMap::new(),
            paths: BTreeMap::new(),
        }
    }
    pub fn initialize(&mut self, scan: AssignmentScan) -> io::Result<()> {
        if !self.routes.is_empty() || !self.nodes.is_empty() {
            return Err(io::Error::other("catalog already initialized"));
        }
        self.publish_removals(&scan)?;
        self.publish_additions(scan)
    }
    pub fn view(&self) -> CatalogView<'_> {
        CatalogView(self)
    }
    pub fn admits(&self, assignment: &AssignmentKey, class: AccessClass) -> bool {
        self.routes
            .get(assignment)
            .is_some_and(|route| route.admitted.contains(&class))
    }
    pub fn validate_scan(scan: &AssignmentScan) -> io::Result<()> {
        if scan.nodes.len() > NODE_LIMIT || scan.assignments.len() > ASSIGNMENT_LIMIT {
            return Err(io::Error::other(
                "discovery node/assignment capacity exceeded",
            ));
        }
        let mut keys = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for node in &scan.nodes {
            if !keys.insert(&node.key)
                || !paths.insert(&node.path)
                || !scan.assignments.contains_key(&node.assignment)
                || node.pin.identity() != node.identity
                || (node.class == AccessClass::Broker) != node.broker.is_some()
                || node
                    .broker
                    .as_ref()
                    .is_some_and(|device| device.path != node.path)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "inconsistent discovery scan",
                ));
            }
        }
        Ok(())
    }
    pub fn validate_update(&self, scan: &AssignmentScan) -> io::Result<()> {
        Self::validate_scan(scan)?;
        let new = scan
            .assignments
            .keys()
            .filter(|key| !self.routes.contains_key(*key))
            .count();
        if self.routes.len() + new > ASSIGNMENT_LIMIT {
            return Err(io::Error::other(
                "loaded logical assignment capacity exceeded before effects",
            ));
        }
        Ok(())
    }
    pub fn can_add_node(&self, node: &ObservedNode) -> bool {
        self.nodes.contains_key(&node.key)
            || self.paths.contains_key(&node.path)
            || self.nodes.len() < NODE_LIMIT
    }
    /// Load fresh desired mapping and withdraw only; never adds an admission.
    pub fn publish_removals(&mut self, scan: &AssignmentScan) -> io::Result<()> {
        self.validate_update(scan)?;
        let classes = classes(scan);
        for (key, route) in &mut self.routes {
            // Missing/removed persistent rule means the implicit seat0 default,
            // not forgetting a port just because it currently has no devnode.
            route.desired = scan
                .assignments
                .get(key)
                .cloned()
                .unwrap_or_else(SeatName::seat0);
            if route.desired != self.seat {
                route.admitted.clear();
            }
            if let Some(classes) = classes.get(key) {
                route.admitted.retain(|class| classes.contains(class));
            }
        }
        for (key, desired) in &scan.assignments {
            self.routes.entry(key.clone()).or_insert_with(|| Route {
                desired: desired.clone(),
                admitted: BTreeSet::new(),
            });
        }
        self.replace_live(scan.nodes.clone());
        self.fence_unadmitted();
        Ok(())
    }
    /// Phase two cannot silently perform phase one's old-owner withdrawal.
    pub fn validate_additions(&self, scan: &AssignmentScan) -> io::Result<()> {
        self.validate_update(scan)?;
        let classes = classes(scan);
        for (key, route) in &self.routes {
            let desired = scan
                .assignments
                .get(key)
                .cloned()
                .unwrap_or_else(SeatName::seat0);
            if !route.admitted.is_empty() && desired != self.seat {
                return Err(io::Error::other(
                    "obsolete route requires explicit removal first",
                ));
            }
            if classes
                .get(key)
                .is_some_and(|classes| !route.admitted.is_subset(classes))
            {
                return Err(io::Error::other(
                    "reclassification requires explicit removal first",
                ));
            }
        }
        Ok(())
    }
    pub fn publish_additions(&mut self, scan: AssignmentScan) -> io::Result<()> {
        self.validate_additions(&scan)?;
        let classes = classes(&scan);
        for (key, desired) in &scan.assignments {
            self.routes.entry(key.clone()).or_insert_with(|| Route {
                desired: desired.clone(),
                admitted: BTreeSet::new(),
            });
        }
        // A formerly explicit offline assignment can return to implicit seat0
        // when its rule is removed; no offline devnode cache is necessary.
        for (key, route) in &mut self.routes {
            route.desired = scan
                .assignments
                .get(key)
                .cloned()
                .unwrap_or_else(SeatName::seat0);
            if route.desired == self.seat {
                if let Some(classes) = classes.get(key) {
                    route.admitted.extend(classes);
                } else {
                    route
                        .admitted
                        .extend([AccessClass::Broker, AccessClass::Direct]);
                }
            }
        }
        self.replace_live(scan.nodes);
        for live in self.nodes.values_mut() {
            if self
                .routes
                .get(&live.description.assignment)
                .is_some_and(|route| route.admitted.contains(&live.description.class))
                && !live.epoch.is_open()
            {
                live.epoch = Permit::new();
            }
        }
        self.fence_unadmitted();
        Ok(())
    }
    /// Physical input changes only identity/presence. Observed ID_SEAT is never
    /// an input to this operation; unknown loaded assignments remain denied.
    pub fn device_added(&mut self, node: ObservedNode) {
        assert!(
            self.can_add_node(&node),
            "live catalog capacity must be validated before mutation"
        );
        if let Some(previous) = self.nodes.get(&node.key) {
            if previous.description == node {
                return;
            }
            previous.epoch.fence();
            self.paths.remove(&previous.description.path);
        }
        if let Some(previous_key) = self.paths.get(&node.path).cloned()
            && previous_key != node.key
            && let Some(previous) = self.nodes.remove(&previous_key)
        {
            previous.epoch.fence();
        }
        self.paths.insert(node.path.clone(), node.key.clone());
        self.nodes.insert(
            node.key.clone(),
            LiveNode {
                description: node,
                epoch: Permit::new(),
            },
        );
    }
    pub fn device_removed(&mut self, key: &str, identity: NodeIdentity) -> bool {
        if !self
            .nodes
            .get(key)
            .is_some_and(|node| node.description.identity == identity)
        {
            return false;
        }
        let old = self.nodes.remove(key).expect("matched live node");
        old.epoch.fence();
        self.paths.remove(&old.description.path);
        true
    }
    fn replace_live(&mut self, nodes: Vec<ObservedNode>) {
        let next: BTreeSet<_> = nodes.iter().map(|node| node.key.clone()).collect();
        let removed: Vec<_> = self
            .nodes
            .keys()
            .filter(|key| !next.contains(*key))
            .cloned()
            .collect();
        for key in removed {
            let node = self.nodes.remove(&key).expect("known key");
            node.epoch.fence();
            self.paths.remove(&node.description.path);
        }
        for node in nodes {
            self.device_added(node);
        }
    }
    fn fence_unadmitted(&self) {
        for node in self.nodes.values() {
            if !self.admits(&node.description.assignment, node.description.class) {
                node.epoch.fence();
            }
        }
    }
    pub fn lookup_broker_node(
        &self,
        path: &Path,
        access: &Permit,
    ) -> Option<(AllowedDevice, Permit)> {
        let key = self.paths.get(path)?;
        let live = self.nodes.get(key)?;
        let node = &live.description;
        if !self.admits(&node.assignment, AccessClass::Broker) {
            return None;
        }
        let description = node.broker.as_ref()?;
        let permit = access.gated(live.epoch.gate());
        permit.is_open().then(|| (description.clone(), permit))
    }
    pub fn contains_broker(&self, description: &AllowedDevice) -> bool {
        self.paths
            .get(&description.path)
            .and_then(|key| self.nodes.get(key))
            .is_some_and(|live| {
                live.description.broker.as_ref() == Some(description)
                    && self.admits(&live.description.assignment, AccessClass::Broker)
            })
    }
    /// Owned function-local removal batch, including formerly admitted fresh
    /// nodes. It is discarded after this operation, not a second inventory.
    pub fn removal_batch(&self, scan: &AssignmentScan) -> RemovalBatch {
        let mut nodes: BTreeMap<_, _> = self
            .view()
            .current_nodes()
            .into_iter()
            .map(|node| (node.identity, node))
            .collect();
        for node in &scan.nodes {
            if node.acl_managed
                && (scan.assignments.get(&node.assignment) == Some(&self.seat)
                    || self.admits(&node.assignment, node.class))
            {
                nodes.insert(
                    node.identity,
                    NodeSpec {
                        key: node.key.clone(),
                        path: node.path.clone(),
                        identity: node.identity,
                        pin: node.pin.clone(),
                        admitted: false,
                        grant_eligible: node.class == AccessClass::Direct,
                    },
                );
            }
        }
        RemovalBatch(nodes.into_values().collect())
    }
    pub fn broker_batch(&self) -> BTreeMap<PathBuf, AllowedDevice> {
        self.nodes
            .values()
            .filter(|live| self.admits(&live.description.assignment, AccessClass::Broker))
            .filter_map(|live| {
                live.description
                    .broker
                    .as_ref()
                    .map(|device| (device.path.clone(), device.clone()))
            })
            .collect()
    }
    pub fn live_node(&self, key: &str) -> Option<&ObservedNode> {
        self.nodes.get(key).map(|node| &node.description)
    }
    pub fn contains_node_incarnation(&self, key: &str, identity: NodeIdentity) -> bool {
        self.nodes
            .get(key)
            .is_some_and(|node| node.description.identity == identity)
    }
}
pub struct RemovalBatch(Vec<NodeSpec>);
impl RemovalBatch {
    pub fn settle_admissions(&mut self, catalog: &DeviceCatalog) {
        for node in &mut self.0 {
            node.admitted = catalog.view().contains(node);
        }
    }
}
impl DeviceView for RemovalBatch {
    fn current_nodes(&self) -> Vec<NodeSpec> {
        self.0.clone()
    }
    fn contains(&self, node: &NodeSpec) -> bool {
        self.0.iter().any(|candidate| {
            candidate.identity == node.identity && candidate.admitted && candidate.grant_eligible
        })
    }
}
pub struct CatalogView<'a>(&'a DeviceCatalog);
impl DeviceView for CatalogView<'_> {
    fn current_nodes(&self) -> Vec<NodeSpec> {
        self.0
            .nodes
            .values()
            .filter_map(|live| {
                let node = &live.description;
                if !node.acl_managed {
                    return None;
                }
                let route = self.0.routes.get(&node.assignment)?;
                let admitted = route.admitted.contains(&node.class);
                // An old remembered pin may be cleared after reassignment, but a
                // fresh unremembered node on another seat must never be touched.
                if route.desired != self.0.seat && !admitted {
                    return None;
                }
                Some(NodeSpec {
                    key: node.key.clone(),
                    path: node.path.clone(),
                    identity: node.identity,
                    pin: node.pin.clone(),
                    admitted,
                    grant_eligible: node.class == AccessClass::Direct,
                })
            })
            .collect()
    }
    fn contains(&self, candidate: &NodeSpec) -> bool {
        self.0.nodes.get(&candidate.key).is_some_and(|live| {
            live.description.identity == candidate.identity
                && live.description.class == AccessClass::Direct
                && self
                    .0
                    .admits(&live.description.assignment, AccessClass::Direct)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node(path: &Path) -> ObservedNode {
        ObservedNode {
            key: "node".into(),
            assignment: AssignmentKey("usb-port-4".into()),
            path: path.into(),
            identity: NodeIdentity::observe(path).unwrap(),
            pin: Arc::new(PinnedNode::open(path).unwrap()),
            class: AccessClass::Direct,
            acl_managed: true,
            broker: None,
        }
    }
    fn scan(node: &ObservedNode, seat: &str) -> AssignmentScan {
        AssignmentScan {
            assignments: BTreeMap::from([(
                node.assignment.clone(),
                SeatName::parse(seat).unwrap(),
            )]),
            nodes: vec![node.clone()],
        }
    }
    #[test]
    fn destination_requires_explicit_add_and_hotplug_never_adopts_mapping() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let device = node(file.path());
        let mut catalog = DeviceCatalog::new(SeatName::parse("seat1").unwrap());
        catalog.initialize(scan(&device, "seat0")).unwrap();
        catalog.device_added(device.clone());
        assert!(!catalog.admits(&device.assignment, AccessClass::Direct));
        catalog.publish_removals(&scan(&device, "seat1")).unwrap();
        catalog.device_added(device.clone());
        assert!(!catalog.admits(&device.assignment, AccessClass::Direct));
        assert!(!catalog.view().current_nodes()[0].admitted);
        catalog.publish_additions(scan(&device, "seat1")).unwrap();
        assert!(catalog.admits(&device.assignment, AccessClass::Direct));
    }
    #[test]
    fn absence_preserves_loaded_port_and_old_remove_cannot_erase_replacement() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let old = node(file.path());
        let mut catalog = DeviceCatalog::new(SeatName::seat0());
        catalog.initialize(scan(&old, "seat0")).unwrap();
        assert!(catalog.device_removed(&old.key, old.identity));
        assert!(catalog.admits(&old.assignment, AccessClass::Direct));
        let replacement = tempfile::NamedTempFile::new().unwrap();
        let new = node(replacement.path());
        catalog.device_added(new.clone());
        assert!(!catalog.device_removed(&old.key, old.identity));
        assert!(catalog.contains_node_incarnation(&new.key, new.identity));
    }
    #[test]
    fn seat0_return_cannot_bypass_removal_or_its_exclusion() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let device = node(file.path());
        let mut catalog = DeviceCatalog::new(SeatName::seat0());
        catalog.initialize(scan(&device, "seat0")).unwrap();
        assert!(catalog.publish_additions(scan(&device, "seat1")).is_err());
        catalog.publish_removals(&scan(&device, "seat1")).unwrap();
        assert!(!catalog.admits(&device.assignment, AccessClass::Direct));
        catalog.device_added(device.clone());
        assert!(catalog.view().current_nodes().is_empty());
        catalog.publish_removals(&scan(&device, "seat0")).unwrap();
        assert!(!catalog.admits(&device.assignment, AccessClass::Direct));
        catalog.publish_additions(scan(&device, "seat0")).unwrap();
        assert!(catalog.admits(&device.assignment, AccessClass::Direct));
    }
    #[test]
    fn explicit_add_restores_an_offline_known_port_to_implicit_seat0() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let device = node(file.path());
        let mut catalog = DeviceCatalog::new(SeatName::seat0());
        catalog.initialize(scan(&device, "seat1")).unwrap();
        catalog
            .publish_removals(&AssignmentScan::default())
            .unwrap();
        assert!(!catalog.admits(&device.assignment, AccessClass::Direct));
        catalog
            .publish_additions(AssignmentScan::default())
            .unwrap();
        catalog.device_added(device.clone());
        assert!(catalog.admits(&device.assignment, AccessClass::Direct));
        assert!(catalog.view().current_nodes()[0].admitted);
    }
    #[tokio::test]
    async fn fresh_old_owner_removal_clears_unremembered_acl_without_touching_another_seat() {
        use dev_acl::{AclOps, AclRegistry, LibAcl};
        let file = tempfile::NamedTempFile::new().unwrap();
        let device = node(file.path());
        let mut catalog = DeviceCatalog::new(SeatName::seat0());
        catalog.initialize(scan(&device, "seat0")).unwrap();
        LibAcl
            .set_users(file.path(), &BTreeSet::from([424242]))
            .unwrap();
        let scan = scan(&device, "seat1");
        let mut batch = catalog.removal_batch(&scan);
        catalog.publish_removals(&scan).unwrap();
        batch.settle_admissions(&catalog);
        assert!(catalog.view().current_nodes().is_empty());
        let mut acl = AclRegistry::new(16, Arc::new(tokio::sync::Semaphore::new(1))).unwrap();
        acl.clear_obsolete_device_acls(&batch).await.unwrap();
        assert_eq!(acl.retained(), 0);
        unsafe extern "C" {
            fn acl_get_file(path: *const libc::c_char, kind: libc::c_int) -> *mut libc::c_void;
            fn acl_to_any_text(
                acl: *mut libc::c_void,
                prefix: *const libc::c_char,
                separator: libc::c_char,
                options: libc::c_int,
            ) -> *mut libc::c_char;
            fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
        }
        let path = std::ffi::CString::new(file.path().as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: libacl allocations are checked and freed exactly once.
        unsafe {
            let acl = acl_get_file(path.as_ptr(), 0x8000);
            assert!(!acl.is_null());
            let text = acl_to_any_text(acl, std::ptr::null(), b'\n' as libc::c_char, 0x08);
            assert!(!text.is_null());
            let value = std::ffi::CStr::from_ptr(text)
                .to_string_lossy()
                .into_owned();
            acl_free(text.cast());
            acl_free(acl);
            assert!(!value.contains("user:424242:"));
        }
    }
    #[test]
    fn snapshot_pins_keep_the_original_inode_alive_after_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node");
        std::fs::write(&path, b"old").unwrap();
        let original = node(&path);
        let mut catalog = DeviceCatalog::new(SeatName::seat0());
        catalog.initialize(scan(&original, "seat0")).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"new").unwrap();
        let new = node(&path);
        assert_ne!(original.identity, new.identity);
        assert!(original.pin.is_gone().unwrap());
        catalog.device_added(new.clone());
        assert!(!catalog.device_removed(&original.key, original.identity));
        assert!(catalog.contains_node_incarnation(&new.key, new.identity));
    }
    #[test]
    fn unknown_nodes_and_other_seats_never_enter_acl_candidates() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let device = node(file.path());
        let mut catalog = DeviceCatalog::new(SeatName::seat0());
        catalog.device_added(device);
        assert!(catalog.view().current_nodes().is_empty());
    }
}
