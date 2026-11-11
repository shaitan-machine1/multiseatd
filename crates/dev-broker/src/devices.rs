//! Ordered connection device slots and bounded blocking kernel work.
//!
//! Keys are caller correlation tags, not credentials or context identifiers.
//! The caller supplies access permits and drives completions on its server
//! runtime. Originals remain in Resources through failure, cancellation/unwind.
use crate::connection::Output;
use crate::device::{AllowedDevice, DeviceKind};
use crate::permit::Permit;
use crate::resources::{ConnectionKey, HandleId, Resources};
use crate::seatd::protocol as wire;
use std::collections::BTreeMap;
use std::io;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::task::JoinSet;

struct Slot {
    device: AllowedDevice,
    handle: HandleId,
    references: u32,
    retired: bool,
    closed: bool,
    running: bool,
    waiter: Option<oneshot::Sender<()>>,
    failed: bool,
}
struct Slots {
    owner: ConnectionKey,
    slots: BTreeMap<i32, Slot>,
    next: i32,
    operations: usize,
    protocol_busy: bool,
    cleaning: bool,
}

enum Operation {
    Open {
        slot: i32,
        device: AllowedDevice,
        handle: HandleId,
        fresh: bool,
        result: io::Result<OwnedFd>,
        permit: Permit,
        quota: OwnedSemaphorePermit,
    },
    Close {
        slot: i32,
        result: io::Result<()>,
    },
    Denied(i32),
}
struct Completion<K> {
    connection: K,
    owner: ConnectionKey,
    operation: Operation,
    done: Option<oneshot::Sender<()>>,
}

/// A protocol response, not a public inventory DTO. The owning generation must
/// still match before delivery. Completing a request never implies FD revocation.
pub struct Reply<K> {
    pub connection: K,
    pub owner: ConnectionKey,
    pub output: Option<Output>,
    pub done: Option<oneshot::Sender<()>>,
    pub error: Option<String>,
    pub disconnect: bool,
    pub publication: Option<(i32, Permit)>,
}
impl<K> Reply<K> {
    fn new(connection: K, owner: ConnectionKey, done: Option<oneshot::Sender<()>>) -> Self {
        Self {
            connection,
            owner,
            output: None,
            done,
            error: None,
            disconnect: false,
            publication: None,
        }
    }
    fn bytes(&mut self, bytes: Vec<u8>) {
        self.output = Some(Output {
            permission: None,
            bytes,
            fd: None,
            tag: None,
            quota: None,
        });
    }
}

pub struct Devices<K> {
    connections: BTreeMap<K, Slots>,
    jobs: JoinSet<Completion<K>>,
    resources: Arc<Resources>,
    workers: Arc<Semaphore>,
    descriptors: Arc<Semaphore>,
    limit: usize,
}
impl<K: Copy + Ord + Send + 'static> Devices<K> {
    pub fn new(
        resources: Arc<Resources>,
        workers: Arc<Semaphore>,
        descriptors: Arc<Semaphore>,
        limit: usize,
    ) -> Self {
        assert!(limit > 0);
        Self {
            connections: BTreeMap::new(),
            jobs: JoinSet::new(),
            resources,
            workers,
            descriptors,
            limit,
        }
    }
    pub fn register(&mut self, key: K) -> io::Result<ConnectionKey> {
        if self.connections.contains_key(&key) || self.connections.len() == self.limit {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        let owner = ConnectionKey::generate();
        self.connections.insert(
            key,
            Slots {
                owner,
                slots: BTreeMap::new(),
                next: 1,
                operations: 0,
                protocol_busy: false,
                cleaning: false,
            },
        );
        Ok(owner)
    }
    pub fn owner(&self, key: K) -> Option<ConnectionKey> {
        self.connections.get(&key).map(|slots| slots.owner)
    }
    pub fn has_jobs(&self) -> bool {
        !self.jobs.is_empty()
    }
    pub fn running(&self, key: K) -> bool {
        self.connections
            .get(&key)
            .is_some_and(|slots| slots.operations != 0)
    }
    pub fn pending(&self, key: K) -> bool {
        self.connections.get(&key).is_some_and(|slots| {
            slots.operations != 0
                || slots
                    .slots
                    .values()
                    .any(|slot| slot.retired && !slot.closed)
        })
    }
    pub fn begin_cleanup(&mut self, key: K) {
        if let Some(slots) = self.connections.get_mut(&key) {
            slots.cleaning = true;
        }
    }
    /// Only after the separately retained original-owner cleanup has succeeded.
    pub fn cleaned(&mut self, key: K) {
        let slots = self.connections.get_mut(&key).expect("connection slots");
        assert_eq!(slots.operations, 0);
        slots.slots.clear();
        slots.cleaning = false;
    }
    pub fn forget(&mut self, key: K) -> io::Result<()> {
        if self.connections.get(&key).is_some_and(|slots| {
            slots.operations != 0
                || !slots.slots.is_empty()
                || slots.cleaning
                || self.resources.has_owner(slots.owner)
        }) {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        self.connections.remove(&key);
        Ok(())
    }
    pub fn retire_inputs(&mut self, key: K) {
        if let Some(slots) = self.connections.get_mut(&key) {
            for slot in slots.slots.values_mut() {
                if slot.device.kind != DeviceKind::DrmPrimary {
                    slot.retired = true;
                }
            }
        }
    }
    pub fn retire_outdated(&mut self, next: &BTreeMap<PathBuf, AllowedDevice>) {
        for slots in self.connections.values_mut() {
            for slot in slots.slots.values_mut() {
                if next.get(&slot.device.path) != Some(&slot.device) {
                    slot.retired = true;
                }
            }
        }
    }
    pub fn open(
        &mut self,
        key: K,
        admission: Option<(AllowedDevice, Permit)>,
        start: oneshot::Receiver<()>,
        synthetic: bool,
        done: oneshot::Sender<()>,
    ) -> Option<Reply<K>> {
        let client = self.connections.get(&key).expect("connection slots");
        let mut denied = Reply::new(key, client.owner, Some(done));
        if client.protocol_busy {
            denied.bytes(wire::error(libc::EBUSY));
            return Some(denied);
        }
        let Some((device, permit)) =
            admission.filter(|(_, permit)| permit.is_open() && !client.cleaning)
        else {
            denied.bytes(wire::error(libc::EACCES));
            return Some(denied);
        };
        let Ok(worker) = self.workers.clone().try_acquire_owned() else {
            denied.bytes(wire::error(libc::EAGAIN));
            return Some(denied);
        };
        let Ok(quota) = self.descriptors.clone().try_acquire_owned() else {
            denied.bytes(wire::error(libc::EMFILE));
            return Some(denied);
        };
        let available = client.slots.len() < 128;
        let next = client.next;
        let slots: Vec<_> = client
            .slots
            .iter()
            .filter(|(_, slot)| !slot.retired && !slot.closed)
            .map(|(number, slot)| (*number, slot.device.clone(), slot.handle))
            .collect();
        let owner = client.owner;
        let resources = self.resources.clone();
        let client = self.connections.get_mut(&key).expect("connection slots");
        client.operations += 1;
        client.protocol_busy = true;
        self.jobs.spawn(async move {
            // Registration is already visible to withdrawal. Kernel work may
            // start only after the caller has released its admission guard.
            let started = start.await.is_ok();
            let operation = tokio::task::spawn_blocking(move || {
                let _worker = worker;
                if !started || !permit.is_open() {
                    return Operation::Denied(libc::EACCES);
                }
                let existing = slots.iter().find(|(_, previous, _)| previous == &device);
                let (slot, handle, fresh) = if let Some((slot, _, handle)) = existing {
                    (*slot, *handle, false)
                } else {
                    if !available || next == i32::MAX {
                        return Operation::Denied(libc::EMFILE);
                    }
                    match reserve(&resources, owner, device.clone(), synthetic) {
                        Ok(handle) => (next, handle, true),
                        Err(error) => return Operation::Denied(errno(&error)),
                    }
                };
                let result = resources.open(handle, &permit);
                if result.is_err() && fresh {
                    let _ = resources.close(handle);
                }
                Operation::Open {
                    slot,
                    device,
                    handle,
                    fresh,
                    result,
                    permit,
                    quota,
                }
            })
            .await
            .expect("device worker panicked");
            Completion {
                connection: key,
                owner,
                operation,
                done: denied.done,
            }
        });
        None
    }
    /// Balance an opened result whose FD was never published. Originals remain
    /// owned and are closed by normal retired-slot settlement.
    pub fn unpublished(&mut self, key: K, number: i32) {
        if let Some(slot) = self
            .connections
            .get_mut(&key)
            .and_then(|slots| slots.slots.get_mut(&number))
        {
            slot.references = slot.references.saturating_sub(1);
            if slot.references == 0 {
                slot.retired = true;
            }
        }
    }
    pub fn close(&mut self, key: K, number: i32, done: oneshot::Sender<()>) -> Option<Reply<K>> {
        let client = self.connections.get_mut(&key).expect("connection slots");
        let mut reply = Reply::new(key, client.owner, Some(done));
        if client.protocol_busy || client.cleaning {
            reply.bytes(wire::error(libc::EBUSY));
            return Some(reply);
        }
        let Some(slot) = client.slots.get_mut(&number) else {
            reply.bytes(wire::error(libc::EBADF));
            return Some(reply);
        };
        if slot.references > 1 {
            slot.references -= 1;
            reply.bytes(wire::empty(wire::SERVER_DEVICE_CLOSED));
            return Some(reply);
        }
        if slot.closed {
            client.slots.remove(&number);
            reply.bytes(wire::empty(wire::SERVER_DEVICE_CLOSED));
            return Some(reply);
        }
        slot.references = 0;
        slot.retired = true;
        if slot.running {
            // Join an already-started automatic close instead of scheduling a
            // duplicate which could consume the slot without replying to us.
            slot.waiter = reply.done;
            client.protocol_busy = true;
            return None;
        }
        self.close_slot(key, number, reply.done)
    }
    fn close_slot(
        &mut self,
        key: K,
        number: i32,
        done: Option<oneshot::Sender<()>>,
    ) -> Option<Reply<K>> {
        let client = self.connections.get_mut(&key).expect("connection slots");
        let owner = client.owner;
        let Ok(worker) = self.workers.clone().try_acquire_owned() else {
            if done.is_some() {
                let mut reply = Reply::new(key, owner, done);
                reply.bytes(wire::error(libc::EAGAIN));
                return Some(reply);
            }
            return None;
        };
        let slot = client.slots.get_mut(&number).expect("device slot");
        slot.running = true;
        if done.is_some() {
            client.protocol_busy = true;
        }
        client.operations += 1;
        let handle = slot.handle;
        let resources = self.resources.clone();
        self.jobs.spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let _worker = worker;
                resources.close(handle)
            })
            .await
            .expect("device close worker panicked");
            Completion {
                connection: key,
                owner,
                operation: Operation::Close {
                    slot: number,
                    result,
                },
                done,
            }
        });
        None
    }
    /// Start each retired-slot close once. Failure is reported for fatal handling.
    pub fn settle_retired(&mut self) {
        let pending: Vec<_> = self
            .connections
            .iter()
            .filter(|(_, slots)| !slots.cleaning)
            .flat_map(|(key, slots)| {
                slots
                    .slots
                    .iter()
                    .filter(|(_, slot)| {
                        slot.retired && !slot.closed && !slot.running && !slot.failed
                    })
                    .map(|(number, _)| (*key, *number))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (key, number) in pending {
            self.close_slot(key, number, None);
        }
    }
    pub async fn next_completion(&mut self) -> io::Result<Reply<K>> {
        let completion = self
            .jobs
            .join_next()
            .await
            .expect("device job exists")
            .map_err(io::Error::other)?;
        Ok(self.complete(completion))
    }
    fn complete(&mut self, completion: Completion<K>) -> Reply<K> {
        let mut reply = Reply::new(completion.connection, completion.owner, completion.done);
        let client = self
            .connections
            .get_mut(&reply.connection)
            .expect("unsettled connection retained");
        assert_eq!(client.owner, reply.owner);
        client.operations -= 1;
        match completion.operation {
            Operation::Denied(error) => reply.bytes(wire::error(error)),
            Operation::Open {
                slot,
                device,
                handle,
                fresh,
                result,
                permit,
                quota,
            } => {
                if fresh {
                    client.next += 1;
                    client.slots.insert(
                        slot,
                        Slot {
                            device,
                            handle,
                            references: 0,
                            retired: true,
                            closed: false,
                            running: false,
                            waiter: None,
                            failed: false,
                        },
                    );
                }
                let result = result.and_then(|fd| {
                    if permit.is_open() && !client.cleaning {
                        Ok(fd)
                    } else {
                        Err(io::Error::from_raw_os_error(libc::EACCES))
                    }
                });
                match result {
                    Ok(fd) => {
                        let entry = client.slots.get_mut(&slot).expect("open slot");
                        if let Some(references) = entry.references.checked_add(1) {
                            entry.references = references;
                            entry.retired = false;
                            reply.publication = Some((slot, permit.clone()));
                            reply.output = Some(Output {
                                permission: Some(permit),
                                bytes: wire::device_opened(slot),
                                fd: Some(fd),
                                tag: None,
                                quota: Some(quota),
                            });
                        } else {
                            reply.disconnect = true;
                        }
                    }
                    Err(error) => reply.bytes(wire::error(errno(&error))),
                }
            }
            Operation::Close { slot, result } => {
                if let Some(entry) = client.slots.get_mut(&slot) {
                    entry.running = false;
                    if reply.done.is_none() {
                        reply.done = entry.waiter.take();
                    }
                    match result {
                        Ok(()) => {
                            entry.closed = true;
                            if entry.references == 0 {
                                client.slots.remove(&slot);
                            }
                            if reply.done.is_some() {
                                reply.bytes(wire::empty(wire::SERVER_DEVICE_CLOSED));
                            }
                        }
                        Err(error) => {
                            // The caller must fail-stop; never schedule a
                            // normal-service retry of required withdrawal.
                            entry.failed = true;
                            reply.error = Some(error.to_string());
                            if reply.done.is_some() {
                                reply.bytes(wire::error(errno(&error)));
                            }
                        }
                    }
                }
            }
        }
        if reply.done.is_some() {
            client.protocol_busy = false;
        }
        reply
    }
}
#[cfg(test)]
mod tests;

fn errno(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(libc::EIO)
}
fn reserve(
    resources: &Resources,
    owner: ConnectionKey,
    device: AllowedDevice,
    synthetic: bool,
) -> io::Result<HandleId> {
    if synthetic {
        #[cfg(feature = "test-support")]
        {
            return resources.reserve_with(owner, device, Box::new(crate::device::NullDeviceOps));
        }
        #[cfg(not(feature = "test-support"))]
        {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
    }
    resources.reserve(owner, device)
}
