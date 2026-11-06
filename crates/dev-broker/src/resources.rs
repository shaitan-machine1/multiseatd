//! Retained broker descriptions and physical-key serialization. No context,
//! UID, ACL, udev or D-Bus policy lives here. Register before starting an open;
//! outer ownership survives waiter cancellation, logical removal and unwinding.
use crate::device::{AllowedDevice, DeviceId, DeviceKind, DeviceOps, KernelDeviceOps};
use crate::permit::Permit;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// Internal connection incarnation, never a credential or public FD handle.
/// Exhaustion fails rather than recycling a key while late work may exist.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionKey(u64);

impl ConnectionKey {
    pub fn generate() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let mut value = NEXT.load(Ordering::Relaxed);
        loop {
            let next = value
                .checked_add(1)
                .expect("broker connection incarnation exhaustion");
            match NEXT.compare_exchange_weak(value, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Self(value),
                Err(current) => value = current,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HandleId(u64);

type DeviceRecords = BTreeMap<HandleId, RetainedDevice>;
type CardKeys = BTreeMap<u64, Arc<Mutex<KeyState>>>;

// Immutable ownership/identity stays queryable while a driver holds the mutable
// record lock. Both references share one descriptor, not mirrored inventories.
struct RetainedDevice {
    owner: ConnectionKey,
    device: Arc<AllowedDevice>,
    record: Arc<Mutex<DeviceRecord>>,
}

#[derive(Default)]
struct KeyState {
    master: Option<HandleId>,
    blocked: BTreeSet<HandleId>,
}

struct DeviceRecord {
    device: Arc<AllowedDevice>,
    key: Arc<Mutex<KeyState>>,
    fd: Option<OwnedFd>,
    active: bool,
    retired: bool,
    ops: Box<dyn DeviceOps>,
}

impl DeviceRecord {
    fn resume(&mut self) -> io::Result<()> {
        let fd = self.fd.as_ref().ok_or_else(stopped)?;
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
        if let Err(error) = attempt(|| self.revoke()) {
            tracing::error!(%error, "final brokered description revocation failed");
        }
    }
}

pub struct Resources {
    devices: Mutex<DeviceRecords>,
    keys: Mutex<CardKeys>,
    #[cfg(feature = "test-support")]
    open_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    closing: AtomicBool,
    next: AtomicU64,
    limit: usize,
}

impl Resources {
    pub fn new(limit: usize) -> io::Result<Self> {
        if limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero broker resource limit",
            ));
        }
        Ok(Self {
            devices: Mutex::new(BTreeMap::new()),
            keys: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "test-support")]
            open_hook: Mutex::new(None),
            closing: AtomicBool::new(false),
            next: AtomicU64::new(1),
            limit,
        })
    }

    pub fn reserve(&self, owner: ConnectionKey, device: AllowedDevice) -> io::Result<HandleId> {
        self.reserve_with(owner, device, Box::<KernelDeviceOps>::default())
    }

    pub fn reserve_with(
        &self,
        owner: ConnectionKey,
        device: AllowedDevice,
        ops: Box<dyn DeviceOps>,
    ) -> io::Result<HandleId> {
        let mut records = lock(&self.devices);
        if self.closing.load(Ordering::Acquire) {
            return Err(stopped());
        }
        if records.len() == self.limit {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "broker handle limit reached",
            ));
        }
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
        let device = Arc::new(device);
        records.insert(
            id,
            RetainedDevice {
                owner,
                device: device.clone(),
                record: Arc::new(Mutex::new(DeviceRecord {
                    device,
                    key,
                    fd: None,
                    active: false,
                    retired: false,
                    ops,
                })),
            },
        );
        Ok(id)
    }

    fn record(&self, id: HandleId) -> io::Result<Arc<Mutex<DeviceRecord>>> {
        lock(&self.devices)
            .get(&id)
            .map(|entry| entry.record.clone())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
    }

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
            #[cfg(feature = "test-support")]
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
        if self.closing.load(Ordering::Acquire) || !permit.is_open() {
            return Err(stopped());
        }
        record.fd.as_ref().expect("opened description").try_clone()
    }

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

    fn owner_records(&self, owner: ConnectionKey) -> Vec<HandleId> {
        lock(&self.devices)
            .iter()
            .filter_map(|(id, entry)| (entry.owner == owner).then_some(*id))
            .collect()
    }

    pub fn deactivate_owner(&self, owner: ConnectionKey) -> Vec<io::Error> {
        self.owner_records(owner)
            .into_iter()
            .filter_map(|id| self.deactivate(id).err())
            .collect()
    }

    pub fn activate_owner(&self, owner: ConnectionKey, permit: &Permit) -> Vec<io::Error> {
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

    pub fn close_owner(&self, owner: ConnectionKey) -> Vec<io::Error> {
        self.owner_records(owner)
            .into_iter()
            .filter_map(|id| self.close(id).err())
            .collect()
    }

    /// Immutable ownership remains queryable even while a driver is blocked.
    pub fn has_owner(&self, owner: ConnectionKey) -> bool {
        lock(&self.devices)
            .values()
            .any(|entry| entry.owner == owner)
    }

    pub fn owner(&self, id: HandleId) -> io::Result<ConnectionKey> {
        lock(&self.devices)
            .get(&id)
            .map(|entry| entry.owner)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
    }

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
        lock(&self.keys).retain(|_, key| Arc::strong_count(key) > 1);
        Ok(())
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn set_open_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *lock(&self.open_hook) = hook;
    }

    pub fn fence(&self) {
        self.closing.store(true, Ordering::Release);
    }
    pub fn pending(&self) -> usize {
        lock(&self.devices).len()
    }

    /// Retained records, including started opens/failed cleanup. This is one
    /// component of a caller's disownership barrier, not a transfer token.
    pub fn pending_device(&self, id: &DeviceId) -> bool {
        lock(&self.devices)
            .values()
            .any(|entry| &entry.device.id == id)
    }

    pub fn cleanup(&self) -> Vec<io::Error> {
        self.fence();
        let devices: Vec<_> = lock(&self.devices).keys().copied().collect();
        devices
            .into_iter()
            .filter_map(|id| attempt(|| self.close(id)).err())
            .collect()
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
    use std::os::unix::fs::MetadataExt;
    use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
    use std::time::Duration;

    struct Paused {
        started: SyncSender<()>,
        release: Receiver<()>,
    }
    impl DeviceOps for Paused {
        fn open(&mut self, _: &AllowedDevice) -> io::Result<OwnedFd> {
            self.started.send(()).unwrap();
            self.release.recv().unwrap();
            Ok(std::fs::File::open("/dev/null")?.into())
        }
        fn deactivate(&mut self, _: DeviceKind, _: &OwnedFd) -> io::Result<()> {
            Ok(())
        }
        fn activate(&mut self, _: DeviceKind, _: &OwnedFd) -> io::Result<()> {
            Ok(())
        }
    }

    fn device(path: &str) -> AllowedDevice {
        AllowedDevice::canonicalized(
            DeviceId::new(path),
            path,
            std::fs::metadata(path).unwrap().rdev(),
            DeviceKind::Evdev,
        )
        .unwrap()
    }

    #[test]
    fn a_started_open_does_not_block_other_owner_or_identity_queries() {
        let resources = Arc::new(Resources::new(2).unwrap());
        let first = ConnectionKey::generate();
        let other = ConnectionKey::generate();
        assert_ne!(first, other);
        let (started, entered) = sync_channel(1);
        let (release, blocked) = sync_channel(1);
        let id = resources
            .reserve_with(
                first,
                device("/dev/null"),
                Box::new(Paused {
                    started,
                    release: blocked,
                }),
            )
            .unwrap();
        let second = resources.reserve(other, device("/dev/zero")).unwrap();
        let worker_resources = resources.clone();
        let worker = std::thread::spawn(move || worker_resources.open(id, &Permit::new()));
        entered.recv().unwrap();
        let (sent, received) = sync_channel(1);
        let query_resources = resources.clone();
        let query = std::thread::spawn(move || {
            assert_eq!(query_resources.owner(second).unwrap(), other);
            assert!(query_resources.pending_device(&DeviceId::new("/dev/null")));
            assert!(query_resources.close_owner(other).is_empty());
            sent.send(()).unwrap();
        });
        let result = received.recv_timeout(Duration::from_secs(1));
        // Always release/join on regression as well; never strand a test worker.
        release.send(()).unwrap();
        worker.join().unwrap().unwrap();
        query.join().unwrap();
        assert!(
            result.is_ok(),
            "unrelated metadata/cleanup waited for the blocked device"
        );
        assert!(resources.cleanup().is_empty());
    }
}
