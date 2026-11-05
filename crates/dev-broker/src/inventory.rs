//! Sole mutable broker authorization inventory. Discovery/classification belongs
//! to the caller. Immutable job descriptions retain their node epoch so removing
//! or replacing an entry also fences already-admitted, not-yet-started opens.
use crate::device::{AllowedDevice, DeviceId};
use crate::permit::Permit;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

struct Authorization {
    device: AllowedDevice,
    epoch: Permit,
}

#[derive(Default)]
pub struct Inventory {
    devices: BTreeMap<PathBuf, Authorization>,
}

impl Inventory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish an already-validated device after the caller's required old
    /// resource barrier. This changes authorization, not ownership of retained
    /// kernel descriptions; removal alone never certifies completed cleanup.
    pub fn add_device(&mut self, device: AllowedDevice) {
        if self
            .devices
            .get(&device.path)
            .is_some_and(|entry| entry.device == device)
        {
            return;
        }
        self.remove_device(&device.id);
        if let Some(old) = self.devices.remove(&device.path) {
            old.epoch.fence();
        }
        self.devices.insert(
            device.path.clone(),
            Authorization {
                device,
                epoch: Permit::new(),
            },
        );
    }

    pub fn remove_device(&mut self, id: &DeviceId) {
        self.devices.retain(|_, entry| {
            if &entry.device.id == id {
                entry.epoch.fence();
                false
            } else {
                true
            }
        });
    }

    /// Snapshot publication used after a settled local topology barrier. Keep
    /// identical node epochs, fence removed/replaced nodes, never infer policy.
    pub fn replace(&mut self, devices: impl IntoIterator<Item = AllowedDevice>) {
        let next: BTreeMap<_, _> = devices
            .into_iter()
            .map(|device| (device.path.clone(), device))
            .collect();
        self.devices.retain(|path, entry| {
            if next.get(path) == Some(&entry.device) {
                true
            } else {
                entry.epoch.fence();
                false
            }
        });
        for device in next.into_values() {
            self.add_device(device);
        }
    }

    /// Resolve only a published exact path, never canonicalize a client path or
    /// walk caller-chosen filesystem components. The combined epoch is checked
    /// again by the retained resource owner immediately before/after kernel I/O.
    pub fn authorize(&self, path: &Path, access: &Permit) -> Option<(AllowedDevice, Permit)> {
        let entry = self.devices.get(path)?;
        let permit = access.gated(entry.epoch.gate());
        permit.is_open().then(|| (entry.device.clone(), permit))
    }

    pub fn contains(&self, id: &DeviceId) -> bool {
        self.devices.values().any(|entry| &entry.device.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceKind;
    use std::os::unix::fs::MetadataExt;

    fn device() -> AllowedDevice {
        AllowedDevice::canonicalized(
            DeviceId::new("/sys/devices/test"),
            "/dev/null",
            std::fs::metadata("/dev/null").unwrap().rdev(),
            DeviceKind::Evdev,
        )
        .unwrap()
    }

    #[test]
    fn removal_and_replacement_fence_old_jobs_without_reclassifying_devices() {
        let original = device();
        let mut inventory = Inventory::new();
        inventory.add_device(original.clone());
        let access = Permit::new();
        let (_, old) = inventory.authorize(&original.path, &access).unwrap();
        inventory.add_device(original.clone());
        assert!(old.is_open(), "duplicate publication must be idempotent");
        let mut replacement = original.clone();
        replacement.id = DeviceId::new("/sys/devices/replacement");
        inventory.add_device(replacement.clone());
        assert!(!old.is_open());
        assert!(!inventory.contains(&original.id));
        let (_, current) = inventory.authorize(&replacement.path, &access).unwrap();
        inventory.remove_device(&original.id);
        assert!(current.is_open(), "stale removal cannot remove another ID");
        inventory.remove_device(&replacement.id);
        assert!(!current.is_open());
        assert!(inventory.authorize(&replacement.path, &access).is_none());
    }

    #[test]
    fn one_device_id_cannot_keep_its_old_path_authorized() {
        let original = device();
        let mut inventory = Inventory::new();
        inventory.add_device(original.clone());
        let access = Permit::new();
        let (_, old) = inventory.authorize(&original.path, &access).unwrap();
        let renamed = AllowedDevice::canonicalized(
            original.id.clone(),
            "/dev/zero",
            std::fs::metadata("/dev/zero").unwrap().rdev(),
            DeviceKind::Evdev,
        )
        .unwrap();
        inventory.add_device(renamed.clone());
        assert!(!old.is_open());
        assert!(inventory.authorize(&original.path, &access).is_none());
        assert!(inventory.authorize(&renamed.path, &access).is_some());
    }

    #[test]
    fn snapshot_replacement_preserves_identical_epochs_and_never_walks_request_paths() {
        let device = device();
        let mut inventory = Inventory::new();
        inventory.replace([device.clone()]);
        let access = Permit::new();
        let (_, permit) = inventory.authorize(&device.path, &access).unwrap();
        assert!(
            inventory
                .authorize(Path::new("/dev/../dev/null"), &access)
                .is_none()
        );
        inventory.replace([device.clone()]);
        assert!(permit.is_open());
        inventory.replace([]);
        assert!(!permit.is_open());
        inventory.replace([device.clone()]);
        assert!(
            !permit.is_open(),
            "new publication must not reopen an old epoch"
        );
        access.fence();
        assert!(inventory.authorize(&device.path, &access).is_none());
    }
}
