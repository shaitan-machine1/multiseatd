//! Ordered per-transport device operations; originals live in Resources.
use super::*;
use crate::device::{AllowedDevice, DeviceKind};
use crate::resources::HandleId;
use std::path::PathBuf;

pub(super) struct Slot {
    device: AllowedDevice,
    handle: HandleId,
    references: u32,
    retired: bool,
    closed: bool,
    running: bool,
    retry: Instant,
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
pub(super) struct Completion {
    connection: ConnectionId,
    operation: Operation,
    done: Option<oneshot::Sender<()>>,
}

impl Controller {
    pub(super) fn open_device(
        &mut self,
        id: ConnectionId,
        path: PathBuf,
        done: oneshot::Sender<()>,
    ) {
        let client = &self.clients[&id];
        let owner = client.resource_owner;
        let context = client.context;
        let Some(permit) = client.epoch.clone().filter(|epoch| epoch.is_open()) else {
            self.send(id, wire::error(libc::EACCES), None);
            let _ = done.send(());
            return;
        };
        if self.effective != Some(context)
            || client.membership != Membership::Enabled
            || self.topology_paused
        {
            self.send(id, wire::error(libc::EACCES), None);
            let _ = done.send(());
            return;
        }
        let Ok(worker) = self.budget.workers.clone().try_acquire_owned() else {
            self.send(id, wire::error(libc::EAGAIN), None);
            let _ = done.send(());
            return;
        };
        let Ok(quota) = self.budget.descriptors.clone().try_acquire_owned() else {
            self.send(id, wire::error(libc::EMFILE), None);
            let _ = done.send(());
            return;
        };
        let available = client.slots.len() < 128;
        let next = client.next_slot;
        let slots: Vec<_> = client
            .slots
            .iter()
            .filter(|(_, slot)| !slot.retired && !slot.closed)
            .map(|(number, slot)| (*number, slot.device.clone(), slot.handle))
            .collect();
        let devices = self.policy.devices.clone();
        let resources = self.resources.clone();
        let synthetic = self.policy.synthetic;
        self.clients.get_mut(&id).expect("client").operations += 1;
        self.device_jobs.spawn(async move {
            let operation = tokio::task::spawn_blocking(move || {
                let _worker = worker;
                // Requests name a published canonical node, never an arbitrary
                // caller-controlled filesystem walk (including FUSE/autofs).
                let Some(device) = devices.get(&path).cloned() else {
                    return Operation::Denied(libc::EACCES);
                };
                if !permit.is_open() {
                    return Operation::Denied(libc::EACCES);
                }
                let existing = slots.iter().find(|(_, previous, _)| previous == &device);
                let (slot, handle, fresh) = if let Some((slot, _, handle)) = existing {
                    (*slot, *handle, false)
                } else {
                    if !available || next == i32::MAX {
                        return Operation::Denied(libc::EMFILE);
                    }
                    let handle = reserve(&resources, owner, device.clone(), synthetic);
                    match handle {
                        Ok(handle) => (next, handle, true),
                        Err(error) => return Operation::Denied(errno(&error)),
                    }
                };
                let result = resources.open(handle, &permit);
                // Never abandon an original after an open/reply error. Failed
                // cleanup remains indexed and is transferred back as a slot.
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
                connection: id,
                operation,
                done: Some(done),
            }
        });
    }

    pub(super) fn close_device(
        &mut self,
        id: ConnectionId,
        number: i32,
        done: oneshot::Sender<()>,
    ) {
        let Some(slot) = self
            .clients
            .get_mut(&id)
            .and_then(|client| client.slots.get_mut(&number))
        else {
            self.send(id, wire::error(libc::EBADF), None);
            let _ = done.send(());
            return;
        };
        if slot.references > 1 {
            slot.references -= 1;
            self.send(id, wire::empty(wire::SERVER_DEVICE_CLOSED), None);
            let _ = done.send(());
            return;
        }
        if slot.closed {
            self.clients
                .get_mut(&id)
                .expect("client")
                .slots
                .remove(&number);
            self.send(id, wire::empty(wire::SERVER_DEVICE_CLOSED), None);
            let _ = done.send(());
            return;
        }
        slot.references = 0;
        slot.retired = true;
        self.close_slot(id, number, Some(done));
    }

    fn close_slot(
        &mut self,
        id: ConnectionId,
        number: i32,
        done: Option<oneshot::Sender<()>>,
    ) -> bool {
        let Ok(worker) = self.budget.workers.clone().try_acquire_owned() else {
            if let Some(done) = done {
                self.send(id, wire::error(libc::EAGAIN), None);
                let _ = done.send(());
            }
            return false;
        };
        let client = self.clients.get_mut(&id).expect("client");
        let slot = client.slots.get_mut(&number).expect("slot");
        slot.running = true;
        client.operations += 1;
        let handle = slot.handle;
        let resources = self.resources.clone();
        self.device_jobs.spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let _worker = worker;
                resources.close(handle)
            })
            .await
            .expect("device close worker panicked");
            Completion {
                connection: id,
                operation: Operation::Close {
                    slot: number,
                    result,
                },
                done,
            }
        });
        true
    }

    pub(super) fn retire_inputs(&mut self, context: ContextId) {
        for client in self
            .clients
            .values_mut()
            .filter(|client| client.context == context)
        {
            for slot in client.slots.values_mut() {
                if slot.device.kind != DeviceKind::DrmPrimary {
                    slot.retired = true;
                }
            }
        }
    }

    pub(super) fn retire_outdated(&mut self, next: &policy::Policy) {
        for client in self.clients.values_mut() {
            for slot in client.slots.values_mut() {
                if next.devices.get(&slot.device.path) != Some(&slot.device) {
                    slot.retired = true;
                }
            }
        }
    }

    pub(super) fn context_operations(&self, context: ContextId) -> bool {
        self.clients
            .values()
            .filter(|client| client.context == context)
            .any(|client| {
                client.operations != 0
                    || client.cleanup
                    || client.cleanup_running
                    || client
                        .slots
                        .values()
                        .any(|slot| slot.retired && !slot.closed)
            })
    }

    pub(super) fn retry_slots(&mut self) {
        let pending: Vec<_> = self
            .clients
            .iter()
            .filter(|(_, client)| !client.cleanup && !client.cleanup_running)
            .flat_map(|(id, client)| {
                client
                    .slots
                    .iter()
                    .filter(|(_, slot)| {
                        slot.retired
                            && !slot.closed
                            && !slot.running
                            && slot.retry <= Instant::now()
                    })
                    .map(|(number, _)| (*id, *number))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (id, number) in pending {
            self.close_slot(id, number, None);
        }
    }

    pub(super) fn device_completed(&mut self, completion: Completion) {
        let id = completion.connection;
        let Some(client) = self.clients.get_mut(&id) else {
            return;
        };
        client.operations -= 1;
        match completion.operation {
            Operation::Denied(error) => {
                self.send(id, wire::error(error), None);
            }
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
                    client.next_slot += 1;
                    client.slots.insert(
                        slot,
                        Slot {
                            device,
                            handle,
                            references: 0,
                            retired: true,
                            closed: false,
                            running: false,
                            retry: Instant::now(),
                        },
                    );
                }
                let result = result.and_then(|fd| {
                    if !permit.is_open() || client.closing || client.port.close.is_closed() {
                        Err(io::Error::from_raw_os_error(libc::EACCES))
                    } else {
                        Ok(fd)
                    }
                });
                match result {
                    Ok(fd) => {
                        let entry = client.slots.get_mut(&slot).expect("open slot");
                        match entry.references.checked_add(1) {
                            Some(references) => {
                                entry.references = references;
                                entry.retired = false;
                            }
                            None => {
                                self.close_connection(id);
                                return;
                            }
                        }
                        client.port.send(connection::Output {
                            bytes: wire::device_opened(slot),
                            fd: Some(fd),
                            tag: None,
                            quota: Some(quota),
                        });
                    }
                    Err(error) => {
                        self.send(id, wire::error(errno(&error)), None);
                    }
                }
            }
            Operation::Close { slot, result } => {
                if let Some(entry) = client.slots.get_mut(&slot) {
                    entry.running = false;
                    match result {
                        Ok(()) => {
                            entry.closed = true;
                            if entry.references == 0 {
                                client.slots.remove(&slot);
                            }
                            if completion.done.is_some() {
                                self.send(id, wire::empty(wire::SERVER_DEVICE_CLOSED), None);
                            }
                        }
                        Err(error) => {
                            entry.retry = Instant::now() + Duration::from_secs(1);
                            client.error = error.to_string();
                            if completion.done.is_some() {
                                self.send(id, wire::error(errno(&error)), None);
                            }
                        }
                    }
                }
            }
        }
        if let Some(done) = completion.done {
            let _ = done.send(());
        }
    }
}

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
