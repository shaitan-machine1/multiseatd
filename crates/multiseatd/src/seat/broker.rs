//! Policy adaptation only: the broker owns slots, inventory and device jobs.
use super::*;
use std::path::PathBuf;

impl Controller {
    pub(super) fn open_device(
        &mut self,
        id: ConnectionId,
        path: PathBuf,
        done: oneshot::Sender<()>,
    ) {
        let client = &self.clients[&id];
        let permit = client.epoch.clone().filter(|epoch| {
            epoch.is_open()
                && self.effective == Some(client.context)
                && client.membership == Membership::Enabled
                && !self.topology_paused
        });
        let Some(permit) = permit else {
            self.send(id, wire::error(libc::EACCES), None);
            let _ = done.send(());
            return;
        };
        if let Some(reply) = self
            .devices
            .open(id, &path, &permit, self.policy.synthetic, done)
        {
            self.device_reply(reply);
        }
    }
    pub(super) fn close_device(
        &mut self,
        id: ConnectionId,
        number: i32,
        done: oneshot::Sender<()>,
    ) {
        if let Some(reply) = self.devices.close(id, number, done) {
            self.device_reply(reply);
        }
    }
    pub(super) fn retire_inputs(&mut self, context: ContextId) {
        for id in &self.contexts[&context].connections {
            self.devices.retire_inputs(*id);
        }
    }
    pub(super) fn retire_outdated(&mut self, next: &policy::Policy) {
        self.devices.retire_outdated(&next.devices);
    }
    pub(super) fn context_operations(&self, context: ContextId) -> bool {
        self.clients
            .iter()
            .filter(|(_, client)| client.context == context)
            .any(|(id, client)| {
                client.operations != 0
                    || client.cleanup
                    || client.cleanup_running
                    || self.devices.pending(*id)
            })
    }
    pub(super) fn retry_slots(&mut self) {
        self.devices.retry();
    }
    pub(super) fn device_reply(&mut self, reply: dev_broker::devices::Reply<ConnectionId>) {
        let id = reply.connection;
        // A delayed response must never resolve a reused correlation tag onto
        // another owning generation, even if the caller reuses that tag.
        if self.devices.owner(id) != Some(reply.owner) {
            return;
        }
        if let Some(client) = self.clients.get_mut(&id) {
            if let Some(error) = reply.error {
                client.error = error;
            }
            if let Some(output) = reply.output {
                client.port.send(output);
            }
        }
        if reply.disconnect {
            self.close_connection(id);
        }
        if let Some(done) = reply.done {
            let _ = done.send(());
        }
    }
}
