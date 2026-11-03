//! VT facts gate access independently of context selection.
use super::*;
use crate::vt::{Facts, Phase};

pub(super) struct SwitchCompletion {
    connection: ConnectionId,
    result: io::Result<()>,
    done: oneshot::Sender<()>,
}

pub(super) async fn changed(facts: &mut Option<watch::Receiver<Facts>>) -> io::Result<()> {
    match facts {
        Some(facts) => facts.changed().await.map_err(io::Error::other),
        None => std::future::pending().await,
    }
}

impl Controller {
    pub fn attach_vt(&mut self, port: crate::vt::Port) {
        assert!(self.contexts.is_empty());
        self.vt_facts = Some(port.facts.clone());
        self.vt = Some(port);
    }
    pub(super) fn foreground(&self) -> bool {
        self.vt_facts.as_ref().is_none_or(|facts| {
            let facts = facts.borrow();
            facts.phase == Phase::Foreground && facts.gate.is_open()
        })
    }
    pub(super) fn epoch(&self, context: ContextId) -> Permit {
        let mut epoch = Permit::for_context(self.contexts[&context].lifetime.clone())
            .gated(self.policy_gate.borrow().gate());
        if let Some(facts) = &self.vt_facts {
            epoch = epoch.gated(facts.borrow().gate.gate());
        }
        epoch
    }
    pub(super) fn update_vt(&mut self) -> io::Result<()> {
        let Some(facts) = self.vt_facts.as_ref().map(|facts| facts.borrow().clone()) else {
            return Ok(());
        };
        if facts.phase == Phase::Failed {
            return Err(io::Error::other(facts.error));
        }
        if self.vt_generation == Some(facts.generation) {
            return Ok(());
        }
        self.vt_generation = Some(facts.generation);
        self.vt_requested = false;
        if facts.phase == Phase::Releasing {
            self.vt_suspended = true;
            self.vt_release_sent = None;
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
        } else if facts.phase == Phase::Foreground {
            self.vt_suspended = false;
            self.resume_policy = true;
        } else {
            self.vt_suspended = true;
        }
        Ok(())
    }
    pub(super) fn vt_progress(&mut self) -> io::Result<()> {
        let Some(port) = &self.vt else { return Ok(()) };
        let facts = port.facts.borrow().clone();
        if facts.phase == Phase::Releasing
            && self.vt_release_sent != Some(facts.generation)
            && self.jobs.is_empty()
            && self.device_jobs.is_empty()
            && self.switches.is_empty()
            && self.access.is_none()
            && self
                .transition
                .as_ref()
                .is_none_or(|transition| transition.pending_disable.is_empty())
            && self.contexts.iter().all(|(id, state)| {
                !state.dirty && !state.preparing && !state.revoking && !self.context_operations(*id)
            })
        {
            match port.release_ready(facts.generation) {
                Ok(()) => self.vt_release_sent = Some(facts.generation),
                Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    pub(super) fn request_foreground(&mut self, context: ContextId) -> io::Result<()> {
        if self.vt_requested {
            return Ok(());
        }
        if let Some(port) = &self.vt {
            // Full authority may acquire from background; the access epoch's
            // closed foreground gate is deliberately NOT an acquisition right.
            let permit = Permit::for_context(self.contexts[&context].lifetime.clone());
            match port.acquire(permit) {
                Ok(()) => self.vt_requested = true,
                Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    pub(super) fn switch_protocol(
        &mut self,
        connection: ConnectionId,
        target: i32,
        done: oneshot::Sender<()>,
    ) {
        let client = &self.clients[&connection];
        let error = if self.vt.is_none() {
            Some(libc::ENOTSUP)
        } else if client.membership != Membership::Enabled
            || self.effective != Some(client.context)
            || !client.epoch.as_ref().is_some_and(Permit::is_open)
            || !self.foreground()
        {
            Some(libc::EACCES)
        } else if !(1..=63).contains(&target) {
            Some(libc::EINVAL)
        } else {
            None
        };
        if let Some(error) = error {
            self.send(connection, wire::error(error), None);
            let _ = done.send(());
            return;
        }
        let result = self
            .vt
            .as_ref()
            .expect("VT")
            .switch(target as u32, client.epoch.clone().expect("enabled epoch"));
        match result {
            Ok(receiver) => {
                self.clients
                    .get_mut(&connection)
                    .expect("client")
                    .operations += 1;
                self.switches.spawn(async move {
                    SwitchCompletion {
                        connection,
                        result: receiver
                            .await
                            .unwrap_or_else(|_| Err(io::Error::other("VT switch owner lost"))),
                        done,
                    }
                });
            }
            Err(error) => {
                self.send(
                    connection,
                    wire::error(error.raw_os_error().unwrap_or(libc::EIO)),
                    None,
                );
                let _ = done.send(());
            }
        }
    }
    pub(super) fn switch_completed(&mut self, completion: SwitchCompletion) {
        if let Some(client) = self.clients.get_mut(&completion.connection) {
            client.operations -= 1;
        }
        let packet = match completion.result {
            Ok(()) => wire::empty(wire::SERVER_SESSION_SWITCHED),
            Err(error) => wire::error(error.raw_os_error().unwrap_or(libc::EIO)),
        };
        self.send(completion.connection, packet, None);
        let _ = completion.done.send(());
    }
}
