//! Desired UID registrations are context state, never connection leases.
use super::*;

pub(super) struct Change {
    pub context: ContextId,
    uid: u32,
    addition: bool,
    failed: bool,
    running: bool,
    retry: Instant,
    reply: Option<Reply>,
}

impl Controller {
    pub(super) fn grant_request(
        &mut self,
        context: ContextId,
        uid: u32,
        grant: bool,
        reply: Reply,
        quiescing: bool,
    ) {
        if uid == u32::MAX {
            let _ = reply.send(Err(ErrorKind::InvalidArgument));
            return;
        }
        if quiescing
            || !self
                .contexts
                .get(&context)
                .is_some_and(|context| !context.removing && context.lifetime.is_live())
        {
            let _ = reply.send(Err(ErrorKind::ContextRemoving));
            return;
        }
        if self.mutations.len() == 256 {
            let _ = reply.send(Err(ErrorKind::LimitExceeded));
            return;
        }
        self.mutations.push_back(Mutation {
            context,
            activate: false,
            grant: Some((uid, grant)),
            reply,
        });
    }

    pub(super) fn begin_grant(&mut self, context: ContextId, uid: u32, grant: bool, reply: Reply) {
        let Some(state) = self
            .contexts
            .get_mut(&context)
            .filter(|state| !state.removing && state.lifetime.is_live())
        else {
            let _ = reply.send(Err(ErrorKind::ContextRemoving));
            return;
        };
        if state.grants.contains(&uid) == grant {
            let _ = reply.send(Ok(()));
            return;
        }
        if grant && state.grants.len() == 64 {
            let _ = reply.send(Err(ErrorKind::LimitExceeded));
            return;
        }
        if grant {
            state.grants.insert(uid);
        } else {
            state.grants.remove(&uid);
        }
        if self.effective != Some(context) {
            let _ = reply.send(Ok(()));
            return;
        }
        self.access = Some(Change {
            context,
            uid,
            addition: grant,
            failed: false,
            running: false,
            retry: Instant::now(),
            reply: Some(reply),
        });
    }

    pub(super) fn access_pending(&self, context: ContextId) -> bool {
        self.access
            .as_ref()
            .is_some_and(|change| change.context == context)
    }

    pub(super) fn drive_access(&mut self) {
        let Some(change) = self.access.as_mut() else {
            return;
        };
        if change.running || change.retry > Instant::now() {
            return;
        }
        let context = change.context;
        let eligible = self.contexts.get(&context).is_some_and(|state| {
            !state.removing && state.epoch.as_ref().is_some_and(Permit::is_open)
        }) && self.effective == Some(context);
        if !eligible && change.addition && !change.failed {
            change.failed = true;
            if let Some(state) = self.contexts.get_mut(&context) {
                state.grants.remove(&change.uid);
            }
        }
        if self.job(Job::Access(context)) {
            self.access.as_mut().expect("access change").running = true;
        }
    }

    pub(super) fn access_completed(&mut self, context: ContextId, error: Option<String>) {
        let Some(mut change) = self.access.take() else {
            return;
        };
        assert_eq!(change.context, context);
        change.running = false;
        if let Some(error) = error {
            if let Some(state) = self.contexts.get_mut(&context) {
                state.error = error;
                if change.addition {
                    state.grants.remove(&change.uid);
                }
            }
            change.failed = true;
            change.retry = Instant::now() + Duration::from_millis(100);
            self.access = Some(change);
        } else {
            if let Some(state) = self.contexts.get_mut(&context) {
                state.error.clear();
            }
            if let Some(reply) = change.reply.take() {
                let _ = reply.send(if change.failed && change.addition {
                    Err(ErrorKind::BackendFailure)
                } else {
                    Ok(())
                });
            }
        }
    }

    pub(super) fn reconcile_access(&mut self) {
        if self.access.is_some()
            || self.idle_access
            || self.transition.is_some()
            || self.topology_paused
        {
            return;
        }
        if let Some(context) = self.effective {
            self.access = Some(Change {
                context,
                uid: 0,
                addition: false,
                failed: false,
                running: false,
                retry: Instant::now(),
                reply: None,
            });
        } else if self.job(Job::IdleAccess) {
            self.idle_access = true;
        }
    }
}
