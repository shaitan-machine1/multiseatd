//! Routing and creation-publication ownership, not seat activation policy.
//!
//! Removal is level-triggered retained work. Only the owning seat controller may
//! acknowledge completion, after its resource barrier; dropping a client reply
//! or evicting an authority retry cookie never acknowledges that work.

use crate::authority::{Authorities, AuthorityError};
use libmultiseatd::ContextId;
use seat_udev::SeatName;
use std::collections::{BTreeMap, BTreeSet};
use std::future::{Future, poll_fn};
use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::Poll;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;

const PENDING: u8 = 0;
const PUBLISHING: u8 = 1;
const PUBLISHED: u8 = 2;
const ABANDONED: u8 = 3;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub seats: usize,
    pub contexts: usize,
    pub contexts_per_seat: usize,
    pub authority_tombstones: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            seats: 256,
            contexts: 256,
            contexts_per_seat: 64,
            authority_tombstones: 4096,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("daemon admission is closed")]
    Stopping,
    #[error("unknown or withdrawn seat")]
    UnknownSeat,
    #[error("registry limit reached")]
    LimitExceeded,
    #[error("old seat cleanup is incomplete")]
    CleanupPending,
    #[error("registry limits must be nonzero")]
    InvalidLimits,
    #[error(transparent)]
    Authority(#[from] AuthorityError),
}

#[derive(Debug, thiserror::Error)]
pub enum PublicationError<E> {
    #[error("context was invalidated before publication")]
    Invalidated,
    #[error("response publication failed: {0}")]
    Send(E),
}

struct PublicationState {
    phase: AtomicU8,
    changed: Arc<Notify>,
}

impl PublicationState {
    fn authorizes(&self) -> bool {
        matches!(self.phase.load(Ordering::Acquire), PUBLISHING | PUBLISHED)
    }

    fn abandon(&self) {
        self.phase.store(ABANDONED, Ordering::Release);
        // Unlike try_send into a full cleanup queue, this cannot lose removal.
        // The bounded routing table is the durable in-memory work list.
        self.changed.notify_one();
    }
}

/// Irreversible context lifetime fact, shared with its seat controller. It is
/// not a client credential and does not select/activate anything.
#[derive(Clone)]
pub struct Registration(Arc<PublicationState>);

impl Registration {
    pub fn is_live(&self) -> bool {
        self.0.phase.load(Ordering::Acquire) != ABANDONED
    }

    pub fn permit(&self) -> dev_broker::permit::Permit {
        let lifetime = self.clone();
        dev_broker::permit::Permit::with_lifetime(move || lifetime.is_live())
    }
}

/// Unpublished endpoint owner. Prepare the context in its seat controller before
/// calling publish; registration must precede any response leaving the process.
/// Dropping this guard (including unwinding or an undelivered oneshot reply)
/// irrevocably fences the context and wakes registry cleanup.
pub struct ContextPublication {
    context: ContextId,
    endpoint: Option<OwnedFd>,
    state: Arc<PublicationState>,
    committed: bool,
}

impl ContextPublication {
    pub fn context(&self) -> ContextId {
        self.context
    }

    pub fn registration(&self) -> Registration {
        Registration(self.state.clone())
    }

    /// The callback synchronously hands ownership to the bounded response queue.
    /// Ok is its publication commit point, not proof of receipt by the caller.
    /// A queued descriptor must be released on bus loss/failed delivery.
    pub fn publish<T, E>(
        mut self,
        send: impl FnOnce(ContextId, OwnedFd) -> Result<T, E>,
    ) -> Result<T, PublicationError<E>> {
        self.state
            .phase
            .compare_exchange(PENDING, PUBLISHING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| PublicationError::Invalidated)?;
        // Authorize before send: the recipient may use the FD as soon as the
        // queue flushes, even before send returns. Failure fences it via Drop.
        let endpoint = self.endpoint.take().expect("publication owns its endpoint");
        let result = send(self.context, endpoint).map_err(PublicationError::Send)?;
        // Concurrent root/seat removal wins. Never overwrite ABANDONED and
        // resurrect a context just because its response was already queued.
        let _ = self.state.phase.compare_exchange(
            PUBLISHING,
            PUBLISHED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.committed = true;
        self.state.changed.notify_one();
        Ok(result)
    }
}

impl Drop for ContextPublication {
    fn drop(&mut self) {
        if !self.committed {
            self.state.abandon();
        }
    }
}

struct ContextRoute {
    seat: SeatName,
    publication: Arc<PublicationState>,
    removing: bool,
}

pub struct Registry {
    authorities: Authorities,
    seats: BTreeSet<SeatName>,
    contexts: BTreeMap<ContextId, ContextRoute>,
    limits: Limits,
    changed: Arc<Notify>,
    accepting: bool,
}

impl Registry {
    pub fn new(limits: Limits) -> Result<Self, RegistryError> {
        if limits.seats == 0
            || limits.contexts == 0
            || limits.contexts_per_seat == 0
            || limits.authority_tombstones == 0
        {
            return Err(RegistryError::InvalidLimits);
        }
        Ok(Self {
            authorities: Authorities::new(limits.contexts, limits.authority_tombstones)?,
            seats: BTreeSet::new(),
            contexts: BTreeMap::new(),
            limits,
            changed: Arc::new(Notify::new()),
            accepting: true,
        })
    }

    /// The topology owner calls this only after startup/source cleanup gates.
    /// A same-name replacement cannot steal a retiring seat's context routes.
    pub fn add_seat(&mut self, seat: SeatName) -> Result<(), RegistryError> {
        if !self.accepting {
            return Err(RegistryError::Stopping);
        }
        if self.seats.contains(&seat) {
            return Ok(());
        }
        if self.contexts.values().any(|route| route.seat == seat) {
            return Err(RegistryError::CleanupPending);
        }
        if self.seats.len() == self.limits.seats {
            return Err(RegistryError::LimitExceeded);
        }
        self.seats.insert(seat);
        Ok(())
    }

    pub fn withdraw_seat(&mut self, seat: &SeatName) {
        self.seats.remove(seat);
        let contexts: Vec<_> = self
            .contexts
            .iter()
            .filter(|(_, route)| &route.seat == seat)
            .map(|(id, _)| *id)
            .collect();
        for context in contexts {
            self.remove(context);
        }
    }

    pub fn begin_context(&mut self, seat: &SeatName) -> Result<ContextPublication, RegistryError> {
        if !self.accepting {
            return Err(RegistryError::Stopping);
        }
        if !self.seats.contains(seat) {
            return Err(RegistryError::UnknownSeat);
        }
        // Retiring routes count too. Repeated create/remove cannot evade quotas
        // by accumulating arbitrarily many unresolved cleanup records.
        if self.contexts.len() == self.limits.contexts
            || self
                .contexts
                .values()
                .filter(|route| &route.seat == seat)
                .count()
                >= self.limits.contexts_per_seat
        {
            return Err(RegistryError::LimitExceeded);
        }
        let issued = self.authorities.issue()?;
        let state = Arc::new(PublicationState {
            phase: AtomicU8::new(PENDING),
            changed: self.changed.clone(),
        });
        self.contexts.insert(
            issued.context,
            ContextRoute {
                seat: seat.clone(),
                publication: state.clone(),
                removing: false,
            },
        );
        Ok(ContextPublication {
            context: issued.context,
            endpoint: Some(issued.endpoint),
            state,
            committed: false,
        })
    }

    pub fn resolve(&self, authority: BorrowedFd<'_>) -> Result<ContextId, AuthorityError> {
        let context = self.authorities.resolve(authority)?;
        if !self.accepting
            || !self
                .contexts
                .get(&context)
                .is_some_and(|route| !route.removing && route.publication.authorizes())
        {
            return Err(AuthorityError::AccessDenied);
        }
        Ok(context)
    }

    pub fn resolve_removal(&self, authority: BorrowedFd<'_>) -> Result<ContextId, AuthorityError> {
        self.authorities.resolve_removal(authority)
    }

    /// Idempotent, irreversible admission fencing. No device work is discarded.
    pub fn remove(&mut self, context: ContextId) {
        if let Some(route) = self.contexts.get_mut(&context) {
            route.removing = true;
            route.publication.abandon();
        }
        self.authorities.invalidate(context);
    }

    /// Consume capability lifetime/publication facts, never resource completion.
    pub fn reconcile_lifetimes(&mut self) -> Result<(), AuthorityError> {
        for event in self.authorities.retire_ready()? {
            self.remove(event.context);
        }
        let abandoned: Vec<_> = self
            .contexts
            .iter()
            .filter(|(_, route)| {
                !route.removing && route.publication.phase.load(Ordering::Acquire) == ABANDONED
            })
            .map(|(context, _)| *context)
            .collect();
        for context in abandoned {
            self.remove(context);
        }
        Ok(())
    }

    /// Level-triggered outbox. A full controller queue must leave these entries
    /// intact. Enqueue idempotent removal under the normal bounded retry budget.
    pub fn removals(&self) -> impl Iterator<Item = (ContextId, &SeatName)> {
        self.contexts
            .iter()
            .filter(|(_, route)| route.removing)
            .map(|(context, route)| (*context, &route.seat))
    }

    /// Controller-only acknowledgement AFTER all started work and retained
    /// resources are cleaned. Caller timeout is never such an acknowledgement.
    pub fn complete_removal(&mut self, context: ContextId) -> bool {
        if self
            .contexts
            .get(&context)
            .is_some_and(|route| route.removing)
        {
            self.contexts.remove(&context);
            true
        } else {
            false
        }
    }

    pub fn close_admission(&mut self) {
        self.accepting = false;
        let contexts: Vec<_> = self.contexts.keys().copied().collect();
        for context in contexts {
            self.remove(context);
        }
    }

    pub fn context_seat(&self, context: ContextId) -> Option<&SeatName> {
        self.contexts.get(&context).map(|route| &route.seat)
    }

    pub fn retained_contexts(&self) -> usize {
        self.contexts.len()
    }

    /// Readiness, not a periodic sweep. Cancellation is safe: atomic publication
    /// facts and EOF/data remain inspectable, and Notify retains a wake permit.
    /// New commands can interrupt this wait in the registry owner's select loop.
    pub async fn changed(&self) -> io::Result<()> {
        let watches: Vec<_> = self
            .authorities
            .anchors()
            .map(|(_, fd)| {
                // SAFETY: this shared registry borrow keeps every anchor open
                // and unchanged until the watch is dropped, including when the
                // enclosing wait is cancelled. No watch escapes this method.
                unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }
                    .map_err(io::Error::from)
            })
            .collect::<io::Result<_>>()?;
        let mut notified = pin!(self.changed.notified());
        poll_fn(|cx| {
            if notified.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(()));
            }
            for watch in &watches {
                match watch.poll_read_ready(cx) {
                    Poll::Ready(Ok(mut ready)) => {
                        // Reconciliation owns consumption/invalidation. This
                        // wait must not acknowledge away an unprocessed fact.
                        ready.retain_ready();
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        // An orphaned response task must not publish after its owning registry
        // has failed. No allocations or resource-completion acknowledgements on
        // this unwind path; outer owners still owe actual device/ACL cleanup.
        self.accepting = false;
        for route in self.contexts.values() {
            route.publication.abandon();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::os::fd::AsFd;
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::{Duration, timeout};

    fn seat(name: &str) -> SeatName {
        name.parse().unwrap()
    }

    fn registry() -> Registry {
        let mut registry = Registry::new(Limits {
            seats: 2,
            contexts: 3,
            contexts_per_seat: 2,
            authority_tombstones: 1,
        })
        .unwrap();
        registry.add_seat(seat("seat-a")).unwrap();
        registry.add_seat(seat("seat-b")).unwrap();
        registry
    }

    fn publish(guard: ContextPublication) -> OwnedFd {
        guard.publish(|_, fd| Ok::<_, Infallible>(fd)).unwrap()
    }

    fn denied(registry: &Registry, authority: &OwnedFd) {
        assert!(matches!(
            registry.resolve(authority.as_fd()),
            Err(AuthorityError::AccessDenied)
        ));
    }

    #[tokio::test]
    async fn cancelled_creation_reply_retains_removal_without_a_cleanup_queue_slot() {
        let mut registry = registry();
        let guard = registry.begin_context(&seat("seat-a")).unwrap();
        let id = guard.context();
        let (sender, receiver) = oneshot::channel();
        drop(receiver);
        assert!(sender.send(guard).is_err());
        timeout(Duration::from_secs(2), registry.changed())
            .await
            .unwrap()
            .unwrap();
        registry.reconcile_lifetimes().unwrap();
        let (blocked, _receiver) = mpsc::channel::<ContextId>(1);
        blocked.try_send(ContextId::generate()).unwrap();
        assert!(
            blocked
                .try_send(registry.removals().next().unwrap().0)
                .is_err()
        );
        for _ in 0..4 {
            registry.reconcile_lifetimes().unwrap();
            assert_eq!(
                registry.removals().collect::<Vec<_>>(),
                vec![(id, &seat("seat-a"))]
            );
        }
        assert_eq!(registry.retained_contexts(), 1);
        assert!(registry.complete_removal(id));
        assert_eq!(registry.retained_contexts(), 0);
    }

    #[test]
    fn failed_publication_fences_even_a_leaked_endpoint_copy_before_reconciliation() {
        let mut registry = registry();
        let guard = registry.begin_context(&seat("seat-a")).unwrap();
        let id = guard.context();
        let mut leaked = None;
        let result = guard.publish(|_, fd| {
            leaked = Some(fd.try_clone().unwrap());
            Err::<(), _>("queue full")
        });
        assert!(matches!(result, Err(PublicationError::Send("queue full"))));
        let leaked = leaked.unwrap();
        denied(&registry, &leaked);
        registry.reconcile_lifetimes().unwrap();
        assert_eq!(registry.resolve_removal(leaked.as_fd()).unwrap(), id);
        assert_eq!(registry.removals().next().unwrap().0, id);
    }

    #[test]
    fn publication_unwind_invalidates_instead_of_publishing_partial_success() {
        let mut registry = registry();
        let guard = registry.begin_context(&seat("seat-a")).unwrap();
        let id = guard.context();
        let mut leaked = None;
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = guard.publish::<(), Infallible>(|_, fd| {
                leaked = Some(fd);
                panic!("injected publication panic");
            });
        }));
        assert!(unwind.is_err());
        denied(&registry, leaked.as_ref().unwrap());
        registry.reconcile_lifetimes().unwrap();
        assert_eq!(registry.removals().next().unwrap().0, id);
    }

    #[test]
    fn root_removal_before_or_during_publication_cannot_resurrect_authority() {
        let mut registry = registry();
        let guard = registry.begin_context(&seat("seat-a")).unwrap();
        let id = guard.context();
        registry.remove(id);
        assert!(matches!(
            guard.publish::<(), Infallible>(|_, _| panic!("must not publish")),
            Err(PublicationError::Invalidated)
        ));
        assert!(registry.complete_removal(id));

        let guard = registry.begin_context(&seat("seat-a")).unwrap();
        let fd = guard
            .publish(|id, fd| {
                assert_eq!(registry.resolve(fd.as_fd()).unwrap(), id);
                registry.remove(id);
                Ok::<_, Infallible>(fd)
            })
            .unwrap();
        denied(&registry, &fd);
        assert_eq!(registry.removals().count(), 1);
    }

    #[tokio::test]
    async fn final_close_wakes_readiness_and_removes_only_that_context() {
        let mut registry = registry();
        let guard = registry.begin_context(&seat("seat-a")).unwrap();
        let id = guard.context();
        let endpoint = publish(guard);
        let duplicate = endpoint.try_clone().unwrap();
        let sibling = publish(registry.begin_context(&seat("seat-a")).unwrap());
        registry.reconcile_lifetimes().unwrap();
        // Consume the coalesced publication notification, then use only anchor
        // readiness to prove final-close detection (no timer/sweep worker).
        registry.changed().await.unwrap();
        drop(endpoint);
        assert!(
            timeout(Duration::from_millis(20), registry.changed())
                .await
                .is_err()
        );
        drop(duplicate);
        timeout(Duration::from_secs(2), registry.changed())
            .await
            .unwrap()
            .unwrap();
        registry.reconcile_lifetimes().unwrap();
        assert_eq!(registry.removals().next().unwrap().0, id);
        assert!(registry.resolve(sibling.as_fd()).is_ok());
    }

    #[test]
    fn unresolved_removals_count_against_both_limits_after_cookie_eviction() {
        let mut registry = registry();
        let first = registry.begin_context(&seat("seat-a")).unwrap();
        let first_id = first.context();
        let first_fd = publish(first);
        let second = registry.begin_context(&seat("seat-a")).unwrap();
        let second_id = second.context();
        let second_fd = publish(second);
        registry.remove(first_id);
        registry.remove(second_id);
        assert!(matches!(
            registry.resolve_removal(first_fd.as_fd()),
            Err(AuthorityError::AccessDenied)
        ));
        assert_eq!(
            registry.resolve_removal(second_fd.as_fd()).unwrap(),
            second_id
        );
        assert_eq!(registry.removals().count(), 2);
        assert!(matches!(
            registry.begin_context(&seat("seat-a")),
            Err(RegistryError::LimitExceeded)
        ));
        let third = registry.begin_context(&seat("seat-b")).unwrap();
        assert!(matches!(
            registry.begin_context(&seat("seat-b")),
            Err(RegistryError::LimitExceeded)
        ));
        assert!(registry.complete_removal(first_id));
        assert!(registry.begin_context(&seat("seat-b")).is_ok());
        drop(third);
    }

    #[test]
    fn seat_withdrawal_fences_pending_and_published_work_and_keeps_old_routes() {
        let mut registry = registry();
        let pending = registry.begin_context(&seat("seat-a")).unwrap();
        let active = registry.begin_context(&seat("seat-a")).unwrap();
        let id = active.context();
        let endpoint = publish(active);
        let other = publish(registry.begin_context(&seat("seat-b")).unwrap());
        registry.withdraw_seat(&seat("seat-a"));
        denied(&registry, &endpoint);
        assert!(registry.resolve(other.as_fd()).is_ok());
        assert!(matches!(
            registry.begin_context(&seat("seat-a")),
            Err(RegistryError::UnknownSeat)
        ));
        assert!(matches!(
            registry.add_seat(seat("seat-a")),
            Err(RegistryError::CleanupPending)
        ));
        assert!(registry.complete_removal(pending.context()));
        assert!(matches!(
            pending.publish::<(), Infallible>(|_, _| panic!("withdrawn")),
            Err(PublicationError::Invalidated)
        ));
        assert!(registry.complete_removal(id));
        registry.add_seat(seat("seat-a")).unwrap();
        assert!(registry.begin_context(&seat("seat-a")).is_ok());
    }

    #[test]
    fn registry_owner_loss_fences_an_outstanding_publication_guard() {
        let mut registry = registry();
        let guard = registry.begin_context(&seat("seat-a")).unwrap();
        drop(registry);
        assert!(matches!(
            guard.publish::<(), Infallible>(|_, _| panic!("owner is gone")),
            Err(PublicationError::Invalidated)
        ));
    }

    #[test]
    fn shutdown_is_irreversible_and_cannot_acknowledge_a_live_context() {
        let mut registry = registry();
        let guard = registry.begin_context(&seat("seat-a")).unwrap();
        let id = guard.context();
        let endpoint = publish(guard);
        assert!(!registry.complete_removal(id));
        registry.close_admission();
        registry.close_admission();
        denied(&registry, &endpoint);
        assert!(matches!(
            registry.begin_context(&seat("seat-a")),
            Err(RegistryError::Stopping)
        ));
        assert!(matches!(
            registry.add_seat(seat("seat-c")),
            Err(RegistryError::Stopping)
        ));
        assert_eq!(registry.removals().count(), 1);
        assert!(registry.complete_removal(id));
        assert!(!registry.complete_removal(id));
    }

    #[test]
    fn invalid_limits_seat_limits_and_unknown_seats_fail_before_allocation() {
        assert!(matches!(
            Registry::new(Limits {
                seats: 0,
                ..Limits::default()
            }),
            Err(RegistryError::InvalidLimits)
        ));
        let mut registry = registry();
        assert!(matches!(
            registry.add_seat(seat("seat-c")),
            Err(RegistryError::LimitExceeded)
        ));
        registry.add_seat(seat("seat-a")).unwrap();
        assert!(matches!(
            registry.begin_context(&seat("seat-absent")),
            Err(RegistryError::UnknownSeat)
        ));
        assert_eq!(registry.retained_contexts(), 0);
    }
}
