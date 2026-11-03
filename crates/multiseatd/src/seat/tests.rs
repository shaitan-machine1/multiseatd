use super::*;
use crate::daemon::CriticalTasks;
use crate::registry::{Limits, Registry};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

struct DeviceFaults {
    fail_revoke: Arc<AtomicBool>,
    fail_resume: Arc<AtomicBool>,
    revocations: Arc<AtomicUsize>,
}
impl crate::device::DeviceOps for DeviceFaults {
    fn open(&mut self, _: &crate::device::AllowedDevice) -> io::Result<OwnedFd> {
        Ok(std::fs::File::open("/dev/null")?.into())
    }
    fn deactivate(&mut self, _: crate::device::DeviceKind, _: &OwnedFd) -> io::Result<()> {
        self.revocations.fetch_add(1, Ordering::AcqRel);
        if self.fail_revoke.load(Ordering::Acquire) {
            Err(io::Error::other("injected revoke refusal"))
        } else {
            Ok(())
        }
    }
    fn activate(&mut self, _: crate::device::DeviceKind, _: &OwnedFd) -> io::Result<()> {
        if self.fail_resume.load(Ordering::Acquire) {
            Err(io::Error::other("injected resume refusal"))
        } else {
            Ok(())
        }
    }
}

fn attach_device(
    harness: &Harness,
    owner: ConnectionId,
    primary: bool,
    fail_revoke: Arc<AtomicBool>,
    fail_resume: Arc<AtomicBool>,
    revocations: Arc<AtomicUsize>,
) -> OwnedFd {
    use std::os::unix::fs::MetadataExt;
    let device = crate::device::AllowedDevice::canonicalized(
        crate::device::DeviceId::new("fixture"),
        "/dev/null",
        std::fs::metadata("/dev/null").unwrap().rdev(),
        if primary {
            crate::device::DeviceKind::DrmPrimary
        } else {
            crate::device::DeviceKind::Evdev
        },
    )
    .unwrap();
    let id = harness
        .resources
        .reserve_with(
            owner,
            device,
            Box::new(DeviceFaults {
                fail_revoke,
                fail_resume,
                revocations,
            }),
        )
        .unwrap();
    harness.resources.open(id, &Permit::new()).unwrap()
}

struct Peer {
    id: ConnectionId,
    stream: tokio::net::UnixStream,
}
impl Peer {
    async fn send(&mut self, opcode: u16) {
        self.stream.write_all(&wire::empty(opcode)).await.unwrap();
    }
    async fn receive(&mut self) -> io::Result<wire::Packet> {
        timeout(Duration::from_secs(4), async {
            let mut header = [0u8; 4];
            self.stream.read_exact(&mut header).await?;
            let length = u16::from_ne_bytes([header[2], header[3]]) as usize;
            assert!(length <= 1024);
            let mut payload = vec![0; length];
            self.stream.read_exact(&mut payload).await?;
            Ok(wire::Packet {
                opcode: u16::from_ne_bytes([header[0], header[1]]),
                payload,
            })
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "wire reply timeout"))?
    }
    async fn expect(&mut self, opcode: u16) {
        assert_eq!(self.receive().await.unwrap().opcode, opcode);
    }
    async fn open(&mut self) {
        self.send(wire::CLIENT_OPEN_SEAT).await;
        self.expect(wire::SERVER_SEAT_OPENED).await;
    }
    async fn acknowledge(&mut self) {
        self.send(wire::CLIENT_DISABLE_SEAT).await;
        self.expect(wire::SERVER_SEAT_DISABLED).await;
    }
    async fn ping(&mut self) {
        self.send(wire::CLIENT_PING).await;
        self.expect(wire::SERVER_PONG).await;
    }
}

struct Harness {
    registry: Registry,
    port: Port,
    tasks: CriticalTasks,
    authorities: Vec<OwnedFd>,
    resources: Arc<Resources>,
    budget: Budget,
    _cleanup: crate::resources::CleanupGuard,
}
impl Harness {
    fn new() -> Self {
        let mut registry = Registry::new(Limits::default()).unwrap();
        let name: SeatName = "seat-test".parse().unwrap();
        registry.add_seat(name.clone()).unwrap();
        let resources = Arc::new(Resources::new(64, 64).unwrap());
        let mut tasks = CriticalTasks::new(8).unwrap();
        let budget = Budget::default();
        let (controller, port) = Controller::new(name.clone(), resources.clone(), budget.clone());
        tasks
            .spawn(
                crate::daemon::CriticalRole::Seat(name),
                controller.run(tasks.subscribe()),
            )
            .unwrap();
        Self {
            registry,
            port,
            tasks,
            authorities: Vec::new(),
            resources: resources.clone(),
            budget,
            _cleanup: crate::resources::CleanupGuard(resources),
        }
    }
    async fn context(&mut self) -> ContextId {
        let publication = self
            .registry
            .begin_context(&"seat-test".parse().unwrap())
            .unwrap();
        let id = publication.context();
        let (sender, receiver) = oneshot::channel();
        self.port
            .send(Command::Register {
                context: id,
                lifetime: publication.registration(),
                reply: sender,
            })
            .unwrap();
        receiver.await.unwrap().unwrap();
        self.authorities
            .push(publication.publish(|_, fd| Ok::<_, io::Error>(fd)).unwrap());
        id
    }
    async fn publication(&self, context: ContextId) -> ConnectionPublication {
        let (sender, receiver) = oneshot::channel();
        self.port
            .send(Command::CreateConnection {
                context,
                reply: sender,
            })
            .unwrap();
        receiver.await.unwrap().unwrap()
    }
    async fn peer(&self, context: ContextId) -> Peer {
        let publication = self.publication(context).await;
        let id = publication.id();
        let fd = publication.publish(|_, fd| Ok(fd)).unwrap();
        let stream = UnixStream::from(fd);
        stream.set_nonblocking(true).unwrap();
        Peer {
            id,
            stream: tokio::net::UnixStream::from_std(stream).unwrap(),
        }
    }
    fn mutation(
        &self,
        context: ContextId,
        activate: bool,
    ) -> oneshot::Receiver<Result<(), ErrorKind>> {
        let (sender, receiver) = oneshot::channel();
        self.port
            .send(if activate {
                Command::Activate {
                    context,
                    reply: sender,
                }
            } else {
                Command::Deactivate {
                    context,
                    reply: sender,
                }
            })
            .unwrap();
        receiver
    }
    async fn activate(&self, context: ContextId) {
        timeout(Duration::from_secs(4), self.mutation(context, true))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    async fn deactivate(&self, context: ContextId) {
        timeout(Duration::from_secs(4), self.mutation(context, false))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    async fn remove(&mut self, context: ContextId) {
        self.registry.remove(context);
        let (sender, receiver) = oneshot::channel();
        self.port
            .send(Command::Remove {
                context,
                reply: sender,
            })
            .unwrap();
        timeout(Duration::from_secs(4), receiver)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        self.registry.complete_removal(context);
    }
    async fn wait(&mut self, condition: impl Fn(&Status) -> bool) {
        timeout(Duration::from_secs(4), async {
            loop {
                if condition(&self.port.status.borrow()) {
                    return;
                }
                self.port.status.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
    }
    async fn finish(mut self) {
        self.registry.close_admission();
        self.tasks.quiesce();
        self.tasks.advance(ShutdownPhase::Revoke).unwrap();
        assert!(self.resources.cleanup().is_empty());
        self.tasks.advance(ShutdownPhase::RestoreTerminal).unwrap();
        let exits = timeout(Duration::from_secs(4), self.tasks.drain())
            .await
            .unwrap()
            .unwrap();
        assert!(exits.iter().all(|exit| exit.failure.is_none()), "{exits:?}");
        self.tasks.advance(ShutdownPhase::Stopped).unwrap();
    }
}

#[tokio::test]
async fn inactive_membership_and_parallel_transports_never_select_a_context() {
    let mut harness = Harness::new();
    let context = harness.context().await;
    let mut first = harness.peer(context).await;
    let mut second = harness.peer(context).await;
    first.open().await;
    second.open().await;
    first.ping().await;
    second.ping().await;
    assert!(harness.port.status.borrow().seat.3.is_empty());
    assert!(harness.port.status.borrow().seat.4.is_empty());
    assert!(
        timeout(Duration::from_millis(30), first.receive())
            .await
            .is_err()
    );
    harness.activate(context).await;
    first.expect(wire::SERVER_ENABLE_SEAT).await;
    second.expect(wire::SERVER_ENABLE_SEAT).await;
    first.ping().await;
    second.ping().await;
    harness.finish().await;
}

#[tokio::test]
async fn handover_waits_for_each_ack_and_preserves_healthy_siblings() {
    let mut harness = Harness::new();
    let a = harness.context().await;
    let b = harness.context().await;
    let mut first = harness.peer(a).await;
    let mut sibling = harness.peer(a).await;
    let mut target = harness.peer(b).await;
    first.open().await;
    sibling.open().await;
    target.open().await;
    harness.activate(a).await;
    first.expect(wire::SERVER_ENABLE_SEAT).await;
    sibling.expect(wire::SERVER_ENABLE_SEAT).await;
    let mut activating = harness.mutation(b, true);
    first.expect(wire::SERVER_DISABLE_SEAT).await;
    sibling.expect(wire::SERVER_DISABLE_SEAT).await;
    first.acknowledge().await;
    assert!(activating.try_recv().is_err());
    assert!(
        timeout(Duration::from_millis(30), target.receive())
            .await
            .is_err()
    );
    sibling.acknowledge().await;
    activating.await.unwrap().unwrap();
    target.expect(wire::SERVER_ENABLE_SEAT).await;
    first.ping().await;
    sibling.ping().await;
    harness.finish().await;
}

#[tokio::test]
async fn deactivating_an_unselected_inactive_context_does_not_disturb_another() {
    let mut harness = Harness::new();
    let a = harness.context().await;
    let b = harness.context().await;
    let mut peer = harness.peer(b).await;
    peer.open().await;
    harness.activate(b).await;
    peer.expect(wire::SERVER_ENABLE_SEAT).await;
    harness.deactivate(a).await;
    peer.ping().await;
    assert_eq!(harness.port.status.borrow().seat.4, b.to_string());
    harness.remove(a).await;
    peer.ping().await;
    assert_eq!(harness.port.status.borrow().seat.4, b.to_string());
    harness.finish().await;
}

#[tokio::test]
async fn one_eof_leaves_context_and_other_enabled_connections_alive() {
    let mut harness = Harness::new();
    let context = harness.context().await;
    let mut first = harness.peer(context).await;
    let mut sibling = harness.peer(context).await;
    first.open().await;
    sibling.open().await;
    harness.activate(context).await;
    first.expect(wire::SERVER_ENABLE_SEAT).await;
    sibling.expect(wire::SERVER_ENABLE_SEAT).await;
    let first_id = first.id;
    drop(first);
    harness
        .wait(|status| !status.connections.contains_key(&first_id))
        .await;
    sibling.ping().await;
    assert_eq!(harness.port.status.borrow().contexts[&context].2, "active");
    let mut replacement = harness.peer(context).await;
    replacement.open().await;
    replacement.expect(wire::SERVER_ENABLE_SEAT).await;
    assert_ne!(replacement.id, first_id);
    sibling.ping().await;
    harness.finish().await;
}

#[tokio::test]
async fn close_and_reopen_membership_uses_the_same_transport_without_selection_changes() {
    let mut harness = Harness::new();
    let context = harness.context().await;
    harness.activate(context).await;
    let mut peer = harness.peer(context).await;
    peer.open().await;
    peer.expect(wire::SERVER_ENABLE_SEAT).await;
    peer.send(wire::CLIENT_CLOSE_SEAT).await;
    peer.expect(wire::SERVER_SEAT_CLOSED).await;
    peer.ping().await;
    peer.open().await;
    peer.expect(wire::SERVER_ENABLE_SEAT).await;
    assert_eq!(harness.port.status.borrow().seat.4, context.to_string());
    harness.finish().await;
}

#[tokio::test]
async fn unpublished_connections_are_closed_without_removing_the_context() {
    let mut harness = Harness::new();
    let context = harness.context().await;
    let publication = harness.publication(context).await;
    let id = publication.id();
    drop(publication);
    harness
        .wait(|status| !status.connections.contains_key(&id))
        .await;
    assert!(harness.port.status.borrow().contexts.contains_key(&context));
    let mut peer = harness.peer(context).await;
    peer.ping().await;
    harness.finish().await;
}

#[tokio::test]
async fn removal_fences_a_pending_connection_publication_and_never_falls_back() {
    let mut harness = Harness::new();
    let context = harness.context().await;
    harness.activate(context).await;
    let publication = harness.publication(context).await;
    harness.remove(context).await;
    assert!(
        publication
            .publish::<()>(|_, _| panic!("removed context must not publish"))
            .is_err()
    );
    assert!(harness.port.status.borrow().seat.3.is_empty());
    assert!(harness.port.status.borrow().seat.4.is_empty());
    harness.finish().await;
}

#[tokio::test]
async fn missing_disable_ack_disconnects_only_the_misser_and_requires_a_fresh_transport() {
    let mut harness = Harness::new();
    let a = harness.context().await;
    let b = harness.context().await;
    let mut healthy = harness.peer(a).await;
    let mut missed = harness.peer(a).await;
    healthy.open().await;
    missed.open().await;
    harness.activate(a).await;
    healthy.expect(wire::SERVER_ENABLE_SEAT).await;
    missed.expect(wire::SERVER_ENABLE_SEAT).await;
    let activating = harness.mutation(b, true);
    healthy.expect(wire::SERVER_DISABLE_SEAT).await;
    missed.expect(wire::SERVER_DISABLE_SEAT).await;
    healthy.acknowledge().await;
    timeout(Duration::from_secs(4), activating)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(missed.receive().await.is_err());
    healthy.ping().await;
    let old_id = missed.id;
    let mut fresh = harness.peer(a).await;
    fresh.open().await;
    harness.activate(a).await;
    healthy.expect(wire::SERVER_ENABLE_SEAT).await;
    fresh.expect(wire::SERVER_ENABLE_SEAT).await;
    assert_ne!(fresh.id, old_id);
    let mut disabling = harness.mutation(a, false);
    healthy.expect(wire::SERVER_DISABLE_SEAT).await;
    fresh.expect(wire::SERVER_DISABLE_SEAT).await;
    let _ = missed
        .stream
        .write_all(&wire::empty(wire::CLIENT_DISABLE_SEAT))
        .await;
    assert!(disabling.try_recv().is_err());
    healthy.acknowledge().await;
    fresh.acknowledge().await;
    disabling.await.unwrap().unwrap();
    harness.finish().await;
}

#[tokio::test]
async fn cancellation_of_the_wait_does_not_cancel_an_admitted_activation() {
    let mut harness = Harness::new();
    let context = harness.context().await;
    drop(harness.mutation(context, true));
    harness.wait(|status| status.contexts[&context].6).await;
    assert_eq!(harness.port.status.borrow().seat.4, context.to_string());
    harness.finish().await;
}

#[tokio::test]
async fn connection_removal_rejects_foreign_membership_and_does_not_revoke_siblings() {
    let mut harness = Harness::new();
    let a = harness.context().await;
    let b = harness.context().await;
    let mut peer = harness.peer(a).await;
    let mut sibling = harness.peer(a).await;
    peer.open().await;
    sibling.open().await;
    harness.activate(a).await;
    peer.expect(wire::SERVER_ENABLE_SEAT).await;
    sibling.expect(wire::SERVER_ENABLE_SEAT).await;
    let (sender, receiver) = oneshot::channel();
    harness
        .port
        .send(Command::RemoveConnection {
            context: b,
            connection: peer.id,
            reply: sender,
        })
        .unwrap();
    assert_eq!(receiver.await.unwrap(), Err(ErrorKind::UnknownConnection));
    peer.ping().await;
    let (sender, receiver) = oneshot::channel();
    harness
        .port
        .send(Command::RemoveConnection {
            context: a,
            connection: peer.id,
            reply: sender,
        })
        .unwrap();
    receiver.await.unwrap().unwrap();
    assert!(peer.receive().await.is_err());
    sibling.ping().await;
    assert_eq!(harness.port.status.borrow().seat.4, a.to_string());
    harness.finish().await;
}

#[tokio::test]
async fn failed_revocation_keeps_successor_disabled_until_autonomous_retry_succeeds() {
    let mut harness = Harness::new();
    let a = harness.context().await;
    let b = harness.context().await;
    let mut predecessor = harness.peer(a).await;
    let mut successor = harness.peer(b).await;
    predecessor.open().await;
    successor.open().await;
    harness.activate(a).await;
    predecessor.expect(wire::SERVER_ENABLE_SEAT).await;
    let fail = Arc::new(AtomicBool::new(true));
    let calls = Arc::new(AtomicUsize::new(0));
    let _client_fd = attach_device(
        &harness,
        predecessor.id,
        false,
        fail.clone(),
        Arc::new(AtomicBool::new(false)),
        calls.clone(),
    );
    let mut activating = harness.mutation(b, true);
    predecessor.expect(wire::SERVER_DISABLE_SEAT).await;
    predecessor.acknowledge().await;
    harness
        .wait(|status| !status.contexts[&a].7.is_empty())
        .await;
    assert!(activating.try_recv().is_err());
    assert!(
        timeout(Duration::from_millis(30), successor.receive())
            .await
            .is_err()
    );
    fail.store(false, Ordering::Release);
    timeout(Duration::from_secs(4), activating)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    successor.expect(wire::SERVER_ENABLE_SEAT).await;
    assert!(calls.load(Ordering::Acquire) >= 2);
    harness.finish().await;
}

#[tokio::test]
async fn failed_primary_resume_rolls_back_instead_of_leaving_partial_activation() {
    let mut harness = Harness::new();
    let a = harness.context().await;
    let b = harness.context().await;
    let mut peer = harness.peer(b).await;
    peer.open().await;
    harness.activate(b).await;
    peer.expect(wire::SERVER_ENABLE_SEAT).await;
    let fail_resume = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let _client_fd = attach_device(
        &harness,
        peer.id,
        true,
        Arc::new(AtomicBool::new(false)),
        fail_resume.clone(),
        calls.clone(),
    );
    let deactivating = harness.mutation(b, false);
    peer.expect(wire::SERVER_DISABLE_SEAT).await;
    peer.acknowledge().await;
    deactivating.await.unwrap().unwrap();
    harness.activate(a).await;
    fail_resume.store(true, Ordering::Release);
    let result = timeout(Duration::from_secs(4), harness.mutation(b, true))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, Err(ErrorKind::BackendFailure));
    assert!(harness.port.status.borrow().seat.3.is_empty());
    assert!(harness.port.status.borrow().seat.4.is_empty());
    assert!(calls.load(Ordering::Acquire) >= 2);
    assert!(
        timeout(Duration::from_millis(30), peer.receive())
            .await
            .is_err()
    );
    peer.ping().await;
    harness.finish().await;
}

#[tokio::test]
async fn removal_of_the_selected_target_during_handover_cannot_resurrect_it() {
    let mut harness = Harness::new();
    let a = harness.context().await;
    let b = harness.context().await;
    let mut predecessor = harness.peer(a).await;
    let mut target = harness.peer(b).await;
    predecessor.open().await;
    target.open().await;
    harness.activate(a).await;
    predecessor.expect(wire::SERVER_ENABLE_SEAT).await;
    let activating = harness.mutation(b, true);
    predecessor.expect(wire::SERVER_DISABLE_SEAT).await;
    harness.remove(b).await;
    assert!(target.receive().await.is_err());
    predecessor.acknowledge().await;
    assert_eq!(activating.await.unwrap(), Err(ErrorKind::ContextRemoving));
    assert!(harness.port.status.borrow().seat.3.is_empty());
    assert!(harness.port.status.borrow().seat.4.is_empty());
    predecessor.ping().await;
    harness.finish().await;
}

#[tokio::test]
async fn identical_pending_requests_coalesce_but_not_across_an_intervening_deactivation() {
    let mut harness = Harness::new();
    let a = harness.context().await;
    let b = harness.context().await;
    let mut predecessor = harness.peer(a).await;
    let mut target = harness.peer(b).await;
    predecessor.open().await;
    target.open().await;
    harness.activate(a).await;
    predecessor.expect(wire::SERVER_ENABLE_SEAT).await;
    let first = harness.mutation(b, true);
    predecessor.expect(wire::SERVER_DISABLE_SEAT).await;
    let identical = harness.mutation(b, true);
    let deactivation = harness.mutation(b, false);
    let mut later = harness.mutation(b, true);
    predecessor.acknowledge().await;
    first.await.unwrap().unwrap();
    identical.await.unwrap().unwrap();
    target.expect(wire::SERVER_ENABLE_SEAT).await;
    target.expect(wire::SERVER_DISABLE_SEAT).await;
    assert!(later.try_recv().is_err());
    target.acknowledge().await;
    deactivation.await.unwrap().unwrap();
    later.await.unwrap().unwrap();
    target.expect(wire::SERVER_ENABLE_SEAT).await;
    harness.finish().await;
}

async fn late_join_delivery_case(fail_delivery: bool) {
    // Drive the owner directly so transports cannot run between the initial
    // enable batch and the late OPEN_SEAT. No scheduler timing assumptions.
    let name: SeatName = "seat-test".parse().unwrap();
    let mut registry = Registry::new(Limits::default()).unwrap();
    registry.add_seat(name.clone()).unwrap();
    let publication = registry.begin_context(&name).unwrap();
    let context = publication.context();
    let resources = Arc::new(Resources::new(64, 64).unwrap());
    let (mut controller, _port) = Controller::new(name, resources, Budget::default());
    let (reply, receiver) = oneshot::channel();
    controller
        .command(
            Command::Register {
                context,
                lifetime: publication.registration(),
                reply,
            },
            false,
        )
        .unwrap();
    receiver.await.unwrap().unwrap();
    let _authority = publication.publish(|_, fd| Ok::<_, io::Error>(fd)).unwrap();
    let first = controller.create_connection(context).unwrap();
    let first_id = first.id();
    let _first_fd = first.publish(|_, fd| Ok(fd)).unwrap();
    let (done, _) = oneshot::channel();
    controller
        .packet(connection::Request {
            connection: first_id,
            packet: wire::Packet {
                opcode: wire::CLIENT_OPEN_SEAT,
                payload: Vec::new(),
            },
            done,
        })
        .unwrap();
    let (reply, mut activation) = oneshot::channel();
    controller.mutate(context, true, reply, false);
    controller.drive().unwrap();
    let completion = controller.jobs.join_next().await.unwrap().unwrap();
    controller.complete(completion);
    controller.drive().unwrap();
    assert!(controller.transition.as_ref().unwrap().enabling);
    let late = controller.create_connection(context).unwrap();
    let late_id = late.id();
    let _late_fd = late.publish(|_, fd| Ok(fd)).unwrap();
    if fail_delivery {
        for _ in 0..31 {
            assert!(controller.send(late_id, wire::empty(wire::SERVER_PONG), None));
        }
    }
    let (done, _) = oneshot::channel();
    controller
        .packet(connection::Request {
            connection: late_id,
            packet: wire::Packet {
                opcode: wire::CLIENT_OPEN_SEAT,
                payload: Vec::new(),
            },
            done,
        })
        .unwrap();
    let transition = controller.transition.as_mut().unwrap();
    assert!(transition.pending_enable.contains(&late_id));
    transition.pending_enable.remove(&first_id);
    if fail_delivery {
        assert_eq!(transition.failure, Some(ErrorKind::BackendFailure));
        controller.drive().unwrap();
        assert!(controller.selected.is_none());
        assert!(controller.effective.is_none());
        assert!(
            !controller.contexts[&context]
                .epoch
                .as_ref()
                .unwrap()
                .is_open()
        );
        assert!(activation.try_recv().is_err());
    } else {
        controller.drive().unwrap();
        assert!(
            activation.try_recv().is_err(),
            "late enable has not been delivered"
        );
        controller
            .transition
            .as_mut()
            .unwrap()
            .pending_enable
            .remove(&late_id);
        controller.drive().unwrap();
        assert_eq!(activation.try_recv().unwrap(), Ok(()));
    }
}

#[tokio::test]
async fn late_membership_must_join_the_initial_enable_delivery_barrier() {
    late_join_delivery_case(false).await;
}

#[tokio::test]
async fn late_enable_delivery_failure_fences_and_unwinds_initial_activation() {
    late_join_delivery_case(true).await;
}

mod access_tests;
#[cfg(feature = "test-support")]
mod broker_tests;
mod terminal_tests;
