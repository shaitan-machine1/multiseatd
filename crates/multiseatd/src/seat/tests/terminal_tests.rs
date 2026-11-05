use super::*;
use crate::vt::{
    Owner, Phase,
    tests::{State, owner, phase},
};
use std::sync::atomic::Ordering;

async fn fixture(foreground: u32) -> (Harness, Owner, Arc<State>) {
    let name: SeatName = "seat-test".parse().unwrap();
    let mut registry = Registry::new(Limits::default()).unwrap();
    registry.add_seat(name.clone()).unwrap();
    let resources = Arc::new(Resources::new(64, 64).unwrap());
    let (owner, state) = owner(resources.clone(), foreground).await;
    let budget = Budget::default();
    let mut tasks = CriticalTasks::new(8).unwrap();
    let (mut controller, port) = Controller::new(name.clone(), resources.clone(), budget.clone());
    controller.attach_vt(owner.port());
    tasks
        .spawn(
            crate::daemon::CriticalRole::Seat(name),
            controller.run(tasks.subscribe()),
        )
        .unwrap();
    (
        Harness {
            registry,
            port,
            tasks,
            authorities: Vec::new(),
            resources: resources.clone(),
            budget,
            _cleanup: crate::resources::CleanupGuard(resources),
        },
        owner,
        state,
    )
}

#[tokio::test]
async fn failed_device_revocation_blocks_kernel_release_even_after_disable_ack() {
    let (mut harness, mut owner, state) = fixture(7).await;
    let context = harness.context().await;
    let mut peer = harness.peer(context).await;
    peer.open().await;
    harness.activate(context).await;
    peer.expect(wire::SERVER_ENABLE_SEAT).await;
    let failure = Arc::new(AtomicBool::new(true));
    let _client_fd = attach_device(
        &harness,
        peer.resource_owner,
        false,
        failure.clone(),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicUsize::new(0)),
    );
    state.release(&owner.port());
    peer.expect(wire::SERVER_DISABLE_SEAT).await;
    peer.acknowledge().await;
    harness
        .wait(|status| !status.contexts[&context].7.is_empty())
        .await;
    assert!(!state.contains("release"));
    failure.store(false, Ordering::Release);
    phase(&owner.port(), Phase::Away).await;
    harness.finish().await;
    owner.finish().unwrap();
}

#[tokio::test]
async fn protocol_switch_requires_an_enabled_effective_connection() {
    let (mut harness, mut owner, state) = fixture(7).await;
    let context = harness.context().await;
    let mut peer = harness.peer(context).await;
    peer.open().await;
    peer.stream
        .write_all(&wire::packet(wire::CLIENT_SWITCH_SESSION, &2i32.to_ne_bytes()).unwrap())
        .await
        .unwrap();
    let denied = peer.receive().await.unwrap();
    assert_eq!(denied.opcode, wire::SERVER_ERROR);
    assert_eq!(wire::parse_i32(&denied.payload).unwrap(), libc::EACCES);
    assert!(!state.contains("switch-2"));
    harness.activate(context).await;
    peer.expect(wire::SERVER_ENABLE_SEAT).await;
    peer.stream
        .write_all(&wire::packet(wire::CLIENT_SWITCH_SESSION, &2i32.to_ne_bytes()).unwrap())
        .await
        .unwrap();
    peer.expect(wire::SERVER_SESSION_SWITCHED).await;
    assert!(state.contains("switch-2"));
    harness.finish().await;
    owner.finish().unwrap();
}

#[tokio::test]
async fn already_foreground_context_handover_and_reactivation_never_tour_terminals() {
    let (mut harness, mut owner, state) = fixture(7).await;
    let a = harness.context().await;
    let greeter = harness.context().await;
    let b = harness.context().await;
    harness.activate(a).await;
    harness.activate(greeter).await;
    harness.activate(b).await;
    harness.deactivate(a).await;
    assert_eq!(harness.port.status.borrow().seat.4, b.to_string());
    harness.deactivate(b).await;
    harness
        .wait(|status| status.seat.2 && status.seat.4.is_empty())
        .await;
    harness.activate(b).await;
    assert!(!state.contains("switch-7"));
    assert_eq!(harness.port.status.borrow().seat.1, 7);
    harness.finish().await;
    owner.finish().unwrap();
}

#[tokio::test]
async fn release_waits_for_every_ack_and_returns_only_the_current_selection() {
    let (mut harness, mut owner, state) = fixture(7).await;
    let context = harness.context().await;
    let mut first = harness.peer(context).await;
    let mut sibling = harness.peer(context).await;
    first.open().await;
    sibling.open().await;
    harness.activate(context).await;
    first.expect(wire::SERVER_ENABLE_SEAT).await;
    sibling.expect(wire::SERVER_ENABLE_SEAT).await;
    state.release(&owner.port());
    first.expect(wire::SERVER_DISABLE_SEAT).await;
    sibling.expect(wire::SERVER_DISABLE_SEAT).await;
    first.acknowledge().await;
    assert!(!state.contains("release"));
    sibling.acknowledge().await;
    phase(&owner.port(), Phase::Away).await;
    harness
        .wait(|status| !status.seat.2 && status.seat.4.is_empty())
        .await;
    assert_eq!(harness.port.status.borrow().seat.3, context.to_string());
    state.acquire(&owner.port());
    first.expect(wire::SERVER_ENABLE_SEAT).await;
    sibling.expect(wire::SERVER_ENABLE_SEAT).await;
    harness.finish().await;
    owner.finish().unwrap();
}

#[tokio::test]
async fn deactivation_while_away_prevents_foreground_observation_from_resurrecting_context() {
    let (mut harness, mut owner, state) = fixture(7).await;
    let context = harness.context().await;
    harness.activate(context).await;
    state.release(&owner.port());
    phase(&owner.port(), Phase::Away).await;
    harness.deactivate(context).await;
    state.acquire(&owner.port());
    harness
        .wait(|status| status.seat.2 && status.seat.3.is_empty() && status.seat.4.is_empty())
        .await;
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(!harness.port.status.borrow().contexts[&context].6);
    harness.finish().await;
    owner.finish().unwrap();
}

#[tokio::test]
async fn changing_selection_while_away_supersedes_old_acquisition_without_enabling_old_context() {
    let (mut harness, mut owner, state) = fixture(7).await;
    let a = harness.context().await;
    let b = harness.context().await;
    let c = harness.context().await;
    harness.activate(a).await;
    state.release(&owner.port());
    phase(&owner.port(), Phase::Away).await;
    let b_wait = harness.mutation(b, true);
    harness.wait(|status| status.seat.3 == b.to_string()).await;
    let c_wait = harness.mutation(c, true);
    harness.wait(|status| status.seat.3 == c.to_string()).await;
    assert_eq!(b_wait.await.unwrap(), Err(ErrorKind::TransitionPending));
    state.acquire(&owner.port());
    timeout(Duration::from_secs(4), c_wait)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(harness.port.status.borrow().seat.4, c.to_string());
    assert!(!harness.port.status.borrow().contexts[&b].6);
    assert!(!harness.port.status.borrow().contexts[&a].6);
    harness.finish().await;
    owner.finish().unwrap();
}

#[tokio::test]
async fn already_background_activation_waits_for_real_acquire_not_successful_switch_ioctl() {
    let (mut harness, mut owner, state) = fixture(1).await;
    let context = harness.context().await;
    let mut activation = harness.mutation(context, true);
    phase(&owner.port(), Phase::Acquiring).await;
    assert!(activation.try_recv().is_err());
    assert!(state.contains("switch-7"));
    state.foreground.store(7, Ordering::Release);
    state.acquire(&owner.port());
    timeout(Duration::from_secs(4), activation)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    harness.finish().await;
    owner.finish().unwrap();
}
