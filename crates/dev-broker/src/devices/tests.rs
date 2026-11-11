use super::*;
use std::os::unix::fs::MetadataExt;
fn device() -> AllowedDevice {
    AllowedDevice::canonicalized(
        crate::device::DeviceId::new("fixture"),
        "/dev/null",
        std::fs::metadata("/dev/null").unwrap().rdev(),
        DeviceKind::Evdev,
    )
    .unwrap()
}
fn fixture(limit: usize) -> Devices<u32> {
    Devices::new(
        Arc::new(Resources::new(32).unwrap()),
        Arc::new(Semaphore::new(4)),
        Arc::new(Semaphore::new(16)),
        limit,
    )
}
fn start() -> oneshot::Receiver<()> {
    let (sender, receiver) = oneshot::channel();
    sender.send(()).unwrap();
    receiver
}
#[cfg(feature = "test-support")]
fn admission() -> Option<(AllowedDevice, Permit)> {
    Some((device(), Permit::new()))
}
fn acknowledge<K>(mut reply: Reply<K>) -> Output {
    if let Some(done) = reply.done.take() {
        let _ = done.send(());
    }
    reply.output.take().unwrap()
}
fn opcode(output: &Output) -> u16 {
    u16::from_ne_bytes(output.bytes[..2].try_into().unwrap())
}
#[test]
fn bounded_registration_and_reused_correlation_have_different_owners() {
    let mut devices = fixture(2);
    let first = devices.register(7).unwrap();
    assert!(devices.register(7).is_err());
    devices.register(8).unwrap();
    assert!(devices.register(9).is_err());
    devices.forget(7).unwrap();
    assert_ne!(first, devices.register(7).unwrap());
}
#[test]
fn retained_original_outside_a_slot_still_prevents_forgetting_its_owner() {
    let mut devices = fixture(1);
    let owner = devices.register(7).unwrap();
    let handle = devices.resources.reserve(owner, device()).unwrap();
    assert!(devices.forget(7).is_err());
    devices.resources.close(handle).unwrap();
    devices.forget(7).unwrap();
}
#[test]
fn fenced_or_unpublished_paths_never_start_kernel_work() {
    let mut devices = fixture(1);
    devices.register(7).unwrap();
    let permit = Permit::new();
    permit.fence();
    // Exact path lookup is now the caller's catalog responsibility. A failed
    // lookup supplies no admission, never a path for this broker to authorize.
    for admission in [Some((device(), permit)), None] {
        let (done, _) = oneshot::channel();
        let reply = devices.open(7, admission, start(), false, done).unwrap();
        assert_eq!(opcode(&acknowledge(reply)), wire::SERVER_ERROR);
        assert!(!devices.has_jobs());
        assert!(!devices.pending(7));
    }
}
#[cfg(feature = "test-support")]
async fn open(devices: &mut Devices<u32>, key: u32) -> Output {
    let (done, receiver) = oneshot::channel();
    assert!(
        devices
            .open(key, admission(), start(), true, done)
            .is_none()
    );
    let output = acknowledge(devices.next_completion().await.unwrap());
    receiver.await.unwrap();
    assert_eq!(opcode(&output), wire::SERVER_DEVICE_OPENED);
    output
}
#[cfg(feature = "test-support")]
#[tokio::test]
async fn outstanding_open_fences_forget_and_parallel_slot_allocation() {
    let mut devices = fixture(1);
    devices.register(7).unwrap();
    let (done, receiver) = oneshot::channel();
    assert!(devices.open(7, admission(), start(), true, done).is_none());
    assert!(devices.forget(7).is_err());
    let (other, _) = oneshot::channel();
    let denied = devices.open(7, admission(), start(), true, other).unwrap();
    assert_eq!(opcode(&acknowledge(denied)), wire::SERVER_ERROR);
    acknowledge(devices.next_completion().await.unwrap());
    receiver.await.unwrap();
    assert_eq!(devices.connections[&7].slots.len(), 1);
    let owner = devices.owner(7).unwrap();
    devices.begin_cleanup(7);
    assert!(devices.resources.close_owner(owner).is_empty());
    devices.cleaned(7);
    devices.forget(7).unwrap();
}
#[cfg(feature = "test-support")]
#[tokio::test]
async fn protocol_close_joins_started_retirement_and_still_replies() {
    let mut devices = fixture(1);
    devices.register(7).unwrap();
    let output = open(&mut devices, 7).await;
    let number = i32::from_ne_bytes(output.bytes[4..8].try_into().unwrap());
    drop(output);
    devices.retire_inputs(7);
    devices.settle_retired();
    assert!(devices.connections[&7].slots[&number].running);
    let (done, receiver) = oneshot::channel();
    assert!(devices.close(7, number, done).is_none());
    assert_eq!(devices.jobs.len(), 1);
    assert_eq!(
        opcode(&acknowledge(devices.next_completion().await.unwrap())),
        wire::SERVER_DEVICE_CLOSED
    );
    receiver.await.unwrap();
    assert!(!devices.pending(7));
    devices.forget(7).unwrap();
}
#[cfg(feature = "test-support")]
#[tokio::test]
async fn duplicate_open_reuses_slot_until_last_close_then_allocates_fresh_slot() {
    let mut devices = fixture(1);
    devices.register(7).unwrap();
    let first = open(&mut devices, 7).await;
    let second = open(&mut devices, 7).await;
    assert_eq!(first.bytes, second.bytes);
    let number = i32::from_ne_bytes(first.bytes[4..8].try_into().unwrap());
    drop((first, second));
    for _ in 0..2 {
        let (done, receiver) = oneshot::channel();
        let reply = match devices.close(7, number, done) {
            Some(reply) => reply,
            None => devices.next_completion().await.unwrap(),
        };
        assert_eq!(opcode(&acknowledge(reply)), wire::SERVER_DEVICE_CLOSED);
        receiver.await.unwrap();
    }
    let third = open(&mut devices, 7).await;
    assert_ne!(
        i32::from_ne_bytes(third.bytes[4..8].try_into().unwrap()),
        number
    );
    drop(third);
    let owner = devices.owner(7).unwrap();
    devices.begin_cleanup(7);
    assert!(devices.resources.close_owner(owner).is_empty());
    devices.cleaned(7);
    devices.forget(7).unwrap();
}
#[cfg(feature = "test-support")]
#[tokio::test]
async fn registered_work_is_visible_but_cannot_enter_kernel_before_guard_release() {
    let mut devices = fixture(1);
    devices.register(7).unwrap();
    let (release, wait) = oneshot::channel();
    let (done, _) = oneshot::channel();
    assert!(devices.open(7, admission(), wait, true, done).is_none());
    assert!(devices.running(7));
    assert!(devices.forget(7).is_err());
    tokio::task::yield_now().await;
    assert_eq!(devices.resources.pending(), 0);
    release.send(()).unwrap();
    let output = acknowledge(devices.next_completion().await.unwrap());
    assert_eq!(opcode(&output), wire::SERVER_DEVICE_OPENED);
    drop(output);
    let owner = devices.owner(7).unwrap();
    devices.begin_cleanup(7);
    assert!(devices.resources.close_owner(owner).is_empty());
    devices.cleaned(7);
    devices.forget(7).unwrap();
}
