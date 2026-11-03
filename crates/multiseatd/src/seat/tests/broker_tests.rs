use super::*;
use crate::device::{AllowedDevice, DeviceId, DeviceKind};
use crate::seat::policy::Policy;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;

impl Peer {
    async fn open_device(&mut self, path: &str) -> (wire::Packet, Option<OwnedFd>) {
        let mut payload = ((path.len() + 1) as u16).to_ne_bytes().to_vec();
        payload.extend_from_slice(path.as_bytes());
        payload.push(0);
        self.stream
            .write_all(&wire::packet(wire::CLIENT_OPEN_DEVICE, &payload).unwrap())
            .await
            .unwrap();
        let mut receiver = crate::seatd::transport::Connection::new(
            self.stream.as_fd().try_clone_to_owned().unwrap(),
        )
        .unwrap();
        timeout(Duration::from_secs(4), async {
            loop {
                receiver.read().unwrap();
                if let Some(packet) = receiver.next_packet().unwrap() {
                    return (packet, receiver.take_received_fd());
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap()
    }
    async fn close_device(&mut self, id: i32) {
        self.stream
            .write_all(&wire::packet(wire::CLIENT_CLOSE_DEVICE, &id.to_ne_bytes()).unwrap())
            .await
            .unwrap();
        self.expect(wire::SERVER_DEVICE_CLOSED).await;
    }
}
#[tokio::test]
async fn removing_a_context_cannot_erase_its_started_open_barrier() {
    use std::sync::{Condvar, Mutex};
    let mut harness = Harness::new();
    harness.configure(null_policy()).await;
    let a = harness.context().await;
    let b = harness.context().await;
    harness.activate(a).await;
    let mut peer = harness.peer(a).await;
    peer.open().await;
    peer.expect(wire::SERVER_ENABLE_SEAT).await;
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_gate = gate.clone();
    let (entered, waiting) = oneshot::channel();
    let entered = Mutex::new(Some(entered));
    harness.resources.set_open_hook(Some(Arc::new(move || {
        if let Some(sender) = entered.lock().unwrap().take() {
            let _ = sender.send(());
        }
        let (mutex, condition) = &*worker_gate;
        let mut released = mutex.lock().unwrap();
        while !*released {
            released = condition.wait(released).unwrap();
        }
    })));
    let mut payload = 10u16.to_ne_bytes().to_vec();
    payload.extend_from_slice(b"/dev/null\0");
    peer.stream
        .write_all(&wire::packet(wire::CLIENT_OPEN_DEVICE, &payload).unwrap())
        .await
        .unwrap();
    waiting.await.unwrap();
    harness.registry.remove(a);
    let (reply, removing) = oneshot::channel();
    harness
        .port
        .send(Command::Remove { context: a, reply })
        .unwrap();
    let mut activating = harness.mutation(b, true);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(
        activating.try_recv().is_err(),
        "logical removal must not erase started resource work"
    );
    assert!(
        peer.receive().await.is_err(),
        "no late device descriptor may escape"
    );
    {
        let (mutex, condition) = &*gate;
        *mutex.lock().unwrap() = true;
        condition.notify_all();
    }
    harness.resources.set_open_hook(None);
    timeout(Duration::from_secs(4), activating)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    removing.await.unwrap().unwrap();
    harness.registry.complete_removal(a);
    harness.finish().await;
}

fn null_policy() -> Policy {
    let device = AllowedDevice::canonicalized(
        DeviceId::new("test-only:null"),
        "/dev/null",
        std::fs::metadata("/dev/null").unwrap().rdev(),
        DeviceKind::Evdev,
    )
    .unwrap();
    Policy {
        synthetic: true,
        devices: Arc::new(BTreeMap::from([(device.path.clone(), device)])),
        ..Policy::default()
    }
}

#[tokio::test]
async fn parallel_input_descriptions_are_independent_but_duplicate_opens_share_one_record() {
    let mut harness = Harness::new();
    harness.configure(null_policy()).await;
    let context = harness.context().await;
    harness.activate(context).await;
    let mut first = harness.peer(context).await;
    let mut second = harness.peer(context).await;
    first.open().await;
    first.expect(wire::SERVER_ENABLE_SEAT).await;
    second.open().await;
    second.expect(wire::SERVER_ENABLE_SEAT).await;
    let (one, one_fd) = first.open_device("/dev/null").await;
    assert_eq!(one.opcode, wire::SERVER_DEVICE_OPENED);
    let one_fd = one_fd.unwrap();
    let (two, two_fd) = second.open_device("/dev/null").await;
    assert_eq!(two.opcode, wire::SERVER_DEVICE_OPENED);
    let two_fd = two_fd.unwrap();
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    let flags = fcntl(&one_fd, FcntlArg::F_GETFL).unwrap();
    fcntl(
        &one_fd,
        FcntlArg::F_SETFL(OFlag::from_bits_retain(flags | libc::O_APPEND)),
    )
    .unwrap();
    assert_eq!(
        fcntl(&two_fd, FcntlArg::F_GETFL).unwrap() & libc::O_APPEND,
        0
    );
    let (duplicate, duplicate_fd) = first.open_device("/dev/null").await;
    assert_eq!(duplicate.payload, one.payload);
    assert_ne!(
        fcntl(duplicate_fd.unwrap(), FcntlArg::F_GETFL).unwrap() & libc::O_APPEND,
        0
    );
    first
        .close_device(wire::parse_i32(&one.payload).unwrap())
        .await;
    first
        .close_device(wire::parse_i32(&one.payload).unwrap())
        .await;
    second
        .close_device(wire::parse_i32(&two.payload).unwrap())
        .await;
    harness.finish().await;
}

#[tokio::test]
async fn revoked_input_records_are_not_reopened_after_resume() {
    let mut harness = Harness::new();
    harness.configure(null_policy()).await;
    let context = harness.context().await;
    harness.activate(context).await;
    let mut peer = harness.peer(context).await;
    peer.open().await;
    peer.expect(wire::SERVER_ENABLE_SEAT).await;
    let (old, _old_fd) = peer.open_device("/dev/null").await;
    assert_eq!(old.opcode, wire::SERVER_DEVICE_OPENED);
    let deactivating = harness.mutation(context, false);
    peer.expect(wire::SERVER_DISABLE_SEAT).await;
    peer.acknowledge().await;
    deactivating.await.unwrap().unwrap();
    harness.activate(context).await;
    peer.expect(wire::SERVER_ENABLE_SEAT).await;
    let (fresh, _fresh_fd) = peer.open_device("/dev/null").await;
    assert_eq!(fresh.opcode, wire::SERVER_DEVICE_OPENED);
    assert_ne!(old.payload, fresh.payload);
    peer.close_device(wire::parse_i32(&old.payload).unwrap())
        .await;
    peer.close_device(wire::parse_i32(&fresh.payload).unwrap())
        .await;
    harness.finish().await;
}

#[tokio::test]
async fn inactive_and_unassigned_device_paths_never_return_descriptors() {
    let mut harness = Harness::new();
    harness.configure(null_policy()).await;
    let context = harness.context().await;
    let mut peer = harness.peer(context).await;
    peer.open().await;
    let (packet, fd) = peer.open_device("/dev/null").await;
    assert_eq!(packet.opcode, wire::SERVER_ERROR);
    assert!(fd.is_none());
    harness.activate(context).await;
    peer.expect(wire::SERVER_ENABLE_SEAT).await;
    let (packet, fd) = peer.open_device("/dev/zero").await;
    assert_eq!(packet.opcode, wire::SERVER_ERROR);
    assert!(fd.is_none());
    assert_eq!(wire::parse_i32(&packet.payload).unwrap(), libc::EACCES);
    harness.finish().await;
}
