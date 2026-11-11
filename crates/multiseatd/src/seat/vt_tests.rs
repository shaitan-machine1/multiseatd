//! Mechanical fixtures only; these tests make no native-kernel acceptance claim.
use super::*;
use std::os::fd::AsFd;
use std::sync::atomic::Ordering;
use std::time::Duration;
struct Fixture {
    seat: Seat,
    discovery: discovery::Owner,
    terminal: linux_vt::Owner,
    mechanics: linux_vt::Fixture,
    driver: tokio::task::JoinHandle<io::Result<()>>,
    _file: tempfile::NamedTempFile,
}
impl Fixture {
    async fn new() -> Self {
        let file = tempfile::NamedTempFile::new().unwrap();
        let workers = Arc::new(Semaphore::new(2));
        let resources = Arc::new(dev_broker::resources::Resources::new(128).unwrap());
        let (driver, control, _events) =
            broker::Broker::new("seat-vt-test".into(), false, resources, workers.clone());
        let fatal = Fatal::new(control.clone());
        let discovery = discovery::Owner::start(
            Some(discovery::Fixture {
                seat: SeatName::parse("seat-vt-test").unwrap(),
                direct_nodes: vec![file.path().into()],
                null_device: false,
                assignments: None,
            }),
            fatal.clone(),
        )
        .unwrap();
        let vts = BTreeSet::from([7, 8]);
        let (terminal, mechanics) = linux_vt::Owner::synthetic(vts.clone(), 7).unwrap();
        let seat = Seat::new(
            SeatName::parse("seat-vt-test").unwrap(),
            control,
            discovery.control(),
            fatal,
            workers,
            terminal.control(),
            vts,
        )
        .unwrap();
        let driver = tokio::spawn(driver.run());
        seat.initialize().await.unwrap();
        Self {
            seat,
            discovery,
            terminal,
            mechanics,
            driver,
            _file: file,
        }
    }
    async fn finish(mut self) {
        self.seat.fatal.stop();
        let (settled, errors) = self.seat.cleanup().await;
        assert!(settled && errors.is_empty());
        self.driver.await.unwrap().unwrap();
        self.discovery.control().stop().unwrap();
        self.terminal.control().shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !self.discovery.join_if_finished().unwrap()
                || !self.terminal.join_if_finished().unwrap()
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(self.mechanics.restored.load(Ordering::Acquire), 2);
    }
}
#[tokio::test]
async fn independent_immutable_bindings_and_root_foreground_barrier() {
    let mut h = Fixture::new().await;
    assert_eq!(
        h.seat
            .create_context(0, Budget::new())
            .await
            .unwrap_err()
            .kind,
        ErrorKind::InvalidArgument
    );
    assert_eq!(
        h.seat
            .create_context(9, Budget::new())
            .await
            .unwrap_err()
            .kind,
        ErrorKind::InvalidArgument
    );
    let (a, aid) = h.seat.create_context(7, Budget::new()).await.unwrap();
    let (b, bid) = h.seat.create_context(8, Budget::new()).await.unwrap();
    let (_c, cid) = h.seat.create_context(7, Budget::new()).await.unwrap();
    h.seat
        .set_grant(a.as_fd(), 424242, true, Budget::new())
        .await
        .unwrap();
    h.seat
        .set_grant(b.as_fd(), 424243, true, Budget::new())
        .await
        .unwrap();
    h.seat.activate_context(aid, Budget::new()).await.unwrap();
    h.seat.activate_context(bid, Budget::new()).await.unwrap();
    for id in [aid, cid] {
        assert_eq!(
            h.seat
                .activate_context(id, Budget::new())
                .await
                .unwrap_err()
                .kind,
            ErrorKind::Busy
        );
    }
    let background = h.seat.get_context(b.as_fd(), Budget::new()).await.unwrap();
    assert!(background.active && !background.foreground && !background.effective);
    assert_eq!(
        h.seat.state.read().await.acl.desired_users(),
        &BTreeSet::from([424242])
    );
    assert_eq!(h.mechanics.restored.load(Ordering::Acquire), 0);
    let notices = h.terminal.take_notices().unwrap();
    let mut slot = None;
    {
        let source = crate::sources::run_vt(&h.seat, notices, &mut slot);
        tokio::pin!(source);
        tokio::select! {
            result = h.seat.move_to_foreground(bid, Budget::new()) => result.unwrap(),
            result = &mut source => panic!("notice source ended: {result:?}"),
        }
    }
    assert!(slot.is_none());
    drop(slot);
    let first = h.seat.get_context(a.as_fd(), Budget::new()).await.unwrap();
    let second = h.seat.get_context(b.as_fd(), Budget::new()).await.unwrap();
    assert!(first.active && !first.foreground && !first.effective);
    assert!(second.active && second.foreground && second.effective);
    assert_eq!(
        h.seat.state.read().await.acl.desired_users(),
        &BTreeSet::from([424243])
    );
    let releases = h.mechanics.release_calls.load(Ordering::Acquire);
    h.seat.move_to_foreground(bid, Budget::new()).await.unwrap();
    assert_eq!(h.mechanics.release_calls.load(Ordering::Acquire), releases);
    h.seat.deactivate_context(aid, Budget::new()).await.unwrap();
    assert!(
        h.seat
            .get_context(b.as_fd(), Budget::new())
            .await
            .unwrap()
            .effective
    );
    assert_eq!(h.mechanics.current.load(Ordering::Acquire), 8);
    assert_eq!(h.mechanics.restored.load(Ordering::Acquire), 0);
    h.finish().await;
}
#[tokio::test]
async fn authority_loss_does_not_choose_background_context_and_empty_vt_still_releases() {
    let h = Fixture::new().await;
    let (a, aid) = h.seat.create_context(7, Budget::new()).await.unwrap();
    let (b, bid) = h.seat.create_context(8, Budget::new()).await.unwrap();
    h.seat.activate_context(aid, Budget::new()).await.unwrap();
    h.seat.activate_context(bid, Budget::new()).await.unwrap();
    h.terminal.control().request_switch(8).await.unwrap();
    h.seat.release_requested().await.unwrap();
    h.seat.foreground_observed().await.unwrap();
    drop(b);
    h.seat.prune_authorities().await.unwrap();
    let background = h.seat.get_context(a.as_fd(), Budget::new()).await.unwrap();
    assert!(background.active && !background.effective && !background.foreground);
    assert_eq!(h.mechanics.current.load(Ordering::Acquire), 8);
    let releases = h.mechanics.release_calls.load(Ordering::Acquire);
    h.terminal.control().request_switch(1).await.unwrap();
    h.seat.release_requested().await.unwrap();
    assert_eq!(
        h.mechanics.release_calls.load(Ordering::Acquire),
        releases + 1
    );
    assert_eq!(h.mechanics.current.load(Ordering::Acquire), 1);
    // A stale, empty/unowned release still goes through the native abstraction.
    h.seat.release_requested().await.unwrap();
    assert_eq!(
        h.mechanics.release_calls.load(Ordering::Acquire),
        releases + 2
    );
    h.finish().await;
}
#[tokio::test]
async fn acquisition_revalidates_current_after_state_admission_and_ack_is_noop() {
    let h = Fixture::new().await;
    let (_a, aid) = h.seat.create_context(7, Budget::new()).await.unwrap();
    let (_b, bid) = h.seat.create_context(8, Budget::new()).await.unwrap();
    h.seat.activate_context(aid, Budget::new()).await.unwrap();
    h.seat.activate_context(bid, Budget::new()).await.unwrap();
    let held = h.seat.state.write().await;
    let before = h.mechanics.foreground_calls.load(Ordering::Acquire);
    let mut acquisition = Box::pin(h.seat.foreground_observed());
    assert!(
        tokio::time::timeout(Duration::from_millis(5), acquisition.as_mut())
            .await
            .is_err()
    );
    assert_eq!(h.mechanics.foreground_calls.load(Ordering::Acquire), before);
    h.mechanics.current.store(8, Ordering::Release);
    drop(held);
    acquisition.await.unwrap();
    assert_eq!(h.mechanics.release_calls.load(Ordering::Acquire), 0);
    let rows = h.seat.list_contexts(Budget::new()).await.unwrap();
    assert!(rows.iter().find(|row| row.id == bid).unwrap().effective);
    assert!(!rows.iter().find(|row| row.id == aid).unwrap().effective);
    h.finish().await;
}
#[tokio::test]
async fn native_release_error_is_fatal_after_withdrawal_not_a_failed_context_barrier() {
    let h = Fixture::new().await;
    let (_a, aid) = h.seat.create_context(7, Budget::new()).await.unwrap();
    h.seat.activate_context(aid, Budget::new()).await.unwrap();
    h.mechanics.fail_release.store(true, Ordering::Release);
    assert_eq!(
        h.seat.release_requested().await.unwrap_err().kind,
        ErrorKind::CriticalFailure
    );
    assert!(h.seat.fatal.failed());
    assert!(h.seat.state.try_read().unwrap().applied.is_none());
    assert!(
        h.seat
            .state
            .try_read()
            .unwrap()
            .acl
            .desired_users()
            .is_empty()
    );
    h.finish().await;
}
