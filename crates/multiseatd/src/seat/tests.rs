use super::*;
use futures_util::FutureExt;
use std::os::fd::AsFd;
use std::panic::AssertUnwindSafe;
use std::time::Duration;

struct Fixture {
    seat: Seat,
    owner: discovery::Owner,
    driver: tokio::task::JoinHandle<io::Result<()>>,
    workers: Arc<Semaphore>,
    _file: tempfile::NamedTempFile,
}
impl Fixture {
    async fn new() -> Self {
        let file = tempfile::NamedTempFile::new().unwrap();
        let workers = Arc::new(Semaphore::new(1));
        let resources = Arc::new(dev_broker::resources::Resources::new(128).unwrap());
        let (driver, control, _events) =
            broker::Broker::new("seat-test".into(), false, resources, workers.clone());
        let fatal = Fatal::new(control.clone());
        let owner = discovery::Owner::start(
            Some(discovery::Fixture {
                seat: SeatName::parse("seat-test").unwrap(),
                direct_nodes: vec![file.path().into()],
                null_device: false,
                assignments: None,
            }),
            fatal.clone(),
        )
        .unwrap();
        let seat = Seat::new(
            SeatName::parse("seat-test").unwrap(),
            control,
            owner.control(),
            fatal,
            workers.clone(),
        )
        .unwrap();
        let driver = tokio::spawn(driver.run());
        seat.initialize().await.unwrap();
        Self {
            seat,
            owner,
            driver,
            workers,
            _file: file,
        }
    }
    async fn finish(mut self) {
        self.seat.fatal.stop();
        let (settled, errors) = self.seat.cleanup().await;
        assert!(settled && errors.is_empty());
        self.driver.await.unwrap().unwrap();
        self.owner.control().stop().unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !self.owner.join_if_finished().unwrap() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }
}
#[tokio::test]
async fn exact_master_lookup_is_ambiguous_and_dead_lookup_is_read_only() {
    use std::os::fd::FromRawFd;
    let h = Fixture::new().await;
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) as i32 };
    assert!(raw >= 0);
    let master = crate::master::Master::acquire(unsafe { OwnedFd::from_raw_fd(raw) }).unwrap();
    let (a, id) = h
        .seat
        .create_context_for_master(0, master.clone(), Budget::new())
        .await
        .unwrap();
    let delegate = a.try_clone().unwrap();
    assert_eq!(
        h.seat
            .get_context_by_master_pid(master.pid, master.start_time, Budget::new())
            .await
            .unwrap()
            .id,
        id
    );
    let (b, second) = h
        .seat
        .create_context_for_master(0, master.clone(), Budget::new())
        .await
        .unwrap();
    assert_eq!(
        h.seat
            .get_context_by_master_pid(master.pid, master.start_time, Budget::new())
            .await
            .unwrap_err()
            .kind,
        ErrorKind::AmbiguousContext
    );
    h.seat
        .remove_context_by_id(second, Budget::new())
        .await
        .unwrap();
    drop(b);
    h.seat.activate_context(id, Budget::new()).await.unwrap();
    let revision = *h.seat.changes().borrow();
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(
        h.seat
            .get_context_by_master_pid(master.pid, master.start_time, Budget::new())
            .await
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
    assert_eq!(*h.seat.changes().borrow(), revision);
    assert!(!h.seat.list_contexts(Budget::new()).await.unwrap()[0].effective);
    assert!(
        h.seat
            .create_connection(delegate.as_fd(), Budget::new())
            .await
            .is_err()
    );
    assert_eq!(h.seat.state.read().await.contexts.len(), 1);
    h.seat.master_exited(id).await.unwrap();
    assert!(
        h.seat
            .list_contexts(Budget::new())
            .await
            .unwrap()
            .is_empty()
    );
    drop((a, delegate));
    h.finish().await;
}
#[tokio::test]
async fn occupied_activation_rejects_before_effects_and_never_replaces() {
    let h = Fixture::new().await;
    let (a, first) = h.seat.create_context(0, Budget::new()).await.unwrap();
    let (_b, second) = h.seat.create_context(0, Budget::new()).await.unwrap();
    h.seat
        .set_grant(a.as_fd(), 424242, true, Budget::new())
        .await
        .unwrap();
    h.seat.activate_context(first, Budget::new()).await.unwrap();
    for id in [first, second] {
        assert_eq!(
            h.seat
                .activate_context(id, Budget::new())
                .await
                .unwrap_err()
                .kind,
            ErrorKind::Busy
        );
    }
    let rows = h.seat.list_contexts(Budget::new()).await.unwrap();
    assert!(rows.iter().find(|row| row.id == first).unwrap().effective);
    assert!(!rows.iter().find(|row| row.id == second).unwrap().active);
    h.seat
        .deactivate_context(first, Budget::new())
        .await
        .unwrap();
    h.seat
        .activate_context(second, Budget::new())
        .await
        .unwrap();
    assert!(
        !h.seat
            .get_context(a.as_fd(), Budget::new())
            .await
            .unwrap()
            .active
    );
    h.finish().await;
}
#[tokio::test]
async fn inactive_grants_do_not_union_with_the_current_acl_target() {
    let h = Fixture::new().await;
    let (a, first) = h.seat.create_context(0, Budget::new()).await.unwrap();
    let (b, _second) = h.seat.create_context(0, Budget::new()).await.unwrap();
    h.seat
        .set_grant(a.as_fd(), 424242, true, Budget::new())
        .await
        .unwrap();
    h.seat.activate_context(first, Budget::new()).await.unwrap();
    h.seat
        .set_grant(b.as_fd(), 424243, true, Budget::new())
        .await
        .unwrap();
    h.seat
        .set_grant(b.as_fd(), 424242, true, Budget::new())
        .await
        .unwrap();
    h.seat
        .set_grant(b.as_fd(), 424242, false, Budget::new())
        .await
        .unwrap();
    assert_eq!(
        h.seat.state.read().await.acl.desired_users(),
        &BTreeSet::from([424242])
    );
    assert_eq!(
        h.seat
            .get_context(b.as_fd(), Budget::new())
            .await
            .unwrap()
            .desired_uids,
        vec![424243]
    );
    h.finish().await;
}
#[tokio::test]
async fn one_guard_excludes_queries_during_real_acl_worker_queue_wait() {
    let h = Fixture::new().await;
    let (authority, id) = h.seat.create_context(0, Budget::new()).await.unwrap();
    h.seat
        .set_grant(authority.as_fd(), 424242, true, Budget::new())
        .await
        .unwrap();
    let quota = h.workers.acquire().await.unwrap();
    let mut activation = Box::pin(h.seat.activate_context(id, Budget::new()));
    assert!(
        tokio::time::timeout(Duration::from_millis(5), activation.as_mut())
            .await
            .is_err()
    );
    let query = h
        .seat
        .list_contexts(Budget {
            reply: Instant::now() + Duration::from_millis(10),
        })
        .await;
    assert_eq!(query.unwrap_err().kind, ErrorKind::Busy);
    assert!(h.seat.state.try_read().is_err());
    drop(quota);
    activation.await.unwrap();
    assert!(
        h.seat
            .get_context(authority.as_fd(), Budget::new())
            .await
            .unwrap()
            .effective
    );
    h.finish().await;
}
#[tokio::test]
async fn parent_owned_real_operation_survives_capture_adapter_panic() {
    use futures_util::StreamExt;
    let h = Fixture::new().await;
    let (authority, id) = h.seat.create_context(0, Budget::new()).await.unwrap();
    h.seat
        .set_grant(authority.as_fd(), 424242, true, Budget::new())
        .await
        .unwrap();
    let quota = h.workers.acquire().await.unwrap();
    let mut pending = crate::sources::BrokerWork::new();
    pending.push(crate::sources::operation(
        &h.seat,
        h.seat.activate_context(id, Budget::new()),
    ));
    let adapter = AssertUnwindSafe(async {
        assert!(
            tokio::time::timeout(Duration::from_millis(5), pending.next())
                .await
                .is_err()
        );
        panic!("injected capture failure, not an operation panic");
    })
    .catch_unwind()
    .await;
    assert!(adapter.is_err());
    assert_eq!(pending.len(), 1);
    assert!(
        h.seat.state.try_read().is_err(),
        "capture failure dropped the operation guard"
    );
    assert!(
        !h.seat.fatal.failed(),
        "adapter accidentally cancelled the admitted operation"
    );
    h.seat.fatal.fail("parent supervised capture failure");
    drop(quota);
    assert_eq!(
        pending.next().await.unwrap().unwrap_err().kind,
        ErrorKind::CriticalFailure
    );
    drop(pending);
    assert!(h.seat.state.try_read().is_ok());
    h.finish().await;
}
#[tokio::test]
async fn independent_watchdog_fences_even_when_the_parent_future_is_not_polled() {
    let h = Fixture::new().await;
    let watchdog = crate::daemon::Watchdog::start(h.seat.fatal.clone()).unwrap();
    let budget = Budget {
        reply: Instant::now() + crate::fatal::REPLY_HEADROOM + Duration::from_millis(150),
    };
    let mut op = h.seat.write(budget).await.unwrap();
    op.arm();
    // Deliberately block this test's single Tokio thread. The deadline owner
    // must not need that executor or the held State guard to fence admission.
    std::thread::sleep(Duration::from_millis(250));
    let fenced = h.seat.fatal.failed();
    let still_owned = h.seat.state.try_read().is_err();
    watchdog.finish();
    assert!(fenced && still_owned);
    drop(op);
    assert!(h.seat.state.try_read().is_ok());
    h.finish().await;
}
#[tokio::test]
async fn cancellation_fences_before_unlock_instead_of_publishing_partial_intent() {
    let h = Fixture::new().await;
    let (_authority, id) = h.seat.create_context(0, Budget::new()).await.unwrap();
    let quota = h.workers.acquire().await.unwrap();
    let mut activation = Box::pin(h.seat.activate_context(id, Budget::new()));
    assert!(
        tokio::time::timeout(Duration::from_millis(5), activation.as_mut())
            .await
            .is_err()
    );
    drop(activation);
    assert!(h.seat.fatal.failed());
    assert!(h.seat.state.try_read().is_ok());
    assert_eq!(
        h.seat.list_contexts(Budget::new()).await.unwrap_err().kind,
        ErrorKind::CriticalFailure
    );
    drop(quota);
    h.finish().await;
}
#[tokio::test]
async fn operation_panic_fences_before_the_tokio_guard_unlocks() {
    let h = Fixture::new().await;
    let panic = AssertUnwindSafe(async {
        let mut op = h.seat.write(Budget::new()).await.unwrap();
        op.arm();
        panic!("injected operation panic");
    })
    .catch_unwind()
    .await;
    assert!(panic.is_err());
    assert!(h.seat.fatal.failed());
    assert!(h.seat.state.try_read().is_ok());
    h.finish().await;
}
#[tokio::test]
async fn hard_effect_deadline_is_critical_even_for_an_empty_acl_target() {
    let h = Fixture::new().await;
    let (_authority, id) = h.seat.create_context(0, Budget::new()).await.unwrap();
    let quota = h.workers.acquire().await.unwrap();
    let budget = Budget {
        reply: Instant::now() + crate::fatal::REPLY_HEADROOM + Duration::from_millis(150),
    };
    let error = h.seat.activate_context(id, budget).await.unwrap_err();
    assert_eq!(error.kind, ErrorKind::CriticalFailure);
    assert!(h.seat.fatal.failed());
    drop(quota);
    h.finish().await;
}
#[tokio::test]
async fn authority_loss_during_application_withdraws_and_never_publishes_success() {
    let h = Fixture::new().await;
    let (authority, id) = h.seat.create_context(0, Budget::new()).await.unwrap();
    h.seat
        .set_grant(authority.as_fd(), 424242, true, Budget::new())
        .await
        .unwrap();
    let quota = h.workers.acquire().await.unwrap();
    let mut activation = Box::pin(h.seat.activate_context(id, Budget::new()));
    assert!(
        tokio::time::timeout(Duration::from_millis(5), activation.as_mut())
            .await
            .is_err()
    );
    drop(authority);
    drop(quota);
    assert_eq!(activation.await.unwrap_err().kind, ErrorKind::NotAuthorized);
    assert!(
        h.seat
            .list_contexts(Budget::new())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(h.seat.state.read().await.acl.desired_users().is_empty());
    assert!(!h.seat.fatal.failed());
    h.finish().await;
}
#[tokio::test]
async fn binding_metadata_is_immutable_and_removal_retry_is_authority_only() {
    let h = Fixture::new().await;
    assert_eq!(
        h.seat
            .create_context(7, Budget::new())
            .await
            .unwrap_err()
            .kind,
        ErrorKind::InvalidArgument
    );
    let (authority, id) = h.seat.create_context(0, Budget::new()).await.unwrap();
    assert_eq!(
        h.seat
            .seat_metadata(authority.as_fd(), Budget::new())
            .await
            .unwrap(),
        ("seat-test".into(), 0)
    );
    h.seat
        .remove_context(authority.as_fd(), Budget::new())
        .await
        .unwrap();
    h.seat
        .remove_context(authority.as_fd(), Budget::new())
        .await
        .unwrap();
    h.seat
        .remove_context_by_id(id, Budget::new())
        .await
        .unwrap();
    assert_eq!(
        h.seat
            .activate_context(id, Budget::new())
            .await
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        h.seat
            .get_context(authority.as_fd(), Budget::new())
            .await
            .unwrap_err()
            .kind,
        ErrorKind::NotAuthorized
    );
    h.finish().await;
}
