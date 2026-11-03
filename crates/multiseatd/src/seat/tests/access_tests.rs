use super::*;
use crate::acl::{NodeIdentity, test_acl_text};
use crate::seat::policy::Policy;
use std::sync::{Condvar, Mutex};

impl Harness {
    pub(super) async fn configure(&mut self, policy: Policy) {
        self.port
            .prepare_policy(policy)
            .await
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        self.port.commit_policy().await.unwrap();
        self.wait(|status| status.seat.5 != "topology").await;
    }
    fn grant_wait(
        &self,
        context: ContextId,
        uid: u32,
        grant: bool,
    ) -> oneshot::Receiver<Result<(), ErrorKind>> {
        let (reply, receiver) = oneshot::channel();
        self.port
            .send(Command::Grant {
                context,
                uid,
                grant,
                reply,
            })
            .unwrap();
        receiver
    }
    async fn grant(&self, context: ContextId, uid: u32, grant: bool) {
        timeout(Duration::from_secs(4), self.grant_wait(context, uid, grant))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    fn node(&self, file: &tempfile::NamedTempFile) -> NodeIdentity {
        self.resources.pin(file.path()).unwrap()
    }
}
#[tokio::test]
async fn failed_source_acl_clear_blocks_successor_grants() {
    let mut harness = Harness::new();
    let file = tempfile::NamedTempFile::new().unwrap();
    let node = harness.node(&file);
    harness
        .configure(Policy {
            nodes: BTreeSet::from([node]),
            ..Policy::default()
        })
        .await;
    let a = harness.context().await;
    let b = harness.context().await;
    harness.grant(a, 424242, true).await;
    harness.grant(b, 424244, true).await;
    harness.activate(a).await;
    harness.resources.fail_acl_writes(node, 2);
    let activating = harness.mutation(b, true);
    harness
        .wait(|status| !status.contexts[&a].7.is_empty())
        .await;
    assert!(!has(&file, 424244));
    timeout(Duration::from_secs(4), activating)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!has(&file, 424242));
    assert!(has(&file, 424244));
    harness.finish().await;
}

#[tokio::test]
async fn preparing_a_stale_snapshot_never_retargets_a_replacement_inode() {
    use crate::acl::{AclOps, LibAcl};
    use std::os::unix::fs::MetadataExt;
    let harness = Harness::new();
    let directory = tempfile::tempdir().unwrap();
    let original = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
    let metadata = original.as_file().metadata().unwrap();
    let expected = (metadata.dev(), metadata.ino());
    let replacement = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
    std::fs::rename(replacement.path(), original.path()).unwrap();
    LibAcl
        .set_users(original.path(), &BTreeSet::from([424244]))
        .unwrap();
    let name: SeatName = "seat-test".parse().unwrap();
    let snapshot = crate::topology::Snapshot {
        seats: BTreeSet::from([name.clone()]),
        direct: BTreeMap::from([(
            name.clone(),
            BTreeSet::from([original.path().to_path_buf()]),
        )]),
        identities: BTreeMap::from([(original.path().to_path_buf(), expected)]),
        ..Default::default()
    };
    let policies = crate::seat::policy::prepare(&harness.resources, &snapshot).unwrap();
    assert!(policies[&name].nodes.is_empty());
    assert!(harness.resources.cleanup().is_empty());
    assert!(has(&original, 424244));
    harness.finish().await;
}

#[tokio::test]
async fn idle_reconciliation_also_clears_external_named_users() {
    use crate::acl::{AclOps, LibAcl};
    let mut harness = Harness::new();
    let file = tempfile::NamedTempFile::new().unwrap();
    harness
        .configure(Policy {
            nodes: BTreeSet::from([harness.node(&file)]),
            ..Policy::default()
        })
        .await;
    LibAcl
        .set_users(file.path(), &BTreeSet::from([424242]))
        .unwrap();
    timeout(Duration::from_secs(4), async {
        while has(&file, 424242) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    harness.finish().await;
}

fn has(file: &tempfile::NamedTempFile, uid: u32) -> bool {
    test_acl_text(file.path()).contains(&format!("user:{uid}:"))
}

#[tokio::test]
async fn inactive_grants_are_desired_only_and_connection_eof_never_revokes_them() {
    let mut harness = Harness::new();
    let file = tempfile::NamedTempFile::new().unwrap();
    harness
        .configure(Policy {
            nodes: BTreeSet::from([harness.node(&file)]),
            ..Policy::default()
        })
        .await;
    let context = harness.context().await;
    harness.grant(context, 424242, true).await;
    harness.grant(context, 424242, true).await;
    assert!(!has(&file, 424242));
    harness.activate(context).await;
    assert!(has(&file, 424242));
    let peer = harness.peer(context).await;
    let id = peer.id;
    drop(peer);
    harness
        .wait(|status| !status.connections.contains_key(&id))
        .await;
    assert!(has(&file, 424242));
    harness.deactivate(context).await;
    assert!(!has(&file, 424242));
    assert_eq!(
        harness.port.status.borrow().contexts[&context].3,
        vec![424242]
    );
    harness.activate(context).await;
    assert!(has(&file, 424242));
    harness.remove(context).await;
    assert!(!has(&file, 424242));
    harness.finish().await;
}

#[tokio::test]
async fn failed_active_addition_compensates_partial_writes_and_never_reconciles_rejected_uid() {
    let mut harness = Harness::new();
    let first = tempfile::NamedTempFile::new().unwrap();
    let second = tempfile::NamedTempFile::new().unwrap();
    let nodes = BTreeSet::from([harness.node(&first), harness.node(&second)]);
    harness
        .configure(Policy {
            nodes: nodes.clone(),
            ..Policy::default()
        })
        .await;
    let context = harness.context().await;
    harness.activate(context).await;
    harness.resources.fail_acl_writes(*nodes.last().unwrap(), 1);
    let result = harness.grant_wait(context, 424242, true).await.unwrap();
    assert_eq!(result, Err(ErrorKind::BackendFailure));
    assert!(!has(&first, 424242));
    assert!(!has(&second, 424242));
    assert!(harness.port.status.borrow().contexts[&context].3.is_empty());
    tokio::time::sleep(Duration::from_millis(1150)).await;
    assert!(!has(&first, 424242));
    assert!(!has(&second, 424242));
    harness.finish().await;
}

#[tokio::test]
async fn failed_revocation_removes_desired_first_and_retries_without_regranting() {
    let mut harness = Harness::new();
    let file = tempfile::NamedTempFile::new().unwrap();
    let node = harness.node(&file);
    harness
        .configure(Policy {
            nodes: BTreeSet::from([node]),
            ..Policy::default()
        })
        .await;
    let context = harness.context().await;
    harness.activate(context).await;
    harness.grant(context, 424242, true).await;
    harness.resources.fail_acl_writes(node, 2);
    let revoking = harness.grant_wait(context, 424242, false);
    harness
        .wait(|status| {
            status.contexts[&context].3.is_empty() && !status.contexts[&context].7.is_empty()
        })
        .await;
    revoking.await.unwrap().unwrap();
    assert!(!has(&file, 424242));
    harness.finish().await;
}

#[tokio::test]
async fn reconciliation_repairs_external_acl_reset_using_the_complete_desired_set() {
    use crate::acl::{AclOps, LibAcl};
    let mut harness = Harness::new();
    let file = tempfile::NamedTempFile::new().unwrap();
    harness
        .configure(Policy {
            nodes: BTreeSet::from([harness.node(&file)]),
            ..Policy::default()
        })
        .await;
    let context = harness.context().await;
    harness.grant(context, 424242, true).await;
    harness.grant(context, 424244, true).await;
    harness.activate(context).await;
    LibAcl.set_users(file.path(), &BTreeSet::new()).unwrap();
    timeout(Duration::from_secs(4), async {
        while !has(&file, 424242) || !has(&file, 424244) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    harness.finish().await;
}

#[tokio::test]
async fn topology_source_clear_waits_for_a_started_old_write_before_destination_publication() {
    let mut harness = Harness::new();
    let file = tempfile::NamedTempFile::new().unwrap();
    let node = harness.node(&file);
    let source_policy = Policy {
        nodes: BTreeSet::from([node]),
        ..Policy::default()
    };
    harness.configure(source_policy.clone()).await;
    let source = harness.context().await;
    harness.grant(source, 424242, true).await;
    harness.activate(source).await;
    let destination_name: SeatName = "seat-destination".parse().unwrap();
    harness.registry.add_seat(destination_name.clone()).unwrap();
    let (controller, destination) = Controller::new(
        destination_name.clone(),
        harness.resources.clone(),
        harness.budget.clone(),
    );
    harness
        .tasks
        .spawn(
            crate::daemon::CriticalRole::Seat(destination_name.clone()),
            controller.run(harness.tasks.subscribe()),
        )
        .unwrap();
    let publication = harness.registry.begin_context(&destination_name).unwrap();
    let destination_context = publication.context();
    let (reply, receiver) = oneshot::channel();
    destination
        .send(Command::Register {
            context: destination_context,
            lifetime: publication.registration(),
            reply,
        })
        .unwrap();
    receiver.await.unwrap().unwrap();
    harness
        .authorities
        .push(publication.publish(|_, fd| Ok::<_, io::Error>(fd)).unwrap());
    let (reply, receiver) = oneshot::channel();
    destination
        .send(Command::Grant {
            context: destination_context,
            uid: 424244,
            grant: true,
            reply,
        })
        .unwrap();
    receiver.await.unwrap().unwrap();
    let (reply, receiver) = oneshot::channel();
    destination
        .send(Command::Activate {
            context: destination_context,
            reply,
        })
        .unwrap();
    receiver.await.unwrap().unwrap();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_gate = gate.clone();
    let resources = harness.resources.clone();
    let (entered, waiting) = oneshot::channel();
    let worker = std::thread::spawn(move || {
        resources
            .apply_then(node, &BTreeSet::from([424242]), &Permit::new(), || {
                let _ = entered.send(());
                let (mutex, condition) = &*worker_gate;
                let mut released = mutex.lock().unwrap();
                while !*released {
                    released = condition.wait(released).unwrap();
                }
            })
            .unwrap()
    });
    waiting.await.unwrap();
    let snapshot = crate::topology::Snapshot {
        seats: BTreeSet::from(["seat-test".parse().unwrap(), destination_name.clone()]),
        direct: BTreeMap::from([(
            destination_name.clone(),
            BTreeSet::from([file.path().to_path_buf()]),
        )]),
        ..Default::default()
    };
    let previous = BTreeMap::from([
        ("seat-test".parse().unwrap(), source_policy),
        (destination_name.clone(), Policy::default()),
    ]);
    let ports = BTreeMap::from([
        ("seat-test".parse().unwrap(), harness.port.clone()),
        (destination_name.clone(), destination.clone()),
    ]);
    let resources = harness.resources.clone();
    let shutdown = harness.tasks.subscribe();
    let mut moving = tokio::spawn(crate::topology_transaction::reconcile(
        resources,
        snapshot,
        previous,
        ports,
        BTreeSet::new(),
        shutdown,
        None,
    ));
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(!moving.is_finished());
    assert!(!has(&file, 424244));
    {
        let (mutex, condition) = &*gate;
        *mutex.lock().unwrap() = true;
        condition.notify_all();
    }
    let prepared = timeout(Duration::from_secs(4), &mut moving)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .unwrap();
    worker.join().unwrap();
    assert!(!has(&file, 424242));
    assert!(!has(&file, 424244));
    assert!(prepared.affected.contains(&destination_name));
    harness.port.commit_policy().await.unwrap();
    destination.commit_policy().await.unwrap();
    timeout(Duration::from_secs(4), async {
        while !has(&file, 424244) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(!has(&file, 424242));
    harness.finish().await;
}
