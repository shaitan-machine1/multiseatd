//! Independent broker and ACL work lanes; one completion still joins both.
//! Admission is bounded by the owner's context/connection states, not by
//! blocking dispatch while waiting for a kernel-worker permit.
use super::*;
use crate::acl::NodeIdentity;
use tokio::task::JoinError;

pub(super) struct Work {
    pub resources: Arc<Resources>,
    pub owners: Vec<(ConnectionKey, Option<Permit>)>,
    pub nodes: BTreeSet<NodeIdentity>,
    pub users: BTreeSet<u32>,
    pub node_permit: Permit,
    pub job: Job,
}
impl Work {
    pub async fn run(self, workers: Arc<Semaphore>, acl_workers: Arc<Semaphore>) -> Completion {
        let Self {
            resources,
            owners,
            nodes,
            users,
            node_permit,
            job,
        } = self;
        let broker_resources = resources.clone();
        let broker = async move {
            if owners.is_empty() {
                return Ok(Vec::new());
            }
            let Ok(quota) = workers.acquire_owned().await else {
                return Ok(vec![io::Error::other("broker worker budget closed")]);
            };
            tokio::task::spawn_blocking(move || {
                let _quota = quota;
                let mut errors = Vec::new();
                for (owner, permit) in owners {
                    errors.extend(match job {
                        Job::Revoke(_) => broker_resources.deactivate_owner(owner),
                        Job::Prepare(_) => broker_resources
                            .activate_owner(owner, permit.as_ref().expect("activation epoch")),
                        Job::Close(_) => broker_resources.close_owner(owner),
                        Job::Access(_) | Job::IdleAccess => Vec::new(),
                    });
                }
                errors
            })
            .await
        };
        let acl = async move {
            if nodes.is_empty() {
                return Ok(Vec::new());
            }
            let Ok(quota) = acl_workers.acquire_owned().await else {
                return Ok(vec![io::Error::other("ACL worker budget closed")]);
            };
            tokio::task::spawn_blocking(move || {
                let _quota = quota;
                let mut errors = Vec::new();
                for node in nodes {
                    if let Err(error) = resources.apply(node, &users, &node_permit) {
                        errors.push(error);
                    }
                }
                errors
            })
            .await
        };
        // Even a panic in one lane does not cancel/skip started independent
        // cleanup in the other. Propagate only after both outcomes are owned.
        let (broker, acl) = tokio::join!(broker, acl);
        let broker = settled(broker);
        let acl = settled(acl);
        Completion {
            job,
            error: broker
                .into_iter()
                .chain(acl)
                .next()
                .map(|error| error.to_string()),
        }
    }
}
fn settled(result: Result<Vec<io::Error>, JoinError>) -> Vec<io::Error> {
    match result {
        Ok(errors) => errors,
        Err(error) => std::panic::resume_unwind(if error.is_panic() {
            error.into_panic()
        } else {
            Box::new("blocking owner cancelled")
        }),
    }
}
