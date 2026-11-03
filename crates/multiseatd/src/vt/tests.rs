use super::*;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use tokio::time::{Duration, timeout};

pub(crate) struct State {
    pub foreground: AtomicU32,
    pub panic_switch: AtomicBool,
    pub log: Mutex<Vec<(String, std::thread::ThreadId)>>,
}
impl State {
    fn record(&self, name: &str) {
        self.log
            .lock()
            .unwrap()
            .push((name.into(), std::thread::current().id()));
    }
    pub fn contains(&self, name: &str) -> bool {
        self.log
            .lock()
            .unwrap()
            .iter()
            .any(|(event, _)| event == name)
    }
    pub fn release(&self, port: &Port) {
        port.send(Command::Signal(libc::SIGUSR1)).unwrap();
    }
    pub fn acquire(&self, port: &Port) {
        self.foreground.store(7, Ordering::Release);
        port.send(Command::Signal(libc::SIGUSR2)).unwrap();
    }
}
struct Fake(Arc<State>);
impl linux::Operations for Fake {
    fn open(&mut self, _: u32) -> io::Result<()> {
        self.0.record("open");
        Ok(())
    }
    fn foreground(&mut self) -> io::Result<u32> {
        self.0.record("foreground");
        Ok(self.0.foreground.load(Ordering::Acquire))
    }
    fn switch(&mut self, target: u32) -> io::Result<()> {
        self.0.record(&format!("switch-{target}"));
        assert!(
            !self.0.panic_switch.load(Ordering::Acquire),
            "injected VT owner panic"
        );
        Ok(())
    }
    fn release(&mut self) -> io::Result<()> {
        self.0.record("release");
        self.0.foreground.store(1, Ordering::Release);
        Ok(())
    }
    fn acquire(&mut self) -> io::Result<()> {
        self.0.record("acquire");
        Ok(())
    }
    fn restore(&mut self) -> io::Result<()> {
        self.0.record("restore");
        Ok(())
    }
}
pub(crate) async fn owner(resources: Arc<Resources>, foreground: u32) -> (Owner, Arc<State>) {
    let state = Arc::new(State {
        foreground: AtomicU32::new(foreground),
        panic_switch: AtomicBool::new(false),
        log: Mutex::new(Vec::new()),
    });
    let owner = Owner::with_operations(7, resources, Box::new(Fake(state.clone())), true)
        .await
        .unwrap();
    (owner, state)
}
pub(crate) async fn phase(port: &Port, expected: Phase) {
    let mut facts = port.facts.clone();
    timeout(Duration::from_secs(4), async {
        loop {
            if facts.borrow().phase == expected {
                return;
            }
            facts.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn release_requires_matching_barrier_and_switch_acceptance_is_not_acquisition() {
    let resources = Arc::new(Resources::new(8, 8).unwrap());
    let (mut owner, state) = owner(resources, 7).await;
    let port = owner.port();
    let old_gate = port.facts.borrow().gate.clone();
    state.release(&port);
    phase(&port, Phase::Releasing).await;
    assert!(!old_gate.is_open());
    assert!(!state.contains("release"));
    let generation = port.facts.borrow().generation;
    port.release_ready(generation - 1).unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!state.contains("release"));
    port.release_ready(generation).unwrap();
    phase(&port, Phase::Away).await;
    port.acquire(Permit::new()).unwrap();
    phase(&port, Phase::Acquiring).await;
    assert!(!port.facts.borrow().gate.is_open());
    state.acquire(&port);
    phase(&port, Phase::Foreground).await;
    assert!(port.facts.borrow().gate.is_open());
    assert!(!old_gate.is_open());
    owner.finish().unwrap();
    let log = state.log.lock().unwrap();
    let thread = log[0].1;
    assert!(log.iter().all(|(_, task)| *task == thread));
    assert_ne!(thread, std::thread::current().id());
}

#[tokio::test]
async fn seat_teardown_restores_terminal_and_reappearance_reuses_the_same_native_task() {
    let resources = Arc::new(Resources::new(8, 8).unwrap());
    let (mut owner, state) = owner(resources, 7).await;
    let port = owner.port();
    port.presence_after_cleanup(false).await.unwrap();
    phase(&port, Phase::Absent).await;
    assert!(state.contains("restore"));
    state.release(&port);
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(port.facts.borrow().phase, Phase::Absent);
    port.presence_after_cleanup(true).await.unwrap();
    phase(&port, Phase::Foreground).await;
    owner.finish().unwrap();
    let log = state.log.lock().unwrap();
    let task = log[0].1;
    assert!(log.iter().all(|(_, thread)| *thread == task));
    assert_eq!(log.iter().filter(|(name, _)| name == "open").count(), 2);
}

#[tokio::test]
async fn native_panic_keeps_terminal_owned_until_outer_resource_cleanup() {
    use crate::acl::test_acl_text;
    let resources = Arc::new(Resources::new(8, 8).unwrap());
    let file = tempfile::NamedTempFile::new().unwrap();
    let node = resources.pin(file.path()).unwrap();
    resources
        .apply(
            node,
            &std::collections::BTreeSet::from([424242]),
            &Permit::new(),
        )
        .unwrap();
    let (mut owner, state) = owner(resources.clone(), 7).await;
    let port = owner.port();
    state.panic_switch.store(true, Ordering::Release);
    let reply = port.switch(2, Permit::new()).unwrap();
    assert!(reply.await.is_err());
    phase(&port, Phase::Failed).await;
    assert!(!state.contains("restore"));
    assert!(test_acl_text(file.path()).contains("user:424242:"));
    assert!(owner.finish().is_err());
    assert!(!state.contains("restore"));
    assert!(resources.cleanup().is_empty());
    assert!(!test_acl_text(file.path()).contains("user:424242:"));
    assert!(owner.finish().is_err());
    assert!(state.contains("restore"));
}
