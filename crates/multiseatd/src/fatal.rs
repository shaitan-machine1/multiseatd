//! One-way emergency/lifetime control, independent of the authoritative State lock.
use dev_broker::broker::Control;
use libmultiseatd::ErrorKind;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::sync::watch;
use tokio::time::{Duration, Instant};

pub const SERVER_WAIT: Duration = Duration::from_secs(8);
pub const EFFECT_LIMIT: Duration = Duration::from_secs(6);
pub const REPLY_HEADROOM: Duration = Duration::from_secs(1);
pub const FLUSH_LIMIT: Duration = Duration::from_millis(500);
pub const CLEANUP_LIMIT: Duration = Duration::from_secs(5);
pub const MIN_EFFECT_WINDOW: Duration = Duration::from_millis(100);

#[derive(Debug, thiserror::Error)]
#[error("{kind:?}: {text}")]
pub struct Error {
    pub kind: ErrorKind,
    pub text: String,
}
impl Error {
    pub fn new(kind: ErrorKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
        }
    }
    pub fn invalid(text: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidArgument, text)
    }
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy)]
pub struct Budget {
    pub reply: Instant,
}
impl Budget {
    pub fn new() -> Self {
        Self {
            reply: Instant::now() + SERVER_WAIT,
        }
    }
    pub fn admission(&self) -> Instant {
        self.reply - REPLY_HEADROOM
    }
    pub fn effect_deadline(&self) -> Result<Instant> {
        let now = Instant::now();
        let deadline = self.admission().min(now + EFFECT_LIMIT);
        if deadline <= now + MIN_EFFECT_WINDOW {
            Err(Error::new(
                ErrorKind::Busy,
                "insufficient required-effect response headroom",
            ))
        } else {
            Ok(deadline)
        }
    }
}
impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}
struct Inner {
    alive: Arc<AtomicBool>,
    failed: AtomicBool,
    reason: Mutex<Option<String>>,
    changed: watch::Sender<bool>,
    broker: Control,
    clock: std::time::Instant,
    effect_end: AtomicU64,
    watchdog_failed: AtomicBool,
}
#[derive(Clone)]
pub struct Fatal(Arc<Inner>);
impl Fatal {
    pub fn new(broker: Control) -> Self {
        let (changed, _) = watch::channel(false);
        Self(Arc::new(Inner {
            alive: Arc::new(AtomicBool::new(true)),
            failed: AtomicBool::new(false),
            reason: Mutex::new(None),
            changed,
            broker,
            clock: std::time::Instant::now(),
            effect_end: AtomicU64::new(0),
            watchdog_failed: AtomicBool::new(false),
        }))
    }
    // One State writer owns this window. No policy/effect history is retained.
    pub fn begin_effect(&self, deadline: Instant) -> u64 {
        let end = deadline
            .into_std()
            .saturating_duration_since(self.0.clock)
            .as_micros()
            .min(u64::MAX as u128) as u64;
        let end = end.max(1);
        self.0.effect_end.store(end, Ordering::Release);
        end
    }
    pub fn end_effect(&self, token: u64) {
        let _ = self
            .0
            .effect_end
            .compare_exchange(token, 0, Ordering::AcqRel, Ordering::Acquire);
    }
    pub fn enforce_effect_deadline(&self) {
        let end = self.0.effect_end.load(Ordering::Acquire);
        if !self.failed() && end != 0 && self.0.clock.elapsed().as_micros() >= u128::from(end) {
            // No watch borrow, mutex, allocation, log sink, State or runtime.
            self.0.alive.store(false, Ordering::Release);
            self.0.failed.store(true, Ordering::Release);
            self.0.watchdog_failed.store(true, Ordering::Release);
            self.0.broker.fence_only();
        }
    }
    pub async fn wait_stopping(&self) {
        let mut changed = self.subscribe();
        while !self.stopping() {
            let _ = tokio::time::timeout(Duration::from_millis(20), changed.changed()).await;
        }
    }
    pub fn gate(&self) -> Arc<AtomicBool> {
        self.0.alive.clone()
    }
    pub fn stopping(&self) -> bool {
        !self.0.alive.load(Ordering::Acquire)
    }
    pub fn failed(&self) -> bool {
        self.0.failed.load(Ordering::Acquire)
    }
    pub fn check(&self) -> Result<()> {
        if self.stopping() {
            Err(Error::new(
                if self.failed() {
                    ErrorKind::CriticalFailure
                } else {
                    ErrorKind::Stopping
                },
                "seat is stopping",
            ))
        } else {
            Ok(())
        }
    }
    pub fn fail(&self, reason: impl Into<String>) -> Error {
        // Fence FIRST. No State acquisition, worker join, or diagnostic lock can
        // defer the emergency barrier. Never reopen this gate.
        self.0.alive.store(false, Ordering::Release);
        self.0.failed.store(true, Ordering::Release);
        self.0.broker.emergency_stop();
        let reason = reason.into();
        self.0.changed.send_replace(true);
        if let Ok(mut stored) = self.0.reason.try_lock()
            && stored.is_none()
        {
            *stored = Some(reason.clone());
        }
        // No synchronous logging/diagnostic lock may delay the caller's reply.
        Error::new(
            ErrorKind::CriticalFailure,
            reason.chars().take(1024).collect::<String>(),
        )
    }
    pub fn stop(&self) {
        self.0.alive.store(false, Ordering::Release);
        self.0.broker.emergency_stop();
        self.0.changed.send_replace(true);
    }
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.0.changed.subscribe()
    }
    pub fn reason(&self) -> Option<String> {
        self.0
            .reason
            .try_lock()
            .ok()
            .and_then(|reason| reason.clone())
            .or_else(|| {
                self.0
                    .watchdog_failed
                    .load(Ordering::Acquire)
                    .then(|| "independent cumulative effect deadline expired".into())
            })
    }
}
