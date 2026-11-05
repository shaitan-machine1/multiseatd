//! Irreversible access epochs. Callers can attach their own lifetime predicate
//! without exposing contexts, credentials or policy state to the broker.
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone)]
pub struct Permit {
    open: Arc<AtomicBool>,
    parents: Vec<Arc<AtomicBool>>,
    lifetime: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
}

impl Default for Permit {
    fn default() -> Self {
        Self::new()
    }
}

impl Permit {
    pub fn new() -> Self {
        Self {
            open: Arc::new(AtomicBool::new(true)),
            parents: Vec::new(),
            lifetime: None,
        }
    }

    /// The trusted owner supplies a nonblocking, irreversible lifetime check. The callback
    /// remains attached to every descendant epoch, including in-flight work.
    pub fn with_lifetime(check: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self {
            lifetime: Some(Arc::new(check)),
            ..Self::new()
        }
    }

    pub fn gated(&self, gate: Arc<AtomicBool>) -> Self {
        let mut child = self.child();
        child.parents.push(gate);
        child
    }

    pub fn child(&self) -> Self {
        let mut parents = self.parents.clone();
        parents.push(self.open.clone());
        Self {
            open: Arc::new(AtomicBool::new(true)),
            parents,
            lifetime: self.lifetime.clone(),
        }
    }

    pub fn gate(&self) -> Arc<AtomicBool> {
        self.open.clone()
    }

    pub fn fence(&self) {
        self.open.store(false, Ordering::Release);
    }

    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
            && self.parents.iter().all(|gate| gate.load(Ordering::Acquire))
            && self.lifetime.as_ref().is_none_or(|check| check())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descendants_keep_parent_and_external_lifetime_fences() {
        let alive = Arc::new(AtomicBool::new(true));
        let check = alive.clone();
        let root = Permit::with_lifetime(move || check.load(Ordering::Acquire));
        let child = root.child().child();
        assert!(child.is_open());
        alive.store(false, Ordering::Release);
        assert!(!root.is_open() && !child.is_open());
        let root = Permit::new();
        let child = root.child();
        root.fence();
        assert!(!root.is_open() && !child.is_open());
        assert!(Permit::new().is_open());
    }
}
