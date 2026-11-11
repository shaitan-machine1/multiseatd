//! Root-only runtime, signal masks and independent last-resort exit watchdog.
use crate::{fatal::Fatal, instance::InstanceLock};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use std::{
    future::Future,
    io,
    marker::PhantomData,
    os::fd::AsFd,
    path::Path,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::unix::AsyncFd;
use tokio::runtime::{Builder, Runtime};

pub struct DaemonRuntime {
    runtime: Option<Runtime>,
    #[cfg(feature = "vt")]
    _vt_mask: linux_vt::SignalMask,
    signals: ShutdownSignals,
    _instance: InstanceLock,
}
impl DaemonRuntime {
    pub fn acquire(path: &Path) -> io::Result<Self> {
        let instance = InstanceLock::acquire(path)?;
        let signals = ShutdownSignals::block()?;
        #[cfg(feature = "vt")]
        let vt_mask = linux_vt::SignalMask::block()?;
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            // Four regular slots plus bounded independent fatal ACL/resource
            // cleanup capacity; a hung original cannot consume every exit lane.
            .max_blocking_threads(8)
            .thread_name("multiseatd")
            .enable_io()
            .enable_time()
            .build()?;
        Ok(Self {
            runtime: Some(runtime),
            signals,
            #[cfg(feature = "vt")]
            _vt_mask: vt_mask,
            _instance: instance,
        })
    }
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime
            .as_ref()
            .expect("owned runtime")
            .block_on(future)
    }
    pub fn shutdown_signals(&self) -> &ShutdownSignals {
        &self.signals
    }
}
impl Drop for DaemonRuntime {
    fn drop(&mut self) {
        // Dropping Runtime normally can wait forever for an uncancellable native
        // worker. The outer instance guard stays held through this bounded wait.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_millis(500));
        }
    }
}
pub struct ShutdownSignals {
    original: SigSet,
    shutdown: SignalFd,
    _thread_affine: PhantomData<Rc<()>>,
}
impl ShutdownSignals {
    fn block() -> io::Result<Self> {
        let original = SigSet::thread_get_mask()?;
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGTERM);
        mask.add(Signal::SIGINT);
        mask.thread_block()?;
        let shutdown =
            match SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK) {
                Ok(fd) => fd,
                Err(error) => {
                    let _ = original.thread_set_mask();
                    return Err(error.into());
                }
            };
        Ok(Self {
            original,
            shutdown,
            _thread_affine: PhantomData,
        })
    }
    pub async fn requested(&self) -> io::Result<Signal> {
        let watched = unsafe {
            AsyncFd::register_with_interest(self.shutdown.as_fd(), tokio::io::Interest::READABLE)
        }?;
        loop {
            let mut ready = watched.readable().await?;
            if let Some(info) = self.shutdown.read_signal()? {
                return Signal::try_from(info.ssi_signo as i32).map_err(Into::into);
            }
            ready.clear_ready();
        }
    }
}
impl Drop for ShutdownSignals {
    fn drop(&mut self) {
        let _ = self.original.thread_set_mask();
    }
}

/// This explicit owner never acquires State or waits for Tokio/native workers.
/// A stuck syscall/log sink cannot prevent eventual nonzero process exit.
pub struct Watchdog {
    completed: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Watchdog {
    pub fn start(fatal: Fatal) -> io::Result<Self> {
        let completed = Arc::new(AtomicBool::new(false));
        let finished = completed.clone();
        let thread = std::thread::Builder::new()
            .name("seat-exit-watchdog".into())
            .spawn(move || {
                let mut deadline = None;
                while !finished.load(Ordering::Acquire) {
                    fatal.enforce_effect_deadline();
                    if fatal.stopping() {
                        let end = *deadline
                            .get_or_insert_with(|| Instant::now() + Duration::from_secs(10));
                        if Instant::now() >= end {
                            unsafe { libc::_exit(1) }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            })?;
        Ok(Self {
            completed,
            thread: Some(thread),
        })
    }
    pub fn finish(mut self) {
        self.completed.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
// An unfinished watchdog is intentionally NOT disarmed by Drop/unwinding.
