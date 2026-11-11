//! Explicit native terminal ownership. No contexts, broker, ACLs or executor.
//! Block VT signals on the parent BEFORE creating runtime/worker threads.
#[cfg(feature = "test-support")]
mod fixture;
mod linux;
#[cfg(feature = "test-support")]
pub use fixture::Fixture;
use futures_channel::oneshot;
use nix::sys::signal::{SigSet, Signal};
use std::collections::BTreeSet;
use std::io;
use std::marker::PhantomData;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::JoinHandle;

pub struct SignalMask {
    original: SigSet,
    _thread_affine: PhantomData<Rc<()>>,
}
impl SignalMask {
    pub fn block() -> io::Result<Self> {
        let original = SigSet::thread_get_mask()?;
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGUSR1);
        mask.add(Signal::SIGUSR2);
        mask.thread_block()?;
        Ok(Self {
            original,
            _thread_affine: PhantomData,
        })
    }
}
impl Drop for SignalMask {
    fn drop(&mut self) {
        // Caller has restored/joined all terminal owners. Do not deliver an
        // obsolete queued release/acquisition hint to default signal actions.
        if let Ok(fd) = linux::signals() {
            for _ in 0..128 {
                if !matches!(linux::signal(&fd), Ok(Some(_))) {
                    break;
                }
            }
        }
        if let Err(error) = self.original.thread_set_mask() {
            eprintln!("linux-vt: signal mask restore failed: {error}");
        }
    }
}
#[derive(Debug)]
pub enum Notice {
    ReleaseRequested,
    ForegroundAcquired,
}
enum Command {
    Foreground(oneshot::Sender<io::Result<u32>>),
    Switch(u32, oneshot::Sender<io::Result<()>>),
    Release(bool, oneshot::Sender<io::Result<()>>),
    Restore(oneshot::Sender<io::Result<()>>),
    Shutdown(oneshot::Sender<io::Result<()>>),
}
#[derive(Clone)]
pub struct Control {
    commands: mpsc::SyncSender<Command>,
    wake: Arc<UnixStream>,
    failed: Arc<AtomicBool>,
}
impl Control {
    fn submit(&self, command: Command) -> io::Result<()> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => io::Error::from_raw_os_error(libc::EAGAIN),
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::from_raw_os_error(libc::ESHUTDOWN)
                }
            })?;
        let byte = 1u8;
        // Registration already transferred ownership. Prefer the owner's actual
        // reply even if it consumed shutdown and closed the wake peer first.
        let _ = unsafe {
            libc::send(
                self.wake.as_raw_fd(),
                (&byte as *const u8).cast(),
                1,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        Ok(())
    }
    pub async fn foreground(&self) -> io::Result<u32> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Foreground(reply))?;
        result.await.map_err(|_| stopped())?
    }
    pub async fn request_switch(&self, target: u32) -> io::Result<()> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Switch(target, reply))?;
        result.await.map_err(|_| stopped())?
    }
    pub async fn acknowledge_release(&self) -> io::Result<()> {
        self.release(true).await
    }
    pub async fn deny_release(&self) -> io::Result<()> {
        self.release(false).await
    }
    async fn release(&self, allow: bool) -> io::Result<()> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Release(allow, reply))?;
        result.await.map_err(|_| stopped())?
    }
    /// Acquisition is already complete: NEVER issue VT_RELDISP/VT_ACKACQ here.
    pub async fn acknowledge_acquisition(&self) -> io::Result<()> {
        if self.failed.load(Ordering::Acquire) {
            Err(stopped())
        } else {
            Ok(())
        }
    }
    pub async fn restore_all(&self) -> io::Result<()> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Restore(reply))?;
        result.await.map_err(|_| stopped())?
    }
    pub async fn shutdown(&self) -> io::Result<()> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Shutdown(reply))?;
        result.await.map_err(|_| stopped())?
    }
}
pub struct Notices {
    receiver: mpsc::Receiver<Notice>,
    wake: Arc<OwnedFd>,
    failed: Arc<AtomicBool>,
}
impl Notices {
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.wake.as_fd()
    }
    /// Clear readiness then drain bounded notices in original native order.
    pub fn clear_ready(&self) -> io::Result<()> {
        let mut count = 0u64;
        let result = unsafe {
            libc::read(
                self.wake.as_raw_fd(),
                (&mut count as *mut u64).cast(),
                size_of::<u64>(),
            )
        };
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn try_next(&self) -> io::Result<Option<Notice>> {
        if self.failed.load(Ordering::Acquire) {
            return Err(io::Error::other("native VT owner failed"));
        }
        match self.receiver.try_recv() {
            Ok(notice) => Ok(Some(notice)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(stopped()),
        }
    }
}
pub struct Owner {
    control: Control,
    notices: Option<Notices>,
    thread: Option<JoinHandle<io::Result<()>>>,
    startup: Option<oneshot::Receiver<io::Result<()>>>,
}
impl Owner {
    pub fn claim_all(vts: &BTreeSet<u32>) -> io::Result<Self> {
        let mask = SigSet::thread_get_mask()?;
        if !mask.contains(Signal::SIGUSR1) || !mask.contains(Signal::SIGUSR2) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block VT signals before runtime/worker creation",
            ));
        }
        let (wake, waiting) = UnixStream::pair()?;
        wake.set_nonblocking(true)?;
        waiting.set_nonblocking(true)?;
        let event = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if event < 0 {
            return Err(io::Error::last_os_error());
        }
        let event = Arc::new(unsafe { OwnedFd::from_raw_fd(event) });
        let failed = Arc::new(AtomicBool::new(false));
        let (commands, receiver) = mpsc::sync_channel(64);
        let (notices, capture) = mpsc::sync_channel(64);
        let (ready, started) = oneshot::channel();
        let set = vts.clone();
        let native_event = event.clone();
        let native_failed = failed.clone();
        let thread = std::thread::Builder::new()
            .name("linux-vt".into())
            .spawn(move || {
                let mut native = None;
                let initialized = (|| {
                    native = Some(linux::Linux::new(&set)?);
                    native
                        .as_mut()
                        .expect("opened native owner")
                        .claim_all(&set)?;
                    linux::signals()
                })();
                let signals = match initialized {
                    Ok(fd) => fd,
                    Err(error) => {
                        let reason = error.to_string();
                        native_failed.store(true, Ordering::Release);
                        notify(&native_event);
                        let _ = ready.send(Err(error));
                        return failed_cleanup(&mut native, &receiver, reason);
                    }
                };
                // Reply expiry/drop does not abandon or restore claims. Their
                // owner remains here until explicit daemon-directed cleanup.
                let _ = ready.send(Ok(()));
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(
                        native.as_mut().expect("initialized native owner"),
                        &signals,
                        &waiting,
                        &receiver,
                        &notices,
                        &native_event,
                    )
                }));
                match result {
                    Ok(Ok(())) => Ok(()),
                    failed => {
                        let reason = match failed {
                            Ok(Err(error)) => error.to_string(),
                            Err(_) => "native owner panicked".into(),
                            _ => unreachable!(),
                        };
                        native_failed.store(true, Ordering::Release);
                        notify(&native_event);
                        // No diagnostic sink can block cleanup command progress.
                        failed_cleanup(&mut native, &receiver, reason)
                    }
                }
            })?;
        Ok(Self {
            control: Control {
                commands,
                wake: Arc::new(wake),
                failed: failed.clone(),
            },
            notices: Some(Notices {
                receiver: capture,
                wake: event,
                failed,
            }),
            thread: Some(thread),
            startup: Some(started),
        })
    }
    /// The caller must complete readiness before publishing service policy.
    /// A timed-out waiter leaves claims and the receipt owned for cleanup.
    pub async fn ready(&mut self) -> io::Result<()> {
        if let Some(receipt) = self.startup.as_mut() {
            let result = receipt
                .await
                .map_err(|_| io::Error::other("native startup owner disappeared"));
            self.startup.take();
            result??;
        }
        if self.control.failed.load(Ordering::Acquire) {
            return Err(stopped());
        }
        Ok(())
    }
    pub fn control(&self) -> Control {
        self.control.clone()
    }
    pub fn take_notices(&mut self) -> io::Result<Notices> {
        self.notices
            .take()
            .ok_or_else(|| io::Error::other("VT notices already taken"))
    }
    /// Nonblocking join probe. The caller bounds shutdown, including native stalls.
    pub fn join_if_finished(&mut self) -> io::Result<bool> {
        if self
            .thread
            .as_ref()
            .is_none_or(|thread| thread.is_finished())
        {
            if let Some(thread) = self.thread.take() {
                thread
                    .join()
                    .map_err(|_| io::Error::other("native VT owner panic"))??;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        if self.thread.is_some() {
            eprintln!(
                "linux-vt: owner dropped without a completed native join; not a clean restoration"
            );
        }
    }
}
fn failed_cleanup(
    native: &mut Option<linux::Linux>,
    commands: &mpsc::Receiver<Command>,
    reason: String,
) -> io::Result<()> {
    // Startup and runtime failures retain exact native claims, never reset state
    // or restore before the daemon's resource barrier. No executor is created.
    while let Ok(command) = commands.recv() {
        match command {
            Command::Restore(reply) => {
                let _ = reply.send(native.as_mut().map_or(Ok(()), linux::Linux::restore_all));
            }
            Command::Shutdown(reply) => {
                let result = native.as_mut().map_or(Ok(()), linux::Linux::restore_all);
                let done = result.is_ok();
                let _ = reply.send(result);
                if done {
                    return Err(io::Error::other(reason));
                }
            }
            Command::Foreground(reply) => {
                let _ = reply.send(Err(stopped()));
            }
            Command::Switch(_, reply) | Command::Release(_, reply) => {
                let _ = reply.send(Err(stopped()));
            }
        }
    }
    Err(io::Error::other(reason))
}
fn run(
    native: &mut linux::Linux,
    signals: &OwnedFd,
    waiting: &UnixStream,
    commands: &mpsc::Receiver<Command>,
    notices: &mpsc::SyncSender<Notice>,
    event: &OwnedFd,
) -> io::Result<()> {
    loop {
        // Preserve signalfd's dequeue order. Standard signals are only hints.
        for _ in 0..64 {
            let Some(signal) = linux::signal(signals)? else {
                break;
            };
            let notice = match signal {
                libc::SIGUSR1 => Notice::ReleaseRequested,
                libc::SIGUSR2 => Notice::ForegroundAcquired,
                _ => return Err(io::Error::other("unexpected VT signal")),
            };
            notices
                .try_send(notice)
                .map_err(|_| io::Error::other("VT capture overflow/disconnect"))?;
            notify(event);
        }
        for _ in 0..64 {
            let command = match commands.try_recv() {
                Ok(command) => command,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(_) => return Err(stopped()),
            };
            match command {
                Command::Foreground(reply) => {
                    let _ = reply.send(native.foreground());
                }
                Command::Switch(target, reply) => {
                    let _ = reply.send(native.request_switch(target));
                }
                Command::Release(allow, reply) => {
                    let _ = reply.send(native.release(allow));
                }
                Command::Restore(reply) => {
                    let _ = reply.send(native.restore_all());
                }
                Command::Shutdown(reply) => {
                    let result = native.restore_all();
                    let done = result.is_ok();
                    let _ = reply.send(result);
                    if done {
                        return Ok(());
                    }
                }
            }
        }
        let mut fds = [
            libc::pollfd {
                fd: signals.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: waiting.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if fds
            .iter()
            .any(|fd| fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0)
        {
            return Err(stopped());
        }
        if fds[1].revents & libc::POLLIN != 0 {
            let mut bytes = [0u8; 128];
            unsafe {
                libc::read(waiting.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len());
            }
        }
    }
}
fn notify(event: &OwnedFd) {
    let count = 1u64;
    unsafe {
        libc::write(
            event.as_raw_fd(),
            (&count as *const u64).cast(),
            size_of::<u64>(),
        );
    }
}
fn stopped() -> io::Error {
    io::Error::from_raw_os_error(libc::ESHUTDOWN)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn complete<F: std::future::Future>(future: F) -> F::Output {
        let mut future = Box::pin(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let end = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let std::task::Poll::Ready(result) = future.as_mut().poll(&mut context) {
                return result;
            }
            assert!(
                std::time::Instant::now() < end,
                "native fixture did not settle"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    #[test]
    fn invalid_startup_has_owned_readiness_failure_and_never_resets_to_ready() {
        // Empty sets are rejected BEFORE opening any terminal. This only tests
        // native ownership/receipts; it does not exercise the host's VT domain.
        let _mask = SignalMask::block().unwrap();
        let mut owner = Owner::claim_all(&BTreeSet::new()).unwrap();
        assert_eq!(
            complete(owner.ready()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            complete(owner.ready()).unwrap_err().raw_os_error(),
            Some(libc::ESHUTDOWN)
        );
        complete(owner.control().shutdown()).unwrap();
        let end = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match owner.join_if_finished() {
                Err(error) => {
                    assert!(error.to_string().contains("configured VTs"));
                    break;
                }
                Ok(true) => panic!("failed startup incorrectly claimed a normal native exit"),
                Ok(false) => {
                    assert!(std::time::Instant::now() < end);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
    }
}
