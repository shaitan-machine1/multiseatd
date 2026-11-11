//! Explicit mechanical fixture, never opens a terminal or sends a signal.
use super::*;
use std::sync::atomic::{AtomicU32, AtomicUsize};

pub struct Fixture {
    pub current: Arc<AtomicU32>,
    pub release_calls: Arc<AtomicUsize>,
    pub foreground_calls: Arc<AtomicUsize>,
    pub restored: Arc<AtomicUsize>,
    pub fail_release: Arc<AtomicBool>,
    notices: mpsc::SyncSender<Notice>,
    event: Arc<OwnedFd>,
}
impl Fixture {
    pub fn notice(&self, notice: Notice) -> io::Result<()> {
        self.notices
            .try_send(notice)
            .map_err(|_| io::Error::other("fixture capture overflow"))?;
        notify(&self.event);
        Ok(())
    }
}
impl Owner {
    pub fn synthetic(vts: BTreeSet<u32>, current: u32) -> io::Result<(Self, Fixture)> {
        if vts.is_empty() || vts.iter().any(|vt| !(1..=63).contains(vt)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid fixture VT set",
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
        let fixture = Fixture {
            current: Arc::new(AtomicU32::new(current)),
            release_calls: Arc::new(AtomicUsize::new(0)),
            foreground_calls: Arc::new(AtomicUsize::new(0)),
            restored: Arc::new(AtomicUsize::new(0)),
            fail_release: Arc::new(AtomicBool::new(false)),
            notices: notices.clone(),
            event: event.clone(),
        };
        let current = fixture.current.clone();
        let releases = fixture.release_calls.clone();
        let queries = fixture.foreground_calls.clone();
        let restored = fixture.restored.clone();
        let fail_release = fixture.fail_release.clone();
        let native_event = event.clone();
        let native_failed = failed.clone();
        let thread = std::thread::Builder::new()
            .name("vt-mechanical-fixture".into())
            .spawn(move || {
                let _waiting = waiting;
                let mut pending = None;
                let mut claimed = vts;
                let emit = |notice| -> io::Result<()> {
                    notices
                        .try_send(notice)
                        .map_err(|_| io::Error::other("fixture notices lost"))?;
                    notify(&native_event);
                    Ok(())
                };
                while let Ok(command) = receiver.recv() {
                    match command {
                        Command::Foreground(reply) => {
                            queries.fetch_add(1, Ordering::AcqRel);
                            let _ = reply.send(Ok(current.load(Ordering::Acquire)));
                        }
                        Command::Switch(target, reply) => {
                            let result = if !(1..=63).contains(&target) {
                                Err(io::Error::from_raw_os_error(libc::EINVAL))
                            } else if current.load(Ordering::Acquire) == target {
                                Ok(())
                            } else if claimed.contains(&current.load(Ordering::Acquire)) {
                                pending = Some(target);
                                emit(Notice::ReleaseRequested)
                            } else {
                                current.store(target, Ordering::Release);
                                if claimed.contains(&target) {
                                    emit(Notice::ForegroundAcquired)
                                } else {
                                    Ok(())
                                }
                            };
                            let _ = reply.send(result);
                        }
                        Command::Release(allow, reply) => {
                            releases.fetch_add(1, Ordering::AcqRel);
                            let result = if fail_release.load(Ordering::Acquire) {
                                Err(io::Error::from_raw_os_error(libc::EIO))
                            } else if let Some(target) = pending.take().filter(|_| allow) {
                                current.store(target, Ordering::Release);
                                if claimed.contains(&target) {
                                    emit(Notice::ForegroundAcquired)
                                } else {
                                    Ok(())
                                }
                            } else {
                                Ok(())
                            };
                            let _ = reply.send(result);
                        }
                        Command::Restore(reply) => {
                            restored.fetch_add(claimed.len(), Ordering::AcqRel);
                            claimed.clear();
                            let _ = reply.send(Ok(()));
                        }
                        Command::Shutdown(reply) => {
                            restored.fetch_add(claimed.len(), Ordering::AcqRel);
                            let _ = reply.send(Ok(()));
                            return Ok(());
                        }
                    }
                }
                native_failed.store(true, Ordering::Release);
                notify(&native_event);
                Err(stopped())
            })?;
        let owner = Self {
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
            startup: None,
        };
        Ok((owner, fixture))
    }
}
