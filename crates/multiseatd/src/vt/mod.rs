//! A dedicated native task owns the seat's single VT for its whole lifetime.
mod linux;
use crate::resources::{Permit, Resources};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use tokio::sync::{oneshot, watch};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Starting,
    Absent,
    Foreground,
    Releasing,
    Away,
    Acquiring,
    Failed,
}
#[derive(Clone)]
pub struct Facts {
    pub terminal: u32,
    pub generation: u64,
    pub phase: Phase,
    pub gate: Permit,
    pub error: String,
}
impl Facts {
    fn advance(&mut self, phase: Phase, publisher: &watch::Sender<Self>) -> io::Result<()> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("VT generation exhaustion"))?;
        self.phase = phase;
        publisher.send_replace(self.clone());
        Ok(())
    }
}
enum Command {
    Presence {
        enabled: bool,
        reply: oneshot::Sender<io::Result<()>>,
    },
    Acquire(Permit),
    Release(u64),
    Switch {
        target: u32,
        permit: Permit,
        reply: oneshot::Sender<io::Result<()>>,
    },
    Stop,
    #[cfg(test)]
    Signal(i32),
}
#[derive(Clone)]
pub struct Port {
    commands: mpsc::SyncSender<Command>,
    wake: Arc<UnixStream>,
    pub facts: watch::Receiver<Facts>,
}
impl Port {
    fn send(&self, command: Command) -> io::Result<()> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => io::Error::from_raw_os_error(libc::EAGAIN),
                mpsc::TrySendError::Disconnected(_) => io::Error::other("VT owner disconnected"),
            })?;
        match (&*self.wake).write(&[1]) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error),
        }
    }
    pub async fn presence_after_cleanup(&self, enabled: bool) -> io::Result<()> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::Presence { enabled, reply })?;
        receiver.await.map_err(io::Error::other)?
    }
    pub fn acquire(&self, permit: Permit) -> io::Result<()> {
        self.send(Command::Acquire(permit))
    }
    pub fn release_ready(&self, generation: u64) -> io::Result<()> {
        self.send(Command::Release(generation))
    }
    pub fn switch(
        &self,
        target: u32,
        permit: Permit,
    ) -> io::Result<oneshot::Receiver<io::Result<()>>> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::Switch {
            target,
            permit,
            reply,
        })?;
        Ok(receiver)
    }
    pub async fn failed(mut self) -> io::Result<()> {
        loop {
            if self.facts.borrow().phase == Phase::Failed {
                return Err(io::Error::other(self.facts.borrow().error.clone()));
            }
            self.facts.changed().await.map_err(io::Error::other)?;
        }
    }
}

pub struct Owner {
    port: Port,
    thread: Option<JoinHandle<io::Result<()>>>,
    resources: Arc<Resources>,
}
impl Owner {
    pub async fn start(
        terminal: u32,
        resources: Arc<Resources>,
        enabled: bool,
    ) -> io::Result<Self> {
        Self::with_operations(terminal, resources, Box::<linux::Linux>::default(), enabled).await
    }
    async fn with_operations(
        terminal: u32,
        resources: Arc<Resources>,
        mut operations: Box<dyn linux::Operations>,
        enabled: bool,
    ) -> io::Result<Self> {
        let (commands, receiver) = mpsc::sync_channel(32);
        let (wake, mut input) = UnixStream::pair()?;
        wake.set_nonblocking(true)?;
        input.set_nonblocking(true)?;
        let closed = Permit::new();
        closed.fence();
        let facts = Facts {
            terminal,
            generation: 0,
            phase: Phase::Starting,
            gate: closed,
            error: String::new(),
        };
        let (publisher, snapshot) = watch::channel(facts.clone());
        let port = Port {
            commands,
            wake: Arc::new(wake),
            facts: snapshot,
        };
        let (ready, started) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("multiseat-vt".into())
            .spawn(move || {
                let mut facts = facts;
                let mut ready = Some(ready);
                let mut stopping = false;
                // Keep operations OUTSIDE the unwind boundary. A bug reports failure
                // immediately but cannot restore VT_AUTO before outer revocation.
                let outcome = catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
                    let signals = linux::signals()?;
                    if enabled {
                        install(&mut facts, &publisher, &mut *operations)?;
                    } else {
                        facts.advance(Phase::Absent, &publisher)?;
                    }
                    // Consume signals already pending before announcing readiness.
                    while let Some(signal) = linux::signal(&signals)? {
                        signal_event(signal, &mut facts, &publisher, &mut *operations)?;
                    }
                    let _ = ready.take().expect("startup reply").send(Ok(()));
                    loop {
                        let mut descriptors = [
                            libc::pollfd {
                                fd: signals.as_raw_fd(),
                                events: libc::POLLIN,
                                revents: 0,
                            },
                            libc::pollfd {
                                fd: input.as_raw_fd(),
                                events: libc::POLLIN,
                                revents: 0,
                            },
                        ];
                        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) };
                        if result < 0 {
                            let error = io::Error::last_os_error();
                            if error.kind() == io::ErrorKind::Interrupted {
                                continue;
                            }
                            return Err(error);
                        }
                        // Kernel facts fence queued requests before processing them.
                        for _ in 0..64 {
                            let Some(signal) = linux::signal(&signals)? else {
                                break;
                            };
                            signal_event(signal, &mut facts, &publisher, &mut *operations)?;
                        }
                        let mut bytes = [0; 64];
                        let _ = input.read(&mut bytes);
                        for _ in 0..32 {
                            for _ in 0..64 {
                                let Some(signal) = linux::signal(&signals)? else {
                                    break;
                                };
                                signal_event(signal, &mut facts, &publisher, &mut *operations)?;
                            }
                            let command = match receiver.try_recv() {
                                Ok(command) => command,
                                Err(mpsc::TryRecvError::Empty) => break,
                                Err(_) => return Err(io::Error::other("VT control owner lost")),
                            };
                            match command {
                                Command::Presence { enabled, reply } => {
                                    if enabled && facts.phase == Phase::Absent {
                                        install(&mut facts, &publisher, &mut *operations)?;
                                    } else if !enabled && facts.phase != Phase::Absent {
                                        facts.gate.fence();
                                        operations.restore()?;
                                        facts.advance(Phase::Absent, &publisher)?;
                                    }
                                    for _ in 0..64 {
                                        let Some(signal) = linux::signal(&signals)? else {
                                            break;
                                        };
                                        signal_event(
                                            signal,
                                            &mut facts,
                                            &publisher,
                                            &mut *operations,
                                        )?;
                                    }
                                    let _ = reply.send(Ok(()));
                                }
                                Command::Stop => {
                                    stopping = true;
                                    facts.gate.fence();
                                    return operations.restore();
                                }
                                Command::Acquire(permit) => {
                                    if permit.is_open() && facts.phase == Phase::Away {
                                        operations.switch(terminal)?;
                                        facts.advance(Phase::Acquiring, &publisher)?;
                                    }
                                }
                                Command::Release(generation) => {
                                    if facts.phase == Phase::Releasing
                                        && facts.generation == generation
                                    {
                                        operations.release()?;
                                        facts.advance(Phase::Away, &publisher)?;
                                    }
                                }
                                Command::Switch {
                                    target,
                                    permit,
                                    reply,
                                } => {
                                    let result =
                                        if !permit.is_open() || facts.phase != Phase::Foreground {
                                            Err(io::Error::from_raw_os_error(libc::EACCES))
                                        } else if !(1..=63).contains(&target) {
                                            Err(io::Error::from_raw_os_error(libc::EINVAL))
                                        } else {
                                            operations.switch(target)
                                        };
                                    let _ = reply.send(result);
                                }
                                #[cfg(test)]
                                Command::Signal(signal) => {
                                    signal_event(signal, &mut facts, &publisher, &mut *operations)?
                                }
                            }
                        }
                    }
                }));
                let failure = match outcome {
                    Ok(Ok(())) => return Ok(()),
                    Ok(Err(error)) => error.to_string(),
                    Err(_) => "VT owner panicked".into(),
                };
                if stopping {
                    return Err(io::Error::other(failure));
                }
                facts.gate.fence();
                facts.error = failure.clone();
                let _ = facts.advance(Phase::Failed, &publisher);
                if let Some(ready) = ready.take() {
                    let _ = ready.send(Err(io::Error::other(failure.clone())));
                }
                // Stay alive (and retain terminal ownership) until outer cleanup has
                // explicitly attempted revocation and sends the final stop command.
                while let Ok(command) = receiver.recv() {
                    if matches!(command, Command::Stop) {
                        break;
                    }
                }
                let restored = operations.restore();
                if let Err(error) = restored {
                    tracing::error!(%error, "VT restoration after owner failure failed");
                }
                Err(io::Error::other(failure))
            })?;
        let mut owner = Self {
            port,
            thread: Some(thread),
            resources,
        };
        match started.await {
            Ok(Ok(())) => Ok(owner),
            Ok(Err(error)) => {
                let _ = owner.finish();
                Err(error)
            }
            Err(error) => {
                let _ = owner.finish();
                Err(io::Error::other(error))
            }
        }
    }
    pub fn port(&self) -> Port {
        self.port.clone()
    }
    pub fn finish(&mut self) -> io::Result<()> {
        if self.resources.pending() != (0, 0) {
            return Err(io::Error::other(
                "terminal restoration blocked by retained resources",
            ));
        }
        self.finish_unchecked()
    }
    fn finish_unchecked(&mut self) -> io::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        let sent = self
            .port
            .commands
            .send(Command::Stop)
            .map_err(io::Error::other);
        let _ = (&*self.port.wake).write(&[1]);
        let joined = thread
            .join()
            .map_err(|_| io::Error::other("VT native owner join panicked"));
        sent?;
        joined?
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        if self.thread.is_some() {
            // Main-owner unwind is also ordered: attempt both resource classes
            // before allowing terminal restoration. Errors are not a clean pass.
            for error in self.resources.cleanup() {
                tracing::error!(%error, "VT owner fallback cleanup incomplete");
            }
            if let Err(error) = self.finish_unchecked() {
                tracing::error!(%error, "VT owner shutdown failed");
            }
        }
    }
}

fn install(
    facts: &mut Facts,
    publisher: &watch::Sender<Facts>,
    operations: &mut dyn linux::Operations,
) -> io::Result<()> {
    operations.open(facts.terminal)?;
    if operations.foreground()? == facts.terminal {
        facts.gate = Permit::new();
        facts.advance(Phase::Foreground, publisher)
    } else {
        facts.advance(Phase::Away, publisher)
    }
}

fn signal_event(
    signal: i32,
    facts: &mut Facts,
    publisher: &watch::Sender<Facts>,
    operations: &mut dyn linux::Operations,
) -> io::Result<()> {
    if facts.phase == Phase::Absent {
        return Ok(());
    }
    match signal {
        libc::SIGUSR1 => {
            if facts.phase != Phase::Releasing {
                facts.gate.fence();
                facts.advance(Phase::Releasing, publisher)?;
            }
        }
        libc::SIGUSR2 => {
            if facts.phase == Phase::Releasing {
                return Err(io::Error::other("acquire arrived before release barrier"));
            }
            if facts.phase != Phase::Foreground {
                operations.acquire()?;
                if operations.foreground()? != facts.terminal {
                    return Err(io::Error::other("acquired VT is not foreground"));
                }
                facts.gate = Permit::new();
                facts.advance(Phase::Foreground, publisher)?;
            }
        }
        _ => return Err(io::Error::other("unexpected VT signal")),
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
