//! One independently owned seatd transport. Output is a single ordered stream
//! produced by its controller; close notification cannot be blocked by data.

use crate::seatd::{
    protocol::{MAX_BUFFER_LEN, Packet},
    transport::{Connection, ReadStatus},
};
use libmultiseatd::ConnectionId;
use std::collections::VecDeque;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::io::{Interest, unix::AsyncFd};
use tokio::sync::{mpsc, oneshot, watch};

pub struct Request {
    pub connection: ConnectionId,
    pub packet: Packet,
    pub done: oneshot::Sender<()>,
}

pub enum Event {
    Delivered { connection: ConnectionId, tag: u64 },
}

pub struct Output {
    pub bytes: Vec<u8>,
    pub fd: Option<OwnedFd>,
    pub tag: Option<u64>,
    pub quota: Option<tokio::sync::OwnedSemaphorePermit>,
}

#[derive(Clone)]
pub struct Close {
    changed: watch::Sender<bool>,
    alive: Arc<AtomicBool>,
}

impl Close {
    pub fn gate(&self) -> Arc<AtomicBool> {
        self.alive.clone()
    }
    pub fn signal(&self) {
        self.alive.store(false, Ordering::Release);
        self.changed.send_replace(true);
    }
    pub fn is_closed(&self) -> bool {
        !self.alive.load(Ordering::Acquire)
    }
}

pub struct Port {
    output: mpsc::Sender<Output>,
    pub close: Close,
}

impl Port {
    pub fn send(&self, output: Output) -> bool {
        if self.close.is_closed() {
            return false;
        }
        if self.output.try_send(output).is_err() {
            self.close.signal();
            return false;
        }
        true
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        self.close.signal();
    }
}

pub fn channel() -> (Port, mpsc::Receiver<Output>, watch::Receiver<bool>) {
    let (output, receiver) = mpsc::channel(32);
    let (close, closed) = watch::channel(false);
    (
        Port {
            output,
            close: Close {
                changed: close,
                alive: Arc::new(AtomicBool::new(true)),
            },
        },
        receiver,
        closed,
    )
}

async fn closing(closed: &mut watch::Receiver<bool>) {
    while !*closed.borrow_and_update() {
        if closed.changed().await.is_err() {
            return;
        }
    }
}

async fn completed(
    pending: &mut Option<oneshot::Receiver<()>>,
) -> Result<(), oneshot::error::RecvError> {
    match pending {
        Some(pending) => pending.await,
        None => std::future::pending().await,
    }
}

pub async fn run(
    id: ConnectionId,
    descriptor: OwnedFd,
    mut output: mpsc::Receiver<Output>,
    mut closed: watch::Receiver<bool>,
    requests: mpsc::Sender<Request>,
    events: mpsc::Sender<Event>,
) -> io::Result<()> {
    let mut connection = Connection::new(descriptor)?;
    let duplicate = connection.fd().try_clone_to_owned()?;
    // SAFETY: an owned, never-replaced duplicate remains live until watch drop.
    let watched = unsafe { AsyncFd::register(duplicate) }?;
    let mut pending = None;
    let mut tags = VecDeque::new();
    let mut quotas = Vec::new();
    loop {
        if *closed.borrow() {
            return Ok(());
        }
        if !connection.wants_write() || connection.flush()? {
            quotas.clear();
            while let Some(tag) = tags.pop_front() {
                tokio::select! {
                    biased;
                    _ = closing(&mut closed) => return Ok(()),
                    sent = events.send(Event::Delivered { connection: id, tag }) => if sent.is_err() { return Ok(()) },
                }
            }
        }
        // Output queue order is also the order of protocol replies and enable/
        // disable notifications; OPENED can never be overtaken by ENABLE.
        if let Ok(next) = output.try_recv() {
            connection.queue(next.bytes, next.fd)?;
            if let Some(quota) = next.quota {
                quotas.push(quota);
            }
            if let Some(tag) = next.tag {
                tags.push_back(tag);
            }
            continue;
        }
        if pending.is_none()
            && connection.can_process_input()
            && let Some(packet) = connection.next_packet()?
        {
            let (done, receiver) = oneshot::channel();
            tokio::select! {
                biased;
                _ = closing(&mut closed) => return Ok(()),
                sent = requests.send(Request { connection: id, packet, done }) => if sent.is_err() { return Ok(()) },
            }
            pending = Some(receiver);
            continue;
        }
        if connection.is_eof() {
            return Ok(());
        }
        // Recheck directly after freeing decoder space. Readiness may have
        // been cleared while the buffer was full and kernel bytes remained.
        if connection.pending_input() < MAX_BUFFER_LEN {
            match connection.read()? {
                ReadStatus::Eof => return Ok(()),
                ReadStatus::Progress => {
                    if connection.received_fd_count() != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected client descriptors",
                        ));
                    }
                    continue;
                }
                ReadStatus::WouldBlock => {}
            }
        }
        let interest = if connection.wants_write() {
            Interest::READABLE | Interest::WRITABLE
        } else {
            Interest::READABLE
        };
        tokio::select! {
            biased;
            _ = closing(&mut closed) => return Ok(()),
            result = completed(&mut pending), if pending.is_some() => {
                if result.is_err() { return Ok(()) }
                pending = None;
            }
            next = output.recv() => {
                let Some(next) = next else { return Ok(()) };
                connection.queue(next.bytes, next.fd)?;
                if let Some(quota) = next.quota { quotas.push(quota); }
                if let Some(tag) = next.tag { tags.push_back(tag); }
            }
            readiness = watched.ready(interest) => {
                let mut ready = readiness?;
                // EOF must stay observable even if a slow resource request has
                // filled the bounded decoder. No next request overtakes it.
                if ready.ready().is_read_closed() { return Ok(()) }
                if ready.ready().is_readable() && connection.pending_input() < MAX_BUFFER_LEN {
                    match connection.read()? {
                        ReadStatus::Eof => return Ok(()),
                        ReadStatus::Progress | ReadStatus::WouldBlock => {},
                    }
                    if connection.received_fd_count() != 0 { return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected client descriptors")) }
                }
                if ready.ready().is_writable() { connection.flush()?; }
                ready.clear_ready();
            }
        }
    }
}
