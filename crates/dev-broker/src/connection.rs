//! One independently owned seatd transport. Output is a single ordered stream
//! produced by its caller; close notification cannot be blocked by data.
//! The caller drives this future on its server runtime; no executor is created.

use crate::seatd::{
    protocol::{MAX_BUFFER_LEN, Packet},
    transport::{Connection, ReadStatus},
};
use std::collections::VecDeque;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::io::{Interest, unix::AsyncFd};
use tokio::sync::{mpsc, oneshot, watch};

pub struct Request<K> {
    pub connection: K,
    pub packet: Packet,
    pub done: oneshot::Sender<()>,
}

pub enum Event<K> {
    Delivered { connection: K, tag: u64 },
}

pub struct Output {
    pub permission: Option<crate::permit::Permit>,
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

pub async fn run<K: Copy + Send + 'static>(
    id: K,
    descriptor: OwnedFd,
    mut output: mpsc::Receiver<Output>,
    mut closed: watch::Receiver<bool>,
    requests: mpsc::Sender<Request<K>>,
    events: mpsc::Sender<Event<K>>,
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
            connection.queue_checked(next.bytes, next.fd, next.permission)?;
            if let Some(quota) = next.quota {
                quotas.push(quota);
            }
            if let Some(tag) = next.tag {
                tags.push_back(tag);
            }
            continue;
        }
        if pending.is_some()
            && connection.can_process_input()
            && let Some(packet) = connection.take_disable_ack()?
        {
            let (done, _completed) = oneshot::channel();
            tokio::select! {
                biased;
                _ = closing(&mut closed) => return Ok(()),
                sent = requests.send(Request { connection: id, packet, done }) => if sent.is_err() { return Ok(()) },
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
                connection.queue_checked(next.bytes, next.fd, next.permission)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seatd::protocol as wire;
    use std::{io::Write, os::unix::net::UnixStream, time::Duration};
    #[tokio::test]
    async fn disable_ack_overtakes_unadmitted_policy_wait_without_reordering_normal_requests() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let (port, output, closed) = channel();
        let (requests, mut incoming) = mpsc::channel(8);
        let (events, _deliveries) = mpsc::channel(8);
        let transport = tokio::spawn(run(1u64, server.into(), output, closed, requests, events));
        client
            .write_all(&wire::packet(wire::CLIENT_OPEN_DEVICE, b"pending").unwrap())
            .unwrap();
        let open = incoming.recv().await.unwrap();
        assert_eq!(open.packet.opcode, wire::CLIENT_OPEN_DEVICE);
        // Simulate a parent-owned admission read waiting behind a writer.
        client.write_all(&wire::empty(wire::CLIENT_PING)).unwrap();
        client
            .write_all(&wire::empty(wire::CLIENT_DISABLE_SEAT))
            .unwrap();
        let ack = tokio::time::timeout(Duration::from_secs(1), incoming.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ack.packet.opcode, wire::CLIENT_DISABLE_SEAT);
        let _ = ack.done.send(());
        assert!(
            tokio::time::timeout(Duration::from_millis(5), incoming.recv())
                .await
                .is_err()
        );
        open.done.send(()).unwrap();
        let ping = tokio::time::timeout(Duration::from_secs(1), incoming.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ping.packet.opcode, wire::CLIENT_PING);
        let _ = ping.done.send(());
        port.close.signal();
        transport.await.unwrap().unwrap();
    }
}
