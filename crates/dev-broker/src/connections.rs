//! Authoritative transport membership and lifetime state. No context selection,
//! UID grants or VT policy: callers supply access permits and shared deadlines.
use crate::connection::{Close, Output, Port};
use crate::permit::Permit;
use crate::seatd::protocol as wire;
use std::collections::BTreeMap;
use std::io;
use std::ops::Index;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Membership {
    Connected,
    Disabled,
    Enabled,
    PendingDisable,
}
impl Membership {
    pub fn name(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
            Self::PendingDisable => "pending-disable",
        }
    }
}

/// Read-only state borrowed from its owning table. Only table methods mutate
/// membership; the caller may fence the supplied access permit at any time.
pub struct Connection {
    pub membership: Membership,
    pub epoch: Option<Permit>,
    pub gone: bool,
    pub closing: bool,
    pub cleanup: bool,
    pub cleanup_running: bool,
    pub retry: Instant,
    pub error: String,
    port: Port,
    enabled_tag: Option<u64>,
    close_seat: Option<oneshot::Sender<()>>,
}
impl Connection {
    pub fn live(&self) -> bool {
        !self.closing && !self.gone && !self.port.close.is_closed()
    }
    pub fn send(&self, output: Output) -> bool {
        self.port.send(output)
    }
    fn fence(&self) {
        if let Some(epoch) = &self.epoch {
            epoch.fence();
        }
    }
}

/// K identifies an owning generation, never a recyclable public socket number.
pub struct Connections<K> {
    entries: BTreeMap<K, Connection>,
    tag: u64,
    limit: usize,
}
impl<K: Copy + Ord> Connections<K> {
    pub fn new(limit: usize) -> Self {
        assert!(limit > 0);
        Self {
            entries: BTreeMap::new(),
            tag: 0,
            limit,
        }
    }
    /// The caller must first reserve a connection quota and a fresh correlation
    /// key. The returned close gate also protects failed endpoint publication.
    pub fn add(&mut self, key: K, port: Port) -> Close {
        assert!(self.entries.len() < self.limit && !self.entries.contains_key(&key));
        let close = port.close.clone();
        self.entries.insert(
            key,
            Connection {
                membership: Membership::Connected,
                epoch: None,
                gone: false,
                closing: false,
                cleanup: false,
                cleanup_running: false,
                retry: Instant::now(),
                error: String::new(),
                port,
                enabled_tag: None,
                close_seat: None,
            },
        );
        close
    }
    pub fn get(&self, key: &K) -> Option<&Connection> {
        self.entries.get(key)
    }
    pub fn remove(&mut self, key: K) -> io::Result<()> {
        if self
            .entries
            .get(&key)
            .is_some_and(|entry| !entry.gone || entry.cleanup || entry.cleanup_running)
        {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        self.entries.remove(&key);
        Ok(())
    }
    pub fn send(&self, key: K, bytes: Vec<u8>, tag: Option<u64>) -> bool {
        self.entries.get(&key).is_some_and(|entry| {
            entry.send(Output {
                bytes,
                fd: None,
                tag,
                quota: None,
            })
        })
    }
    pub fn prepare(&mut self, key: K, epoch: &Permit) -> Option<Permit> {
        let entry = self.entries.get_mut(&key)?;
        if !entry.live()
            || matches!(
                entry.membership,
                Membership::Connected | Membership::PendingDisable
            )
        {
            return None;
        }
        let permit = epoch.gated(entry.port.close.gate());
        entry.epoch = Some(permit.clone());
        Some(permit)
    }
    pub fn enable(&mut self, key: K, epoch: Option<&Permit>) -> io::Result<bool> {
        let entry = &self.entries[&key];
        if !entry.live()
            || entry.membership != Membership::Disabled
            || !epoch.is_some_and(Permit::is_open)
        {
            return Ok(false);
        }
        self.tag = self
            .tag
            .checked_add(1)
            .ok_or_else(|| io::Error::other("output generation exhaustion"))?;
        let entry = self.entries.get_mut(&key).expect("connection");
        entry.membership = Membership::Enabled;
        entry.enabled_tag = Some(self.tag);
        entry.epoch = epoch.map(|epoch| epoch.gated(entry.port.close.gate()));
        Ok(self.send(key, wire::empty(wire::SERVER_ENABLE_SEAT), Some(self.tag)))
    }
    /// True means an ACK is still owed. Caller enforces its shared deadline by
    /// permanently closing the connection, never by recycling an ACK cycle.
    pub fn pause(&mut self, key: K) -> bool {
        let entry = self.entries.get_mut(&key).expect("connection");
        entry.fence();
        if entry.membership != Membership::Enabled {
            return false;
        }
        entry.membership = Membership::PendingDisable;
        self.send(key, wire::empty(wire::SERVER_DISABLE_SEAT), None);
        true
    }
    pub fn close(&mut self, key: K) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.closing = true;
            entry.port.close.signal();
            entry.fence();
        }
    }
    pub fn gone(&mut self, key: K) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.gone = true;
            entry.closing = true;
            entry.cleanup = true;
            entry.fence();
        }
    }
    pub fn delivered(&mut self, key: K, tag: u64) -> bool {
        if let Some(entry) = self.entries.get_mut(&key)
            && entry.enabled_tag == Some(tag)
        {
            entry.enabled_tag = None;
            true
        } else {
            false
        }
    }
    pub fn valid_packet(&self, key: K, packet: &wire::Packet) -> bool {
        let Some(entry) = self.entries.get(&key).filter(|entry| entry.live()) else {
            return false;
        };
        let member = entry.membership != Membership::Connected;
        let valid = match packet.opcode {
            wire::CLIENT_OPEN_SEAT
            | wire::CLIENT_CLOSE_SEAT
            | wire::CLIENT_DISABLE_SEAT
            | wire::CLIENT_PING => wire::parse_empty(&packet.payload),
            wire::CLIENT_OPEN_DEVICE => wire::parse_path(&packet.payload).map(|_| ()),
            wire::CLIENT_CLOSE_DEVICE | wire::CLIENT_SWITCH_SESSION => {
                wire::parse_i32(&packet.payload).map(|_| ())
            }
            _ => Err(libc::EBADMSG),
        };
        valid.is_ok()
            && (member
                || packet.opcode == wire::CLIENT_OPEN_SEAT
                || packet.opcode == wire::CLIENT_PING)
            && !(packet.opcode == wire::CLIENT_OPEN_SEAT && member)
    }
    pub fn open_seat(&mut self, key: K) -> bool {
        let entry = self.entries.get_mut(&key).expect("connection");
        if !entry.live() || entry.cleanup || entry.membership != Membership::Connected {
            return false;
        }
        entry.membership = Membership::Disabled;
        true
    }
    pub fn close_seat(&mut self, key: K, done: oneshot::Sender<()>) {
        let entry = self.entries.get_mut(&key).expect("connection");
        entry.membership = Membership::Connected;
        entry.cleanup = true;
        entry.close_seat = Some(done);
        entry.fence();
    }
    pub fn acknowledge(&mut self, key: K) {
        let entry = self.entries.get_mut(&key).expect("connection");
        if !entry.live() {
            return;
        }
        if matches!(
            entry.membership,
            Membership::PendingDisable | Membership::Disabled
        ) {
            entry.membership = Membership::Disabled;
            self.send(key, wire::empty(wire::SERVER_SEAT_DISABLED), None);
        } else {
            self.close(key);
        }
    }
    pub fn cleanup_started(&mut self, key: K) {
        self.entries
            .get_mut(&key)
            .expect("connection")
            .cleanup_running = true;
    }
    pub fn cleanup_completed(&mut self, key: K, error: Option<String>) -> bool {
        let Some(entry) = self.entries.get_mut(&key) else {
            return false;
        };
        entry.cleanup_running = false;
        if let Some(error) = error {
            entry.error = error;
            entry.retry = Instant::now() + Duration::from_secs(1);
            false
        } else {
            entry.cleanup = false;
            entry.error.clear();
            if let Some(done) = entry.close_seat.take() {
                self.send(key, wire::empty(wire::SERVER_SEAT_CLOSED), None);
                let _ = done.send(());
            }
            true
        }
    }
    pub fn error(&mut self, key: K, error: String) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.error = error;
        }
    }
}
#[cfg(test)]
mod tests;

impl<K: Ord> Index<&K> for Connections<K> {
    type Output = Connection;
    fn index(&self, key: &K) -> &Connection {
        &self.entries[key]
    }
}
