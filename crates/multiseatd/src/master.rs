//! Exact authenticated context-master lifetime. Never acquires by numeric PID.
use libmultiseatd::ContextId;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{io::unix::AsyncFd, sync::watch};

#[derive(Debug)]
pub struct Master {
    fd: OwnedFd,
    pub pid: u32,
    pub start_time: u64,
    dead: AtomicBool,
}
impl AsRawFd for Master {
    fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}
impl Master {
    pub fn acquire(fd: OwnedFd) -> io::Result<Arc<Self>> {
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?;
        let pid = info
            .lines()
            .find_map(|l| l.strip_prefix("Pid:\t"))
            .and_then(|p| p.parse::<u32>().ok())
            .filter(|p| *p > 0 && *p <= i32::MAX as u32)
            .ok_or_else(|| io::Error::other("unusable bus ProcessFD"))?;
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let start_time = stat
            .rsplit_once(')')
            .and_then(|(_, tail)| tail.split_whitespace().nth(19))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::other("malformed process stat"))?;
        let master = Arc::new(Self {
            fd,
            pid,
            start_time,
            dead: AtomicBool::new(false),
        });
        if !master.is_alive()? {
            return Err(io::Error::other("bus ProcessFD process exited"));
        }
        Ok(master)
    }
    pub fn fd_clone(&self) -> io::Result<OwnedFd> {
        self.fd.try_clone()
    }
    pub fn is_alive(&self) -> io::Result<bool> {
        if self.dead.load(Ordering::Acquire) {
            return Ok(false);
        }
        let mut p = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            if unsafe { libc::poll(&mut p, 1, 0) } >= 0 {
                break;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
        if p.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
            return Err(io::Error::other("invalid ProcessFD observation"));
        }
        let alive = p.revents & (libc::POLLIN | libc::POLLHUP) == 0;
        if !alive {
            self.dead.store(true, Ordering::Release);
        }
        Ok(alive)
    }
    #[cfg(test)]
    pub fn current() -> Arc<Self> {
        use std::os::fd::FromRawFd;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) as i32 };
        assert!(fd >= 0);
        Self::acquire(unsafe { OwnedFd::from_raw_fd(fd) }).unwrap()
    }
}
pub struct MasterWatch {
    pub id: ContextId,
    pub fd: AsyncFd<OwnedFd>,
    pub cancelled: watch::Receiver<()>,
    pub master: Arc<Master>,
}
impl MasterWatch {
    pub async fn wait(mut self) -> io::Result<Option<ContextId>> {
        tokio::select! {
            r = self.fd.readable() => {
                let _ready = r?;
                if self.master.is_alive()? { return Err(io::Error::other("spurious ProcessFD readiness")); }
                Ok(Some(self.id))
            }
            _ = self.cancelled.changed() => Ok(None),
        }
    }
}
