//! Native mechanics only. Every terminal ioctl runs on the VT_PROCESS owner task.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
struct Mode {
    mode: u8,
    wait: u8,
    release: i16,
    acquire: i16,
    force: i16,
}
#[repr(C)]
#[derive(Default)]
struct State {
    active: u16,
    signal: u16,
    state: u16,
}
struct Claimed {
    file: File,
    mode: Mode,
    display: i32,
    keyboard: i32,
}
pub(super) struct Linux {
    console: File,
    terminals: BTreeMap<u32, Claimed>,
}
impl Linux {
    pub fn new(vts: &BTreeSet<u32>) -> io::Result<Self> {
        if vts.is_empty() || vts.iter().any(|vt| !(1..=63).contains(vt)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "require unique configured VTs in 1..63",
            ));
        }
        let console = tty(0)?;
        for metadata in [
            console.metadata()?,
            std::fs::symlink_metadata("/dev/console")?,
        ] {
            if metadata.uid() != 0
                || metadata.mode() & 0o077 != 0
                || metadata.mode() & libc::S_IFMT != libc::S_IFCHR
            {
                return Err(io::Error::other(
                    "console aliases must be root-owned character nodes without group/other access",
                ));
            }
        }
        Ok(Self {
            console,
            terminals: BTreeMap::new(),
        })
    }
    pub fn claim_all(&mut self, vts: &BTreeSet<u32>) -> io::Result<()> {
        for &vt in vts {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.claim_one(vt)))
                    .unwrap_or_else(|_| Err(io::Error::other("native claim panicked")));
            if let Err(error) = result {
                if let Err(cleanup) = self.restore_all() {
                    // Failed rows/FDs stay owned by this same native task.
                    return Err(io::Error::other(format!(
                        "VT{vt}: {error}; partial claim restoration: {cleanup}"
                    )));
                }
                return Err(error);
            }
        }
        Ok(())
    }
    fn claim_one(&mut self, vt: u32) -> io::Result<()> {
        let file = tty(vt)?;
        let metadata = file.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "reserved VT must be root-owned without group/other access",
            ));
        }
        let mut mode = Mode::default();
        pointer(&file, VT_GETMODE, &mut mode)?;
        let mut display = 0;
        pointer(&file, KDGETMODE, &mut display)?;
        let mut keyboard = 0;
        pointer(&file, KDGKBMODE, &mut keyboard)?;
        let mut session: libc::pid_t = 0;
        let occupied = unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCGSID, &mut session) } == 0
            && session > 0;
        if occupied || mode.mode != 0 || display != 0 {
            return Err(io::Error::other(
                "reserved VT is occupied; coordinate gettys/controllers before startup",
            ));
        }
        ensure_no_controlling_lineage(metadata.rdev())?;
        // Save ownership BEFORE the first native mutation, including partial claims.
        self.terminals.insert(
            vt,
            Claimed {
                file,
                mode,
                display,
                keyboard,
            },
        );
        let file = &self.terminals[&vt].file;
        let mut owned = owned_mode();
        pointer(file, VT_SETMODE, &mut owned)?;
        value(file, KDSKBMODE, 4)?;
        value(file, KDSETMODE, 1)
    }
    pub fn foreground(&self) -> io::Result<u32> {
        let mut state = State::default();
        pointer(&self.console, VT_GETSTATE, &mut state)?;
        Ok(u32::from(state.active))
    }
    pub fn request_switch(&self, target: u32) -> io::Result<()> {
        if !(1..=63).contains(&target) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        value(&self.console, VT_ACTIVATE, target as i32)
    }
    pub fn release(&self, allow: bool) -> io::Result<()> {
        let current = self.foreground()?;
        let Some(terminal) = self.terminals.get(&current) else {
            return Ok(());
        };
        validate_owned(&terminal.file)?;
        match value(&terminal.file, VT_RELDISP, i32::from(allow)) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
                // Verify the addressed claim still belongs to us, and re-query
                // native current ownership. A switch to another owned VT can
                // itself make this old request obsolete; no historical IDs.
                validate_owned(&terminal.file)?;
                let now = self.foreground()?;
                if let Some(current) = self.terminals.get(&now) {
                    validate_owned(&current.file)?;
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    pub fn restore_all(&mut self) -> io::Result<()> {
        let mut failed = Vec::new();
        let mut restored = Vec::new();
        for (&vt, terminal) in &mut self.terminals {
            let first = value(&terminal.file, KDSKBMODE, terminal.keyboard).err();
            let second = value(&terminal.file, KDSETMODE, terminal.display).err();
            let third = pointer(&terminal.file, VT_SETMODE, &mut terminal.mode).err();
            if let Some(error) = first.or(second).or(third) {
                failed.push(format!("VT{vt}: {error}"));
            } else {
                restored.push(vt);
            }
        }
        for vt in restored {
            self.terminals.remove(&vt);
        }
        if failed.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failed.join("; ")))
        }
    }
}
// No Drop restoration: unwinding must never bypass the daemon's broker barrier.
fn owned_mode() -> Mode {
    Mode {
        mode: 1,
        wait: 0,
        release: libc::SIGUSR1 as i16,
        acquire: libc::SIGUSR2 as i16,
        force: 0,
    }
}
fn validate_owned(file: &File) -> io::Result<()> {
    let mut current = Mode::default();
    pointer(file, VT_GETMODE, &mut current)?;
    if current != owned_mode() {
        return Err(io::Error::other(
            "native VT ownership/mode changed unexpectedly",
        ));
    }
    Ok(())
}
fn tty(number: u32) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(format!("/dev/tty{number}"))?;
    let metadata = file.metadata()?;
    if metadata.mode() & libc::S_IFMT != libc::S_IFCHR
        || libc::major(metadata.rdev()) != 4
        || libc::minor(metadata.rdev()) != number
    {
        return Err(io::Error::other("not the configured Linux VT"));
    }
    Ok(file)
}
fn ensure_no_controlling_lineage(number: u64) -> io::Result<()> {
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let fields = stat
            .rsplit_once(") ")
            .ok_or_else(|| io::Error::other("invalid process terminal inventory"))?
            .1;
        let terminal = fields
            .split_whitespace()
            .nth(4)
            .and_then(|field| field.parse::<i64>().ok())
            .ok_or_else(|| io::Error::other("invalid process terminal inventory"))?;
        if terminal as u32 == number as u32 {
            return Err(io::Error::other(
                "reserved VT has a controlling-terminal lineage",
            ));
        }
    }
    Ok(())
}
const VT_GETMODE: libc::c_ulong = 0x5601;
const VT_SETMODE: libc::c_ulong = 0x5602;
const VT_GETSTATE: libc::c_ulong = 0x5603;
const VT_RELDISP: libc::c_ulong = 0x5605;
const VT_ACTIVATE: libc::c_ulong = 0x5606;
const KDGETMODE: libc::c_ulong = 0x4b3b;
const KDSETMODE: libc::c_ulong = 0x4b3a;
const KDGKBMODE: libc::c_ulong = 0x4b44;
const KDSKBMODE: libc::c_ulong = 0x4b45;
fn pointer<T>(file: &File, request: libc::c_ulong, value: &mut T) -> io::Result<()> {
    if unsafe { libc::ioctl(file.as_raw_fd(), request, value) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn value(file: &File, request: libc::c_ulong, value: i32) -> io::Result<()> {
    if unsafe { libc::ioctl(file.as_raw_fd(), request, value) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub(super) fn signals() -> io::Result<OwnedFd> {
    let mut mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGUSR1);
        libc::sigaddset(&mut mask, libc::SIGUSR2);
    }
    let result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
pub(super) fn signal(fd: &OwnedFd) -> io::Result<Option<i32>> {
    let mut info = std::mem::MaybeUninit::<libc::signalfd_siginfo>::uninit();
    let count = unsafe {
        libc::read(
            fd.as_raw_fd(),
            info.as_mut_ptr().cast(),
            size_of::<libc::signalfd_siginfo>(),
        )
    };
    if count == size_of::<libc::signalfd_siginfo>() as isize {
        return Ok(Some(unsafe { info.assume_init() }.ssi_signo as i32));
    }
    if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    if count < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::other("short VT signalfd read"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_or_out_of_range_sets_are_rejected_before_touching_terminals() {
        for vts in [BTreeSet::new(), BTreeSet::from([0]), BTreeSet::from([64])] {
            assert_eq!(
                Linux::new(&vts).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
    #[test]
    fn owned_modes_have_only_release_and_acquisition_signals() {
        let mode = owned_mode();
        assert_eq!(mode.mode, 1);
        assert_eq!(mode.release, libc::SIGUSR1 as i16);
        assert_eq!(mode.acquire, libc::SIGUSR2 as i16);
        assert_eq!(mode.force, 0);
    }
}
