//! All methods are called only on the task which installs VT_PROCESS.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub(super) trait Operations: Send {
    fn open(&mut self, terminal: u32) -> io::Result<()>;
    fn foreground(&mut self) -> io::Result<u32>;
    fn switch(&mut self, terminal: u32) -> io::Result<()>;
    fn release(&mut self) -> io::Result<()>;
    fn acquire(&mut self) -> io::Result<()>;
    fn restore(&mut self) -> io::Result<()>;
}

#[derive(Default)]
pub(super) struct Linux {
    console: Option<File>,
    terminal: Option<File>,
    original: Option<(Mode, i32, i32)>,
}
impl Linux {
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
}
impl Operations for Linux {
    fn open(&mut self, terminal: u32) -> io::Result<()> {
        if !(1..=63).contains(&terminal) {
            return Err(io::Error::other("graphical VT must be 1..63"));
        }
        self.console = Some(Self::tty(0)?);
        for metadata in [
            self.console.as_ref().expect("console").metadata()?,
            std::fs::metadata("/dev/console")?,
        ] {
            if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
                return Err(io::Error::other(
                    "Linux console aliases must be root-owned with no group/other access",
                ));
            }
        }
        let file = Self::tty(terminal)?;
        let metadata = file.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "graphical VT must be root-owned mode 0600 without group/other access",
            ));
        }
        let mut mode = Mode::default();
        pointer(&file, VT_GETMODE, &mut mode)?;
        let mut kd = 0;
        pointer(&file, KDGETMODE, &mut kd)?;
        let mut keyboard = 0;
        pointer(&file, KDGKBMODE, &mut keyboard)?;
        let mut session: libc::pid_t = 0;
        let occupied = unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCGSID, &mut session) } == 0
            && session > 0;
        if occupied || mode.mode != 0 || kd != 0 {
            return Err(io::Error::other(
                "graphical VT is already owned; coordinate gettys/display managers",
            ));
        }
        ensure_no_controlling_lineage(metadata.rdev())?;
        self.original = Some((mode, kd, keyboard));
        self.terminal = Some(file);
        let mut owned = Mode {
            mode: 1,
            wait: 0,
            release: libc::SIGUSR1 as i16,
            acquire: libc::SIGUSR2 as i16,
            force: 0,
        };
        let file = self.terminal.as_ref().expect("terminal");
        pointer(file, VT_SETMODE, &mut owned)?;
        if let Err(error) = value(file, KDSKBMODE, 4).and_then(|()| value(file, KDSETMODE, 1)) {
            let _ = self.restore();
            return Err(error);
        }
        Ok(())
    }
    fn foreground(&mut self) -> io::Result<u32> {
        let mut state = State::default();
        pointer(
            self.console.as_ref().expect("console"),
            VT_GETSTATE,
            &mut state,
        )?;
        Ok(u32::from(state.active))
    }
    fn switch(&mut self, terminal: u32) -> io::Result<()> {
        if !(1..=63).contains(&terminal) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        value(
            self.console.as_ref().expect("console"),
            VT_ACTIVATE,
            terminal as i32,
        )
    }
    fn release(&mut self) -> io::Result<()> {
        value(self.terminal.as_ref().expect("terminal"), VT_RELDISP, 1)
    }
    fn acquire(&mut self) -> io::Result<()> {
        value(self.terminal.as_ref().expect("terminal"), VT_RELDISP, 2)
    }
    fn restore(&mut self) -> io::Result<()> {
        let Some((mut mode, kd, keyboard)) = self.original else {
            return Ok(());
        };
        let file = self.terminal.as_ref().expect("terminal");
        // Restore the original values, not assumptions about keyboard mode.
        let first = value(file, KDSKBMODE, keyboard).err();
        let second = value(file, KDSETMODE, kd).err();
        let third = pointer(file, VT_SETMODE, &mut mode).err();
        let error = first.or(second).or(third);
        if error.is_none() {
            self.original = None;
            self.terminal.take();
        }
        error.map_or(Ok(()), Err)
    }
}
impl Drop for Linux {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            tracing::error!(%error, "final VT restoration failed");
        }
    }
}

fn ensure_no_controlling_lineage(number: u64) -> io::Result<()> {
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let Some((_, fields)) = stat.rsplit_once(") ") else {
            return Err(io::Error::other("invalid process terminal inventory"));
        };
        let terminal = fields
            .split_whitespace()
            .nth(4)
            .and_then(|number| number.parse::<i64>().ok())
            .ok_or_else(|| io::Error::other("invalid process terminal inventory"))?;
        if terminal as u32 == number as u32 {
            return Err(io::Error::other(
                "configured graphical VT has a controlling-terminal lineage",
            ));
        }
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
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
    let read = unsafe {
        libc::read(
            fd.as_raw_fd(),
            info.as_mut_ptr().cast(),
            size_of::<libc::signalfd_siginfo>(),
        )
    };
    if read == size_of::<libc::signalfd_siginfo>() as isize {
        return Ok(Some(unsafe { info.assume_init() }.ssi_signo as i32));
    }
    if read < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(error);
    }
    Err(io::Error::other("short VT signalfd read"))
}
