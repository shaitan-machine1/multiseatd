//! Synchronous Linux launch hygiene for explicitly trusted exec workers.
//!
//! These functions do not authenticate a capability, choose a context, perform
//! PAM, change credentials, allocate a VT, or construct a runtime. Call in a
//! fresh single-threaded executable, never an allocating post-fork callback.
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

fn linux_console(number: u64) -> bool {
    (libc::major(number) == 4 && libc::minor(number) <= 63)
        || (libc::major(number) == 5 && libc::minor(number) == 1)
}

pub fn is_linux_vt(fd: BorrowedFd<'_>) -> io::Result<bool> {
    is_linux_raw(fd.as_raw_fd())
}

fn is_linux_raw(raw: RawFd) -> io::Result<bool> {
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(raw, &mut metadata) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFCHR {
        return Ok(false);
    }
    if linux_console(metadata.st_rdev as u64) {
        return Ok(true);
    }
    // Resolve /dev/tty's controlling-terminal alias; PTYs remain supported.
    let mut actual = 0u32;
    if unsafe { libc::ioctl(raw, libc::TIOCGDEV, &mut actual) } == 0 {
        return Ok(linux_console(u64::from(actual)));
    }
    Ok(false)
}

pub fn check_no_linux_terminal() -> io::Result<()> {
    for raw in 0..=2 {
        match is_linux_raw(raw) {
            Ok(true) => {
                return Err(io::Error::other(
                    "Linux VT inherited through standard streams",
                ));
            }
            Ok(false) => {}
            Err(error) if error.raw_os_error() == Some(libc::EBADF) => {}
            Err(error) => return Err(error),
        }
    }
    let raw = unsafe {
        libc::open(
            c"/dev/tty".as_ptr(),
            libc::O_RDONLY | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let error = io::Error::last_os_error();
        return if matches!(
            error.raw_os_error(),
            Some(libc::ENXIO | libc::ENODEV | libc::ENOENT)
        ) {
            Ok(())
        } else {
            Err(error)
        };
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if is_linux_vt(std::os::fd::AsFd::as_fd(&fd))? {
        return Err(io::Error::other(
            "managed application retains a controlling Linux VT",
        ));
    }
    Ok(())
}

/// Detach a trusted post-exec worker before user/PAM/application execution.
/// Existing session leaders are accepted only if terminal validation passes.
pub fn detach_worker() -> io::Result<()> {
    if unsafe { libc::getsid(0) } != unsafe { libc::getpid() } && unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    check_no_linux_terminal()
}

/// Fill closed standard streams before opening bus/capability descriptors.
pub fn fill_standard_streams() -> io::Result<()> {
    for target in 0..=2 {
        if unsafe { libc::fcntl(target, libc::F_GETFD) } >= 0 {
            continue;
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
            return Err(io::Error::last_os_error());
        }
        let raw = unsafe {
            libc::open(
                c"/dev/null".as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        if raw == target {
            if unsafe { libc::fcntl(target, libc::F_SETFD, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
        } else {
            let result = unsafe { libc::dup2(raw, target) };
            unsafe {
                libc::close(raw);
            }
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Replace all standard streams in a disposable trusted worker with /dev/null.
pub fn null_standard_streams() -> io::Result<()> {
    let raw = unsafe {
        libc::open(
            c"/dev/null".as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    for target in 0..=2 {
        if raw == target {
            if unsafe { libc::fcntl(target, libc::F_SETFD, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
        } else if unsafe { libc::dup2(raw, target) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // If open filled a closed standard stream, that descriptor must remain live.
    if raw <= 2 {
        std::mem::forget(fd);
    }
    Ok(())
}

/// Close inherited descriptors except the explicit allowlist and standard IO.
///
/// # Safety
/// Run in a fresh single-threaded exec worker. No unlisted descriptor may be
/// owned by a live Rust object; after success proceed directly to exec/exit.
/// Drop the synchronous D-Bus client and authority owners before calling this.
pub unsafe fn close_unlisted(keep: &[RawFd]) -> io::Result<()> {
    if std::fs::read_dir("/proc/self/task")?.count() != 1 {
        return Err(io::Error::other(
            "FD sanitation requires a single-threaded exec worker",
        ));
    }
    let descriptors: Vec<_> = std::fs::read_dir("/proc/self/fd")?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<RawFd>().ok())
        .filter(|fd| *fd > 2 && !keep.contains(fd))
        .collect();
    for fd in descriptors {
        unsafe {
            libc::close(fd);
        }
    }
    Ok(())
}

pub fn inheritable(fd: BorrowedFd<'_>, inherit: bool) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = if inherit {
        flags & !libc::FD_CLOEXEC
    } else {
        flags | libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linux_console_aliases_are_distinct_from_pseudoterminals() {
        assert!(linux_console(libc::makedev(4, 7)));
        assert!(linux_console(libc::makedev(4, 0)));
        assert!(linux_console(libc::makedev(5, 1)));
        assert!(!linux_console(libc::makedev(136, 0)));
        assert!(!linux_console(libc::makedev(1, 3)));
    }
}
