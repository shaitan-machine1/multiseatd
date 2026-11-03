//! Standalone post-exec worker fixture; never opens a Linux VT.
use libmultiseatd::launch;
use std::io;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args().collect();
    let keep: i32 = arguments[2].parse()?;
    let sentinel: i32 = arguments[3].parse()?;
    let owned = unsafe { OwnedFd::from_raw_fd(keep) };
    if arguments[1] != "final" {
        if arguments[1] == "null" {
            launch::null_standard_streams()?;
        }
        launch::detach_worker()?;
        launch::inheritable(owned.as_fd(), true)?;
        // SAFETY: this standalone worker owns only the listed descriptor;
        // all other nonstandard descriptors are inherited, unowned raw FDs.
        unsafe {
            launch::close_unlisted(&[keep])?;
        }
        if unsafe { libc::fcntl(sentinel, libc::F_GETFD) } != -1 {
            return Err("unlisted descriptor escaped sanitation".into());
        }
        let error = std::process::Command::new(std::env::current_exe()?)
            .args(["final", &keep.to_string(), &sentinel.to_string()])
            .exec();
        return Err(error.into());
    }
    launch::check_no_linux_terminal()?;
    if unsafe { libc::fcntl(sentinel, libc::F_GETFD) } != -1 {
        return Err("unlisted descriptor survived exec".into());
    }
    if unsafe { libc::write(keep, c"ok".as_ptr().cast(), 2) } != 2 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
