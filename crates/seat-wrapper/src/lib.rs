//! Shared hygiene for fresh, synchronous, single-threaded exec wrappers.
use libmultiseatd::launch;
use std::{ffi::OsString, io, os::unix::process::CommandExt};

fn single_threaded() -> io::Result<()> {
    if std::fs::read_dir("/proc/self/task")?.count() != 1 {
        return Err(io::Error::other(
            "seat wrappers require a single-threaded exec worker",
        ));
    }
    Ok(())
}

pub fn prepare() -> io::Result<()> {
    single_threaded()?;
    launch::fill_standard_streams()?;
    launch::check_no_linux_terminal()
}

/// Clear capabilities and backend overrides, retaining ordinary session metadata.
pub fn clear_seat_environment() -> io::Result<()> {
    single_threaded()?;
    // SAFETY: these wrappers create no threads or asynchronous runtime.
    unsafe {
        for key in [
            "MULTISEATD_AUTHORITY_FD",
            "MULTISEATD_CONTEXT_ID",
            "SEATD_FD",
            "SEATD_SOCK",
            "LIBSEAT_BACKEND",
        ] {
            std::env::remove_var(key);
        }
    }
    Ok(())
}

pub fn exec(command: &[OsString]) -> io::Error {
    let error = std::process::Command::new(&command[0])
        .args(&command[1..])
        .exec();
    io::Error::other(format!("exec {}: {error}", command[0].to_string_lossy()))
}
