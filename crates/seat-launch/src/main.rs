use clap::Parser;
use libmultiseatd::{Client, launch};
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::time::Duration;

#[derive(Parser)]
#[command(
    version,
    about = "Exec a seat client with one fresh capability-authorized seatd connection"
)]
struct Args {
    /// Explicit inherited full-authority descriptor (otherwise use MULTISEATD_AUTHORITY_FD).
    #[arg(long)]
    authority_fd: Option<i32>,
    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<OsString>,
}
fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("seat-launch: {error}");
        std::process::exit(1);
    }
}
fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    launch::fill_standard_streams()?;
    launch::check_no_linux_terminal()?;
    let raw = match args.authority_fd {
        Some(fd) => fd,
        None => std::env::var("MULTISEATD_AUTHORITY_FD")?.parse()?,
    };
    if raw < 3 || unsafe { libc::fcntl(raw, libc::F_GETFD) } < 0 {
        return Err("authority must name a live inherited descriptor >= 3".into());
    }
    // SAFETY: this fresh single-threaded executable adopts the explicitly
    // inherited FD, which has no other Rust owner in this process.
    let authority = unsafe { OwnedFd::from_raw_fd(raw) };
    launch::inheritable(authority.as_fd(), false)?;
    let client = Client::system(Duration::from_secs(11))?;
    // Standard streams may be sockets (logging), but never context keys.
    // Authorization is performed only by the daemon, not by a local verifier.
    for standard in 0..=2 {
        let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(standard, &mut metadata) } == 0
            && metadata.st_mode & libc::S_IFMT == libc::S_IFSOCK
        {
            let fd = unsafe { BorrowedFd::borrow_raw(standard) };
            match client.get_context(fd) {
                Ok(_) => return Err("authority inherited through standard IO".into()),
                Err(error)
                    if error.name() == Some(libmultiseatd::ErrorKind::AccessDenied.name()) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    let (seat, terminal) = client.seat_metadata(authority.as_fd())?;
    let connection = client.create_connection(authority.as_fd())?;
    let descriptor = connection.into_fd();
    drop(client);
    drop(authority);
    if std::fs::read_dir("/proc/self/task")?.count() != 1 {
        return Err("seat-launch requires a single-threaded exec worker".into());
    }
    use std::os::fd::AsRawFd;
    let raw = descriptor.as_raw_fd();
    // SAFETY: the process is single-threaded; no library worker is running.
    unsafe {
        std::env::remove_var("MULTISEATD_AUTHORITY_FD");
        std::env::remove_var("MULTISEATD_CONTEXT_ID");
        std::env::set_var("LIBSEAT_BACKEND", "seatd");
        std::env::set_var("SEATD_FD", raw.to_string());
        std::env::set_var("XDG_SEAT", seat);
        if terminal == 0 {
            std::env::remove_var("XDG_VTNR");
        } else {
            std::env::set_var("XDG_VTNR", terminal.to_string());
        }
        // All unlisted descriptors are inherited raw FDs, not live Rust owners;
        // the client/authority have been dropped. Only this descriptor survives.
        launch::close_unlisted(&[raw])?;
    }
    launch::inheritable(descriptor.as_fd(), true)?;
    let error = std::process::Command::new(&args.command[0])
        .args(&args.command[1..])
        .exec();
    // Exec failure drops the connection, never its context or siblings.
    Err(io::Error::other(format!(
        "exec {}: {error}",
        args.command[0].to_string_lossy()
    ))
    .into())
}
