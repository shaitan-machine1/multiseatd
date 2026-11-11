use clap::Parser;
use libmultiseatd::launch;
use std::{ffi::OsString, io};

#[derive(Parser)]
#[command(
    version,
    about = "Exec without inherited seat authority or device connections (not a sandbox)"
)]
struct Args {
    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<OsString>,
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("without-seat: {error}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> io::Result<()> {
    seat_wrapper::prepare()?;
    // Without contacting a seat daemon, a socket on standard IO cannot be
    // distinguished from a capability duplicate. Refuse it, preserving ordinary
    // files, pipes and PTYs rather than claiming that unsetting a variable revokes it.
    for raw in 0..=2 {
        let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(raw, &mut metadata) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if metadata.st_mode & libc::S_IFMT == libc::S_IFSOCK {
            return Err(io::Error::other(
                "without-seat cannot preserve socket standard IO",
            ));
        }
    }
    seat_wrapper::clear_seat_environment()?;
    // SAFETY: this fresh executable is single-threaded and owns no nonstandard
    // descriptors; inherited raw capabilities and all their duplicates are closed.
    unsafe {
        launch::close_unlisted(&[])?;
    }
    Err(seat_wrapper::exec(&args.command))
}
