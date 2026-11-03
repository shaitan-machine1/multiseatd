use clap::{Parser, ValueEnum};
use multiseatd::application::{Configuration, run};
use multiseatd::daemon::DaemonRuntime;
use seat_udev::SeatName;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum BusKind {
    System,
    Session,
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Capability-authorized seat contexts and device access"
)]
struct Args {
    #[arg(long, value_enum, default_value_t = BusKind::System)]
    bus: BusKind,
    /// Persistent process-wide lock in a trusted directory. Never unlinked.
    #[arg(long)]
    lock_file: Option<PathBuf>,
    /// Explicitly leave seat0 unmanaged; operate only non-VT seats.
    #[arg(long)]
    non_vt_only: bool,
    /// Seat0's single graphical VT; coordinate gettys and root-only permissions.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=63), conflicts_with = "non_vt_only")]
    graphical_vt: Option<u32>,
    /// Disposable synthetic non-VT fixtures. Never enumerate live topology.
    #[arg(long, hide = true)]
    test_only: bool,
    #[arg(long, hide = true, requires = "test_only")]
    test_seat: Vec<SeatName>,
    #[arg(long, hide = true, requires = "test_only")]
    test_direct_node: Vec<PathBuf>,
    #[arg(long, hide = true, requires = "test_only")]
    test_null_device: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "multiseatd=info".into()),
        )
        .init();
    let args = Args::parse();
    // SAFETY: geteuid has no pointer arguments or side effects.
    if unsafe { libc::geteuid() } != 0 {
        return Err("multiseatd must run as root".into());
    }
    if args.test_only && args.lock_file.is_none() {
        return Err("--test-only requires an explicit disposable --lock-file".into());
    }
    // Acquire the SAME singleton inode as earlier daemon versions. Signal masks
    // and runtime workers are created only after acquisition. Keep this outer
    // owner alive through every cleanup guard, job and native owner join.
    let runtime = DaemonRuntime::acquire(
        args.lock_file
            .as_deref()
            .unwrap_or(Path::new("/run/multiseatd.lock")),
    )?;
    runtime.block_on(run(
        Configuration {
            session_bus: matches!(args.bus, BusKind::Session),
            test_only: args.test_only,
            non_vt_only: args.non_vt_only,
            graphical_vt: args.graphical_vt,
            test_seats: args.test_seat,
            test_direct_nodes: args.test_direct_node,
            test_null_device: args.test_null_device,
        },
        runtime.shutdown_signals(),
    ))?;
    Ok(())
}
