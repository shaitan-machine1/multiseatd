use clap::Parser;
use multiseatd::{
    application::{Configuration, run},
    daemon::DaemonRuntime,
    discovery::Fixture,
};
use seat_udev::SeatName;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum AclFault {
    Error,
    Panic,
    Stall,
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Per-seat capability contexts and managed device access"
)]
struct Args {
    #[arg(long)]
    seat: SeatName,
    /// Persistent per-seat lock in a trusted directory, never unlinked.
    #[arg(long)]
    lock_file: Option<PathBuf>,
    #[cfg(feature = "vt")]
    /// Entire disjoint Linux VT startup reservation; coordinate gettys first.
    #[arg(long, required = true, value_delimiter = ',', num_args = 1.., value_parser = clap::value_parser!(u32).range(1..=63))]
    vts: Vec<u32>,
    #[arg(long, hide = true)]
    test_only: bool,
    #[arg(long, hide = true, requires = "test_only")]
    test_root: Option<PathBuf>,
    #[arg(long, hide = true, requires = "test_only")]
    bus_address: Option<String>,
    #[arg(long, hide = true, requires = "test_only")]
    test_direct_node: Vec<PathBuf>,
    #[arg(long, hide = true, requires = "test_only")]
    test_null_device: bool,
    #[arg(long, hide = true, requires = "test_only")]
    test_assignments: Option<PathBuf>,
    #[cfg(feature = "test-support")]
    #[arg(long, hide = true, requires = "test_only")]
    test_acl_fault: Option<AclFault>,
}
fn disposable(root: &Path, path: &Path) -> std::io::Result<PathBuf> {
    let canonical = std::fs::canonicalize(path)?;
    if !canonical.starts_with(root) || canonical == root {
        return Err(std::io::Error::other(
            "fixture path must be below the explicit disposable root",
        ));
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.nlink() != 1 {
        return Err(std::io::Error::other(
            "fixture must be a root-owned unshared regular file, not a symlink/device",
        ));
    }
    Ok(canonical)
}
fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if unsafe { libc::geteuid() } != 0 {
        return Err("multiseatd must run as root".into());
    }
    libmultiseatd::launch::fill_standard_streams()?;
    if args.test_only && !cfg!(feature = "test-support") {
        return Err("synthetic mode requires an explicit test-support build".into());
    }
    let fixture = if args.test_only {
        let root = args
            .test_root
            .as_deref()
            .ok_or("--test-only requires --test-root")?;
        let metadata = std::fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err("test root must be a root-owned private directory, not a symlink".into());
        }
        let root = std::fs::canonicalize(root)?;
        if root == Path::new("/")
            || root.starts_with("/dev")
            || root.starts_with("/sys")
            || root.starts_with("/proc")
        {
            return Err("unsafe test root".into());
        }
        let nodes = args
            .test_direct_node
            .iter()
            .map(|path| disposable(&root, path))
            .collect::<Result<_, _>>()?;
        let assignments = args
            .test_assignments
            .as_ref()
            .map(|path| disposable(&root, path))
            .transpose()?;
        if args
            .lock_file
            .as_ref()
            .is_none_or(|path| !path.starts_with(&root))
        {
            return Err(
                "synthetic mode requires an explicit lock below its disposable root".into(),
            );
        }
        let lock_parent = std::fs::canonicalize(
            args.lock_file
                .as_ref()
                .expect("validated lock")
                .parent()
                .ok_or("lock requires a parent directory")?,
        )?;
        if !lock_parent.starts_with(&root) {
            return Err("fixture lock parent escapes the disposable root".into());
        }
        Some(Fixture {
            seat: args.seat.clone(),
            direct_nodes: nodes,
            null_device: args.test_null_device,
            assignments,
        })
    } else {
        None
    };
    #[cfg(feature = "vt")]
    let vts = {
        let set: std::collections::BTreeSet<_> = args.vts.iter().copied().collect();
        if set.len() != args.vts.len() {
            return Err("duplicate VT reservation".into());
        }
        // Synthetic tests must never claim physical terminals on the host.
        if fixture.is_some() {
            return Err("synthetic VT policy requires the library fixture harness, not native terminal claims".into());
        }
        set
    };
    let default_lock = if args.lock_file.is_none() {
        let directory = Path::new("/run/multiseatd");
        if !directory.exists() {
            std::fs::DirBuilder::new().mode(0o755).create(directory)?;
        }
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("unsafe per-seat lock directory".into());
        }
        Some(directory.join(format!("{}.lock", args.seat)))
    } else {
        None
    };
    let lock = args
        .lock_file
        .as_deref()
        .or(default_lock.as_deref())
        .expect("chosen lock");
    let runtime = DaemonRuntime::acquire(lock)?;
    let result = runtime.block_on(run(
        Configuration {
            seat: args.seat,
            bus_address: args.bus_address,
            fixture,
            #[cfg(feature = "test-support")]
            acl_fault: args.test_acl_fault.map(|fault| match fault {
                AclFault::Error => dev_acl::TestFault::AfterWriteError,
                AclFault::Panic => dev_acl::TestFault::AfterWritePanic,
                AclFault::Stall => {
                    dev_acl::TestFault::AfterWriteStall(std::time::Duration::from_secs(14))
                }
            }),
            #[cfg(feature = "vt")]
            vts,
        },
        runtime.shutdown_signals(),
    ));
    if let Err(error) = result {
        // Keep runtime/masks/instance inode alive until process exit on an
        // unresolved failure. No destructor may introduce an unbounded join.
        eprintln!("multiseatd: {error}");
        std::process::exit(1);
    }
    Ok(())
}
fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "multiseatd=info".into()),
        )
        .init();
    if let Err(error) = execute() {
        eprintln!("multiseatd: {error}");
        std::process::exit(1);
    }
}
