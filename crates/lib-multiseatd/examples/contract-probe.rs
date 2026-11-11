//! Disposable private-bus acceptance client. No daemon/runtime dependency.
use libmultiseatd::{Client, ContextId, ErrorKind, SeatConnection};
use std::{
    io::{Read, Write},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
fn category<T>(result: Result<T, dbus::Error>, expected: ErrorKind) {
    match result {
        Err(error) => assert_eq!(error.name(), Some(expected.name())),
        Ok(_) => panic!("expected {expected:?}"),
    }
}
struct Peer {
    control: OwnedFd,
    enables: Arc<AtomicUsize>,
    disables: Arc<AtomicUsize>,
    thread: thread::JoinHandle<()>,
}
impl Peer {
    fn start(connection: SeatConnection) -> Self {
        let fd = connection.into_fd();
        let control = fd.try_clone().unwrap();
        let mut stream = UnixStream::from(fd);
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        packet(&mut stream, 1);
        assert_eq!(receive(&mut stream).unwrap(), 0x8001);
        packet(&mut stream, 7);
        assert_eq!(receive(&mut stream).unwrap(), 0x8007);
        let enables = Arc::new(AtomicUsize::new(0));
        let disables = Arc::new(AtomicUsize::new(0));
        let enabled = enables.clone();
        let disabled = disables.clone();
        let thread = thread::spawn(move || {
            loop {
                match receive(&mut stream) {
                    Ok(0x8006) => {
                        enabled.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(0x8005) => {
                        disabled.fetch_add(1, Ordering::SeqCst);
                        packet(&mut stream, 5);
                    }
                    Ok(0x8009 | 0x8007) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                        ) =>
                    {
                        break;
                    }
                    result => panic!("unexpected seatd reply: {result:?}"),
                }
            }
        });
        Self {
            control,
            enables,
            disables,
            thread,
        }
    }
    fn finish(self) {
        let _ = libmultiseatd::remove_connection(self.control.as_fd());
        self.thread.join().unwrap();
    }
}
fn packet(stream: &mut UnixStream, opcode: u16) {
    stream
        .write_all(&[opcode.to_ne_bytes(), 0u16.to_ne_bytes()].concat())
        .unwrap();
}
fn receive(stream: &mut UnixStream) -> std::io::Result<u16> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let count = u16::from_ne_bytes([header[2], header[3]]) as usize;
    if count > 4096 {
        return Err(std::io::Error::other("oversized seatd reply"));
    }
    stream.read_exact(&mut vec![0u8; count])?;
    Ok(u16::from_ne_bytes([header[0], header[1]]))
}
fn until(mut predicate: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(3);
    while !predicate() {
        assert!(Instant::now() < end, "acceptance condition expired");
        thread::sleep(Duration::from_millis(5));
    }
}
fn acl(path: &Path) -> String {
    let result = Command::new("getfacl")
        .args(["--numeric", "--omit-header", "--absolute-names"])
        .arg(path)
        .output()
        .unwrap();
    assert!(result.status.success());
    String::from_utf8(result.stdout).unwrap()
}
fn exec_child(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use libmultiseatd::launch;
    if args.len() != 4 {
        return Err("invalid exec-child arguments".into());
    }
    let raw: i32 = args[2].parse()?;
    if raw < 3 || unsafe { libc::fcntl(raw, libc::F_GETFD) } < 0 {
        return Err("missing inherited test endpoint".into());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    launch::detach_worker()?;
    launch::fill_standard_streams()?;
    assert_eq!(std::fs::read_dir("/proc/self/task")?.count(), 1);
    let launcher = std::env::var("CONTEXT_PROBE_LAUNCHER").ok();
    let mut keep = vec![raw];
    if launcher.is_some() {
        keep.push(std::env::var("CONTEXT_TEST_SENTINEL_FD")?.parse()?);
    }
    unsafe {
        launch::close_unlisted(&keep)?;
    }
    launch::inheritable(descriptor.as_fd(), true)?;
    let mut command = if let Some(launcher) = launcher {
        let mut command = Command::new(launcher);
        command.args([
            "--seat",
            &std::env::var("XDG_SEAT")?,
            "--bus-address",
            &std::env::var("CONTEXT_PROBE_ADDRESS")?,
            "--authority-fd",
            &raw.to_string(),
            "--",
            &args[3],
        ]);
        command
    } else {
        Command::new(&args[3])
    };
    Err(command.exec().into())
}
fn libseat_case(
    client: &Client,
    address: &str,
    seat: &str,
    executable: &str,
    launcher: Option<&str>,
    native: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use libmultiseatd::launch;
    let context = client.create_context(0)?;
    client.add_acl_grant(context.as_fd(), 65534)?;
    let inherited = if launcher.is_some() || native {
        context.as_fd().try_clone_to_owned()?
    } else {
        client.create_connection(context.as_fd())?.into_fd()
    };
    client.activate_context(context.id)?;
    let (sentinel, _peer) = UnixStream::pair()?;
    launch::inheritable(sentinel.as_fd(), true)?;
    launch::inheritable(inherited.as_fd(), true)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exec-client",
            &inherited.as_raw_fd().to_string(),
            executable,
        ])
        .uid(65534)
        .gid(65534)
        .env(
            "CONTEXT_TEST_AUTHORITY_FD",
            if launcher.is_some() || native {
                inherited.as_raw_fd()
            } else {
                context.as_fd().as_raw_fd()
            }
            .to_string(),
        )
        .env("CONTEXT_TEST_SENTINEL_FD", sentinel.as_raw_fd().to_string())
        .env("CONTEXT_TEST_METADATA", "1")
        .env("CONTEXT_TEST_SEAT", seat)
        .env("XDG_SEAT", seat)
        .env_remove("XDG_VTNR")
        .env_remove("MULTISEATD_AUTHORITY_FD");
    command.env_remove("LIBSEAT_BACKEND");
    if native {
        command
            .env("LIBSEAT_BACKEND", "multiseatd")
            .env("DBUS_SYSTEM_BUS_ADDRESS", address)
            .env("MULTISEATD_AUTHORITY_FD", inherited.as_raw_fd().to_string())
            .env_remove("SEATD_FD")
            .env_remove("CONTEXT_PROBE_LAUNCHER");
    } else if let Some(launcher) = launcher {
        command
            .env("CONTEXT_PROBE_LAUNCHER", launcher)
            .env("CONTEXT_PROBE_ADDRESS", address)
            .env("MULTISEATD_AUTHORITY_FD", inherited.as_raw_fd().to_string());
    } else {
        command
            .env("SEATD_FD", inherited.as_raw_fd().to_string())
            .env_remove("CONTEXT_PROBE_LAUNCHER");
    }
    let mut child = command.spawn()?;
    launch::inheritable(inherited.as_fd(), false)?;
    drop(inherited);
    drop(sentinel);
    let status = child.wait()?;
    assert!(
        status.success(),
        "maintained C libseat acceptance failed: {status}"
    );
    until(|| {
        client
            .get_context(context.as_fd())
            .unwrap()
            .connection_handles
            .is_empty()
    });
    assert!(
        client.get_context(context.as_fd())?.active,
        "EOF selected or removed the context"
    );
    client.remove_context(context.as_fd())?;
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<_> = std::env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "--exec-client") {
        return exec_child(&args);
    }
    let fatal = args.get(1).is_some_and(|arg| arg == "--fatal");
    if fatal {
        args.remove(1);
    }
    if args.len() == 4 && args[1] == "--unprivileged" {
        let client = Client::for_address(&args[2], &args[3], Duration::from_secs(10))?;
        category(client.create_context(0), ErrorKind::NotAuthorized);
        category(client.list_contexts(), ErrorKind::NotAuthorized);
        category(
            client.activate_context(ContextId::generate()),
            ErrorKind::NotAuthorized,
        );
        category(client.remove_unassigned_devices(), ErrorKind::NotAuthorized);
        let error = client
            .connection()
            .request_name("org.SGLogin.Multiseatd1.Seat_seat_fake", false, false, true)
            .unwrap_err();
        assert_eq!(
            error.name(),
            Some("org.freedesktop.DBus.Error.AccessDenied")
        );
        return Ok(());
    }
    if args.len() != 4 {
        return Err("usage: contract-probe ADDRESS SEAT DISPOSABLE_NODE".into());
    }
    let (address, seat, path) = (&args[1], &args[2], Path::new(&args[3]));
    let end = Instant::now() + Duration::from_secs(5);
    let client = loop {
        match Client::for_address(address, seat, Duration::from_millis(250)) {
            Ok(client) => break client,
            Err(error) => {
                if Instant::now() >= end {
                    return Err(error.into());
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    };
    // A new client has the specified ten-second contract budget.
    drop(client);
    let client = Client::for_address(address, seat, Duration::from_secs(10))?;
    if fatal {
        let context = client.create_context(0)?;
        client.add_acl_grant(context.as_fd(), 424242)?;
        let start = Instant::now();
        category(
            client.activate_context(context.id),
            ErrorKind::CriticalFailure,
        );
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "critical reply did not reserve server response headroom"
        );
        println!("explicit CriticalFailure received on a healthy bus before bounded fatal exit");
        return Ok(());
    }
    let executable = std::env::current_exe()?;
    assert!(
        Command::new(executable)
            .args(["--unprivileged", address, seat])
            .uid(65534)
            .gid(65534)
            .status()?
            .success()
    );
    assert!(client.list_contexts()?.is_empty());
    category(client.create_context(7), ErrorKind::InvalidArgument);
    let first = client.create_context(0)?;
    let second = client.create_context(0)?;
    assert_eq!(client.seat_metadata(first.as_fd())?, (seat.clone(), 0));
    client.add_acl_grant(first.as_fd(), 424242)?;
    assert!(!acl(path).contains("user:424242:"));
    let connection = client.create_connection(first.as_fd())?;
    let first_handle = connection.handle;
    let peer = Peer::start(connection);
    let connection = client.create_connection(first.as_fd())?;
    let sibling_handle = connection.handle;
    let sibling = Peer::start(connection);
    assert_ne!(first_handle, sibling_handle);
    assert_eq!(peer.enables.load(Ordering::SeqCst), 0);
    client.activate_context(first.id)?;
    until(|| {
        peer.enables.load(Ordering::SeqCst) == 1 && sibling.enables.load(Ordering::SeqCst) == 1
    });
    let info = client.get_context(first.as_fd())?;
    assert!(info.active && info.effective && !info.foreground && info.vt == 0);
    assert_eq!(info.connection_handles.len(), 2);
    assert!(acl(path).contains("user:424242:rw-"));
    category(client.activate_context(first.id), ErrorKind::Busy);
    category(client.activate_context(second.id), ErrorKind::Busy);
    client.add_acl_grant(second.as_fd(), 424243)?;
    assert!(!acl(path).contains("user:424243:"));
    assert_eq!(peer.disables.load(Ordering::SeqCst), 0);
    category(
        client.move_to_foreground(first.id),
        ErrorKind::InvalidArgument,
    );
    // Removal is exact but never adds the missing legitimate named entry.
    assert!(
        Command::new("setfacl")
            .args(["-x", "u:424242"])
            .arg(path)
            .status()?
            .success()
    );
    assert!(
        Command::new("setfacl")
            .args(["-m", "u:424244:rw,g:424245:rw"])
            .arg(path)
            .status()?
            .success()
    );
    client.remove_unassigned_devices()?;
    let text = acl(path);
    assert!(
        !text.contains("user:424242:")
            && !text.contains("user:424244:")
            && !text.contains("group:424245:")
    );
    client.add_assigned_devices()?;
    assert!(acl(path).contains("user:424242:rw-"));
    peer.finish();
    until(|| {
        client
            .get_context(first.as_fd())
            .unwrap()
            .connection_handles
            == vec![sibling_handle]
    });
    assert!(client.get_context(first.as_fd())?.effective);
    client.deactivate_context(first.id)?;
    assert_eq!(sibling.disables.load(Ordering::SeqCst), 1);
    assert!(!acl(path).contains("user:424242:"));
    client.activate_context(second.id)?;
    assert!(acl(path).contains("user:424243:rw-"));
    client.remove_context(first.as_fd())?;
    client.remove_context(first.as_fd())?;
    sibling.finish();
    category(client.get_context(first.as_fd()), ErrorKind::NotAuthorized);
    client.remove_context_by_id(first.id)?;
    drop(second);
    until(|| client.list_contexts().unwrap().is_empty());
    assert!(!acl(path).contains("user:424243:"));
    if let Some(executable) = std::env::var("CONTEXT_LIBSEAT_CLIENT")
        .ok()
        .filter(|value| !value.is_empty())
    {
        libseat_case(&client, address, seat, &executable, None, false)?;
        if let Ok(launcher) = std::env::var("CONTEXT_SEAT_LAUNCH") {
            libseat_case(&client, address, seat, &executable, Some(&launcher), false)?;
        }
        println!(
            "maintained C libseat opens, duplicate FDs, close/reopen, no authority and seat-launch acceptance passed"
        );
    }
    if let Some(executable) = std::env::var("CONTEXT_NATIVE_CLIENT")
        .ok()
        .filter(|value| !value.is_empty())
    {
        libseat_case(&client, address, seat, &executable, None, true)?;
        println!(
            "native maintained C backend bootstrapped the real per-seat daemon, consumed authority and retained no extra FDs"
        );
    }
    println!(
        "private-bus fourteen-method SDK, credentials, ACL, sibling and authority lifetime acceptance passed"
    );
    Ok(())
}
