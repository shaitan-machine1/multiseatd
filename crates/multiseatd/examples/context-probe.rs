//! Disposable private-bus capability/credential probe. No live topology access.
use dbus::blocking::Connection;
use libmultiseatd::contract::{self, ContextRow, ErrorKind, SeatRow};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let connection = Connection::new_system()?;
    let proxy = connection.with_proxy(
        contract::BUS_NAME,
        contract::OBJECT_PATH,
        Duration::from_secs(3),
    );
    match args.get(1).map(String::as_str) {
        Some("ready") => {
            let _: (Vec<SeatRow>,) =
                proxy.method_call(contract::INTERFACE_NAME, "ListSeats", ())?;
        }
        Some("contract") => {
            let (rows,): (Vec<SeatRow>,) =
                proxy.method_call(contract::INTERFACE_NAME, "ListSeats", ())?;
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].0, "seat-test");
            let error = proxy
                .method_call::<(dbus::arg::OwnedFd, String), _, _, _>(
                    contract::INTERFACE_NAME,
                    "CreateContext",
                    ("seat-test", 0u32),
                )
                .err()
                .unwrap();
            assert_eq!(error.name(), Some(ErrorKind::InvalidArgument.name()));
            let (fd, id): (dbus::arg::OwnedFd, String) =
                proxy.method_call(contract::INTERFACE_NAME, "CreateContext", ("seat-test",))?;
            let (row,): (ContextRow,) =
                proxy.method_call(contract::INTERFACE_NAME, "GetContext", (&fd,))?;
            assert_eq!(row.0, id);
            assert_eq!(row.2, "inactive");
            assert!(!row.5 && !row.6 && row.3.is_empty() && row.4.is_empty());
            let (unrelated, _peer) = UnixStream::pair()?;
            let unrelated = dbus_fd(unrelated.into());
            let error = proxy
                .method_call::<(ContextRow,), _, _, _>(
                    contract::INTERFACE_NAME,
                    "GetContext",
                    (&unrelated,),
                )
                .err()
                .unwrap();
            assert_eq!(error.name(), Some(ErrorKind::AccessDenied.name()));
            proxy.method_call::<(), _, _, _>(contract::INTERFACE_NAME, "RemoveContext", (&fd,))?;
            proxy.method_call::<(), _, _, _>(contract::INTERFACE_NAME, "RemoveContext", (&fd,))?;
            proxy.method_call::<(), _, _, _>(
                contract::INTERFACE_NAME,
                "RemoveContextById",
                (id,),
            )?;
            let error = proxy
                .method_call::<(ContextRow,), _, _, _>(
                    contract::INTERFACE_NAME,
                    "GetContext",
                    (&fd,),
                )
                .err()
                .unwrap();
            assert_eq!(error.name(), Some(ErrorKind::AccessDenied.name()));
            // Final endpoint close, rather than D-Bus-owner loss, removes it.
            let (fd, id): (dbus::arg::OwnedFd, String) =
                proxy.method_call(contract::INTERFACE_NAME, "CreateContext", ("seat-test",))?;
            drop(fd);
            for attempt in 0..100 {
                let (rows,): (Vec<ContextRow>,) =
                    proxy.method_call(contract::INTERFACE_NAME, "ListContexts", ())?;
                if !rows.iter().any(|row| row.0 == id) {
                    break;
                }
                assert!(attempt < 99, "final authority close did not remove context");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Some("grants") => {
            use std::os::unix::process::CommandExt;
            let uid: u32 = args[3].parse()?;
            let gid: u32 = args[4].parse()?;
            let readable = || -> Result<bool, std::io::Error> {
                Ok(std::process::Command::new("/usr/bin/test")
                    .args(["-r", &args[2]])
                    .uid(uid)
                    .gid(gid)
                    .status()?
                    .success())
            };
            assert!(!readable()?);
            let (fd, id): (dbus::arg::OwnedFd, String) =
                proxy.method_call(contract::INTERFACE_NAME, "CreateContext", ("seat-test",))?;
            let received = unsafe { OwnedFd::from_raw_fd(fd.into_raw_fd()) };
            let authority = received.try_clone()?;
            drop(received);
            proxy.method_call::<(), _, _, _>(
                contract::INTERFACE_NAME,
                "GrantAccess",
                (dbus_fd(authority.try_clone()?), uid),
            )?;
            assert!(!readable()?, "inactive desired grant must not apply");
            proxy.method_call::<(), _, _, _>(
                contract::INTERFACE_NAME,
                "ActivateContext",
                (dbus_fd(authority.try_clone()?),),
            )?;
            assert!(readable()?);
            proxy.method_call::<(), _, _, _>(
                contract::INTERFACE_NAME,
                "RevokeAccess",
                (dbus_fd(authority.try_clone()?), uid),
            )?;
            assert!(!readable()?);
            proxy.method_call::<(), _, _, _>(
                contract::INTERFACE_NAME,
                "GrantAccess",
                (dbus_fd(authority.try_clone()?), uid),
            )?;
            assert!(readable()?);
            proxy.method_call::<(), _, _, _>(
                contract::INTERFACE_NAME,
                "RemoveContextById",
                (id,),
            )?;
            assert!(!readable()?);
        }
        Some("sdk") => {
            use std::os::fd::AsFd;
            use std::sync::{
                Arc,
                atomic::{AtomicU64, Ordering},
            };
            drop(connection);
            let client = libmultiseatd::Client::system(Duration::from_secs(11))?;
            let revision = Arc::new(AtomicU64::new(0));
            let observed = revision.clone();
            client.subscribe(move |value| {
                observed.store(value, Ordering::Release);
            })?;
            let context = client.create_context("seat-test")?;
            assert_ne!(
                unsafe { libc::fcntl(context.as_fd().as_raw_fd(), libc::F_GETFD) }
                    & libc::FD_CLOEXEC,
                0
            );
            assert_eq!(
                client.seat_metadata(context.as_fd())?,
                ("seat-test".into(), 0)
            );
            let first = client.create_connection(context.as_fd())?;
            let second = client.create_connection(context.as_fd())?;
            assert_ne!(first.id, second.id);
            assert_ne!(first.as_fd().as_raw_fd(), second.as_fd().as_raw_fd());
            assert_ne!(
                unsafe { libc::fcntl(first.as_fd().as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            client.remove_connection(context.as_fd(), first.id)?;
            assert!(
                client
                    .get_context(context.as_fd())?
                    .4
                    .contains(&second.id.to_string())
            );
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while revision.load(Ordering::Acquire) == 0 && std::time::Instant::now() < deadline {
                client.process(Duration::from_millis(50))?;
            }
            assert_ne!(
                revision.load(Ordering::Acquire),
                0,
                "root state subscription did not receive a hint"
            );
            client.remove_context(context.as_fd())?;
            client.remove_context(context.as_fd())?;
            assert_eq!(
                client.get_context(context.as_fd()).unwrap_err().name(),
                Some(ErrorKind::AccessDenied.name())
            );
        }
        Some("wrapper") => {
            use std::os::fd::AsFd;
            use std::os::unix::process::CommandExt;
            drop(connection);
            let client = libmultiseatd::Client::system(Duration::from_secs(11))?;
            let context = client.create_context("seat-test")?;
            client.activate_context(context.as_fd())?;
            let sibling = client.create_connection(context.as_fd())?;
            let (sentinel, _peer) = std::os::unix::net::UnixStream::pair()?;
            for (target, bad_stdio) in [
                (args[3].as_str(), false),
                ("/definitely-not-a-program", false),
                (args[3].as_str(), true),
            ] {
                let raw = context.as_fd().as_raw_fd();
                let extra = sentinel.as_raw_fd();
                let mut command = std::process::Command::new(&args[2]);
                command
                    .arg("--")
                    .arg(target)
                    .uid(args[4].parse()?)
                    .gid(args[5].parse()?)
                    .env("MULTISEATD_AUTHORITY_FD", "59")
                    .env("CONTEXT_TEST_AUTHORITY_FD", "59")
                    .env("CONTEXT_TEST_SENTINEL_FD", "60")
                    .env("CONTEXT_TEST_METADATA", "1")
                    .env("XDG_SEAT", "seat-spoofed")
                    .env("XDG_VTNR", "63")
                    .stdin(std::process::Stdio::null());
                unsafe {
                    command.pre_exec(move || {
                        if bad_stdio && libc::dup2(raw, 0) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::dup2(raw, 59) < 0
                            || libc::fcntl(59, libc::F_SETFD, 0) < 0
                            || libc::dup2(extra, 60) < 0
                            || libc::fcntl(60, libc::F_SETFD, 0) < 0
                        {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let status = command.status()?;
                assert_eq!(status.success(), target == args[3] && !bad_stdio);
                let deadline = std::time::Instant::now() + Duration::from_secs(3);
                while client.get_context(context.as_fd())?.4.len() != 1
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                let row = client.get_context(context.as_fd())?;
                assert_eq!(row.4, vec![sibling.id.to_string()]);
                assert!(row.6);
            }
            client.remove_context_by_id(context.id)?;
        }
        Some("libseat") => {
            use std::os::unix::process::CommandExt;
            let (authority, id): (dbus::arg::OwnedFd, String) =
                proxy.method_call(contract::INTERFACE_NAME, "CreateContext", ("seat-test",))?;
            // Normalize received descriptors before exec: only the fresh seatd
            // endpoint will deliberately have CLOEXEC cleared in the child.
            let received = unsafe { OwnedFd::from_raw_fd(authority.into_raw_fd()) };
            let authority = received.try_clone()?;
            drop(received);
            proxy.method_call::<(), _, _, _>(
                contract::INTERFACE_NAME,
                "ActivateContext",
                (dbus_fd(authority.try_clone()?),),
            )?;
            let (endpoint, _): (dbus::arg::OwnedFd, String) = proxy.method_call(
                contract::INTERFACE_NAME,
                "CreateConnection",
                (dbus_fd(authority.try_clone()?),),
            )?;
            let received = unsafe { OwnedFd::from_raw_fd(endpoint.into_raw_fd()) };
            let endpoint = received.try_clone()?;
            drop(received);
            let raw = endpoint.as_raw_fd();
            let mut command = std::process::Command::new(&args[2]);
            command
                .uid(args[3].parse()?)
                .gid(args[4].parse()?)
                .env("SEATD_FD", "57")
                .env("LIBSEAT_BACKEND", "seatd")
                .env(
                    "CONTEXT_TEST_AUTHORITY_FD",
                    authority.as_raw_fd().to_string(),
                )
                .env_remove("MULTISEATD_AUTHORITY_FD")
                .stdin(std::process::Stdio::null());
            // SAFETY: the single-threaded probe's post-fork callback performs
            // only async-signal-safe descriptor syscalls, with no allocation.
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(raw, 57) < 0 || libc::fcntl(57, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            assert!(
                command.status()?.success(),
                "patched C libseat fixture failed"
            );
            proxy.method_call::<(), _, _, _>(
                contract::INTERFACE_NAME,
                "RemoveContextById",
                (id,),
            )?;
        }
        Some("delegate") => {
            let listener = UnixListener::bind(&args[2])?;
            std::fs::set_permissions(&args[2], std::fs::Permissions::from_mode(0o666))?;
            let (fd, _id): (dbus::arg::OwnedFd, String) =
                proxy.method_call(contract::INTERFACE_NAME, "CreateContext", ("seat-test",))?;
            // Creator bus-owner loss must not remove an FD-backed context.
            drop(connection);
            let (mut peer, _) = listener.accept()?;
            let credentials =
                nix::sys::socket::getsockopt(&peer, nix::sys::socket::sockopt::PeerCredentials)?;
            assert_eq!(credentials.uid(), args[3].parse::<u32>()?);
            sendmsg::<()>(
                peer.as_raw_fd(),
                &[IoSlice::new(b"x")],
                &[ControlMessage::ScmRights(&[fd.as_raw_fd()])],
                MsgFlags::MSG_NOSIGNAL,
                None,
            )?;
            drop(fd);
            let mut done = [0];
            peer.read_exact(&mut done)?;
            assert_eq!(done, [b'!']);
        }
        Some("delegated") => {
            let mut peer = UnixStream::connect(&args[2])?;
            let mut bytes = [0];
            let mut vectors = [IoSliceMut::new(&mut bytes)];
            let mut space = nix::cmsg_space!([i32; 1]);
            let message = recvmsg::<()>(
                peer.as_raw_fd(),
                &mut vectors,
                Some(&mut space),
                MsgFlags::MSG_CMSG_CLOEXEC,
            )?;
            assert!(!message.flags.contains(MsgFlags::MSG_CTRUNC));
            let mut descriptors = Vec::new();
            for control in message.cmsgs()? {
                if let ControlMessageOwned::ScmRights(rights) = control {
                    for raw in rights {
                        // SAFETY: recvmsg transferred each descriptor once.
                        descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
                    }
                }
            }
            assert_eq!(descriptors.len(), 1);
            let original = descriptors.pop().unwrap();
            let duplicate = original.try_clone()?;
            drop(original);
            let fd = dbus_fd(duplicate);
            let (row,): (ContextRow,) =
                proxy.method_call(contract::INTERFACE_NAME, "GetContext", (&fd,))?;
            assert_eq!(row.1, "seat-test");
            for member in ["ListSeats", "ListContexts", "ListConnections"] {
                let error = proxy
                    .method_call::<(), _, _, _>(contract::INTERFACE_NAME, member, ())
                    .err()
                    .unwrap();
                assert_eq!(error.name(), Some(ErrorKind::AccessDenied.name()));
            }
            let error = proxy
                .method_call::<(), _, _, _>(
                    contract::INTERFACE_NAME,
                    "RemoveContextById",
                    (&row.0,),
                )
                .err()
                .unwrap();
            assert_eq!(error.name(), Some(ErrorKind::AccessDenied.name()));
            let error = proxy
                .method_call::<(), _, _, _>(
                    contract::INTERFACE_NAME,
                    "CreateContext",
                    ("seat-test",),
                )
                .err()
                .unwrap();
            assert_eq!(error.name(), Some(ErrorKind::AccessDenied.name()));
            proxy.method_call::<(), _, _, _>(contract::INTERFACE_NAME, "RemoveContext", (&fd,))?;
            peer.write_all(b"!")?;
        }
        _ => return Err("expected ready, contract, delegate or delegated".into()),
    }
    Ok(())
}

fn dbus_fd(fd: OwnedFd) -> dbus::arg::OwnedFd {
    // SAFETY: transfer ownership once.
    unsafe { dbus::arg::OwnedFd::from_raw_fd(fd.into_raw_fd()) }
}
