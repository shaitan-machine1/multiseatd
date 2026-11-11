//! Explicit monitor/enumeration owner. No retained second device inventory.
use crate::{
    catalog::{AccessClass, AssignmentKey, AssignmentScan, ObservedNode},
    fatal::Fatal,
};
use dev_acl::PinnedNode;
use dev_broker::device::{AllowedDevice, DeviceId, DeviceKind};
use seat_udev::{PhysicalHint, PhysicalMonitor, ResolvedDevice, SeatName};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use tokio::sync::{mpsc as queue, oneshot};

pub struct Snapshot {
    pub sequence: u64,
    pub scan: AssignmentScan,
}
pub struct Event {
    pub sequence: u64,
    pub hint: PhysicalHint,
}
enum Command {
    Scan(oneshot::Sender<io::Result<Snapshot>>),
    Current(PathBuf, oneshot::Sender<io::Result<Option<ObservedNode>>>),
    Stop,
    RefreshNeeded,
}
#[derive(Clone)]
pub struct Control {
    commands: mpsc::SyncSender<Command>,
    wake: Arc<UnixStream>,
}
impl Control {
    fn submit(&self, command: Command) -> io::Result<()> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => io::Error::from_raw_os_error(libc::EAGAIN),
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::from_raw_os_error(libc::ESHUTDOWN)
                }
            })?;
        let byte = 1u8;
        // A queued command remains owned even if the native peer exits before
        // this advisory wake. The receipt/join provides the actual result.
        let _ = unsafe {
            libc::send(
                self.wake.as_raw_fd(),
                (&byte as *const u8).cast(),
                1,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        Ok(())
    }
    pub async fn scan(&self) -> io::Result<Snapshot> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Scan(reply))?;
        result
            .await
            .map_err(|_| io::Error::other("discovery owner stopped"))?
    }
    pub async fn current(&self, path: PathBuf) -> io::Result<Option<ObservedNode>> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Current(path, reply))?;
        result
            .await
            .map_err(|_| io::Error::other("discovery owner stopped"))?
    }
    pub fn refresh_needed(&self) {
        let _ = self.submit(Command::RefreshNeeded);
    }
    pub fn stop(&self) -> io::Result<()> {
        self.submit(Command::Stop)
    }
}
#[derive(Clone)]
pub struct Fixture {
    pub seat: SeatName,
    pub direct_nodes: Vec<PathBuf>,
    pub null_device: bool,
    pub assignments: Option<PathBuf>,
}
impl Fixture {
    fn scan(&self) -> io::Result<AssignmentScan> {
        let mut assignments = BTreeMap::new();
        let mut nodes = Vec::new();
        for path in &self.direct_nodes {
            let key = format!("fixture:{}", path.display());
            assignments.insert(AssignmentKey(key.clone()), self.seat.clone());
            match PinnedNode::open(path) {
                Ok(pin) => nodes.push(ObservedNode {
                    key: key.clone(),
                    assignment: AssignmentKey(key),
                    path: path.clone(),
                    identity: pin.identity(),
                    pin: Arc::new(pin),
                    class: AccessClass::Direct,
                    acl_managed: true,
                    broker: None,
                }),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        if self.null_device {
            let path = PathBuf::from("/dev/null");
            let key = "fixture:null".to_string();
            assignments.insert(AssignmentKey(key.clone()), self.seat.clone());
            let metadata = std::fs::metadata(&path)?;
            nodes.push(ObservedNode {
                key: key.clone(),
                assignment: AssignmentKey(key.clone()),
                identity: PinnedNode::open(&path)?.identity(),
                pin: Arc::new(PinnedNode::open(&path)?),
                broker: Some(AllowedDevice::canonicalized(
                    DeviceId::new(key),
                    &path,
                    metadata.rdev(),
                    DeviceKind::Evdev,
                )?),
                path,
                class: AccessClass::Broker,
                acl_managed: false,
            });
        }
        if let Some(path) = &self.assignments {
            for line in std::fs::read_to_string(path)?
                .lines()
                .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            {
                let words: Vec<_> = line.split_whitespace().collect();
                if words.len() != 2 {
                    return Err(io::Error::other("fixture mapping requires KEY SEAT"));
                }
                let seat = SeatName::parse(words[1]).map_err(io::Error::other)?;
                let key = AssignmentKey(words[0].into());
                if !assignments.contains_key(&key) {
                    return Err(io::Error::other("unknown fixture assignment key"));
                }
                assignments.insert(key, seat);
            }
        }
        Ok(AssignmentScan { assignments, nodes })
    }
}
pub struct Owner {
    control: Control,
    events: Option<queue::Receiver<Event>>,
    thread: Option<JoinHandle<io::Result<()>>>,
}
impl Owner {
    pub fn start(fixture: Option<Fixture>, fatal: Fatal) -> io::Result<Self> {
        let (wake, waiting) = UnixStream::pair()?;
        wake.set_nonblocking(true)?;
        waiting.set_nonblocking(true)?;
        let (commands, receiver) = mpsc::sync_channel(64);
        let (events, incoming) = queue::channel(256);
        let (ready, started) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("seat-udev".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let monitor = if fixture.is_none() {
                        Some(PhysicalMonitor::new().map_err(io::Error::other)?)
                    } else {
                        None
                    };
                    let _ = ready.send(());
                    run(monitor, fixture, waiting, receiver, events)
                }));
                match result {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => {
                        fatal.fail(format!("discovery owner: {error}"));
                        Err(error)
                    }
                    Err(_) => {
                        fatal.fail("discovery owner panicked");
                        Err(io::Error::other("discovery owner panicked"))
                    }
                }
            })?;
        started
            .recv()
            .map_err(|_| io::Error::other("discovery startup failed"))?;
        Ok(Self {
            control: Control {
                commands,
                wake: Arc::new(wake),
            },
            events: Some(incoming),
            thread: Some(thread),
        })
    }
    pub fn control(&self) -> Control {
        self.control.clone()
    }
    pub fn take_events(&mut self) -> io::Result<queue::Receiver<Event>> {
        self.events
            .take()
            .ok_or_else(|| io::Error::other("discovery events already taken"))
    }
    pub fn join_if_finished(&mut self) -> io::Result<bool> {
        if self
            .thread
            .as_ref()
            .is_none_or(|thread| thread.is_finished())
        {
            if let Some(thread) = self.thread.take() {
                thread
                    .join()
                    .map_err(|_| io::Error::other("discovery join panic"))??;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
fn run(
    mut monitor: Option<PhysicalMonitor>,
    fixture: Option<Fixture>,
    waiting: UnixStream,
    commands: mpsc::Receiver<Command>,
    events: queue::Sender<Event>,
) -> io::Result<()> {
    let mut sequence = 0u64;
    let mut lost = false;
    loop {
        if let Some(monitor) = &mut monitor {
            for _ in 0..256 {
                let captured = match monitor.receive() {
                    Ok(hint) => hint,
                    Err(error) => {
                        tracing::warn!(%error, "udev input lost; explicit seat refresh required");
                        break;
                    }
                };
                let Some(hint) = captured else { break };
                if let Some(hint) = hint {
                    sequence = sequence
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("discovery sequence exhaustion"))?;
                    if events.try_send(Event { sequence, hint }).is_err() {
                        if !lost {
                            tracing::warn!(
                                "udev capture saturated; explicit seat refresh required"
                            );
                        }
                        lost = true;
                    }
                }
            }
        }
        for _ in 0..64 {
            let command = match commands.try_recv() {
                Ok(command) => command,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(_) => return Ok(()),
            };
            match command {
                Command::Stop => return Ok(()),
                Command::RefreshNeeded => {
                    tracing::warn!("catalog capacity reached; explicit seat refresh required")
                }
                Command::Scan(reply) => {
                    // State's exclusive admission precedes this snapshot. Hints
                    // captured later have larger sequence and are revalidated.
                    let baseline = sequence;
                    let scan = if let Some(fixture) = &fixture {
                        fixture.scan()
                    } else {
                        fresh_scan()
                    };
                    if scan.is_ok() {
                        lost = false;
                    }
                    let _ = reply.send(scan.map(|scan| Snapshot {
                        sequence: baseline,
                        scan,
                    }));
                }
                Command::Current(path, reply) => {
                    let result = if let Some(fixture) = &fixture {
                        fixture.scan().map(|scan| {
                            scan.nodes
                                .into_iter()
                                .find(|node| node.key == path.to_string_lossy())
                        })
                    } else {
                        seat_udev::resolve_current(&path)
                            .map_err(io::Error::other)
                            .and_then(|node| node.map(observed).transpose())
                            .map(Option::flatten)
                    };
                    let _ = reply.send(result);
                }
            }
        }
        let mut fds = [
            libc::pollfd {
                fd: waiting.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: monitor
                    .as_ref()
                    .map_or(-1, |monitor| monitor.fd().as_raw_fd()),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if fds
            .iter()
            .any(|fd| fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0)
        {
            return Err(io::Error::other("discovery descriptor failed"));
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let mut bytes = [0u8; 128];
            unsafe {
                libc::read(waiting.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len());
            }
        }
    }
}
fn observed(resolved: ResolvedDevice) -> io::Result<Option<ObservedNode>> {
    let device = resolved.device;
    let Some(path) = device.devnode else {
        return Ok(None);
    };
    let pin = match PinnedNode::open(&path) {
        Ok(pin) => Arc::new(pin),
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::ENOENT | libc::ENODEV | libc::ELOOP)
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let identity = pin.identity();
    if !identity.is_device() || device.devnum != Some(identity.device_number()) {
        return Ok(None);
    }
    if !device
        .node_identity
        .is_some_and(|observed| identity.same_inode(observed))
    {
        return Ok(None);
    }
    let kind = match device.kind {
        seat_udev::DeviceKind::Drm => Some(DeviceKind::DrmPrimary),
        seat_udev::DeviceKind::Evdev => Some(DeviceKind::Evdev),
        seat_udev::DeviceKind::Hidraw => Some(DeviceKind::Hidraw),
        _ => None,
    };
    let key = device.syspath.to_string_lossy().into_owned();
    let broker = kind
        .map(|kind| {
            AllowedDevice::canonicalized(
                DeviceId::new(key.clone()),
                &path,
                device
                    .devnum
                    .ok_or_else(|| io::Error::other("broker devnum missing"))?,
                kind,
            )
        })
        .transpose()?;
    if broker.as_ref().is_some_and(|broker| {
        !broker.same_inode(device.node_identity.expect("validated initialized inode"))
    }) {
        return Ok(None);
    }
    Ok(Some(ObservedNode {
        key,
        assignment: AssignmentKey(resolved.assignment),
        path,
        identity,
        pin,
        class: if broker.is_some() {
            AccessClass::Broker
        } else {
            AccessClass::Direct
        },
        acl_managed: true,
        broker,
    }))
}
fn fresh_scan() -> io::Result<AssignmentScan> {
    let source = seat_udev::fresh_inventory().map_err(io::Error::other)?;
    let assignments = source
        .assignments
        .into_iter()
        .map(|(key, seat)| (AssignmentKey(key), seat))
        .collect();
    let mut nodes = Vec::new();
    let mut paths = BTreeSet::new();
    for device in source.devices {
        if let Some(node) = observed(device)?
            && paths.insert(node.path.clone())
        {
            nodes.push(node);
        }
    }
    for path in source.static_nodes {
        if !paths.insert(path.clone()) {
            continue;
        }
        let pin = match PinnedNode::open(&path) {
            Ok(pin) => Arc::new(pin),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOENT | libc::ENODEV | libc::ELOOP)
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let identity = pin.identity();
        if !identity.is_device() {
            return Err(io::Error::other(
                "static uaccess tag does not identify a real device node",
            ));
        }
        let key = format!("static:{}", path.display());
        nodes.push(ObservedNode {
            key: key.clone(),
            assignment: AssignmentKey(key),
            path,
            identity,
            pin,
            class: AccessClass::Direct,
            acl_managed: true,
            broker: None,
        });
    }
    let scan = AssignmentScan { assignments, nodes };
    crate::catalog::DeviceCatalog::validate_scan(&scan)?;
    Ok(scan)
}
