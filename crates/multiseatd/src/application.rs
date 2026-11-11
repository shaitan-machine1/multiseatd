//! Explicit owners, direct source wiring and bounded all-context shutdown.
use crate::{
    daemon::{ShutdownSignals, Watchdog},
    dbus::reactor::BusIo,
    discovery,
    fatal::{self, Fatal},
    seat::Seat,
    sources::{self, BrokerWork, ControlWork, SequentialWork},
};
use dev_broker::{broker::Broker, resources::Resources};
use futures_util::{FutureExt, StreamExt, future::LocalBoxFuture};
use seat_udev::SeatName;
use std::{io, panic::AssertUnwindSafe, sync::Arc};
use tokio::sync::{Semaphore, oneshot, watch};
use tokio::time::{Duration, Instant, sleep_until};

pub struct Configuration {
    pub seat: SeatName,
    pub bus_address: Option<String>,
    pub fixture: Option<discovery::Fixture>,
    #[cfg(feature = "test-support")]
    pub acl_fault: Option<dev_acl::TestFault>,
    #[cfg(feature = "vt")]
    pub vts: std::collections::BTreeSet<u32>,
}
#[cfg(feature = "vt")]
macro_rules! select_sources { ([$($base:tt)*] [$($native:tt)*]) => { tokio::select! { $($base)* $($native)* } }; }
#[cfg(not(feature = "vt"))]
macro_rules! select_sources { ([$($base:tt)*] [$($native:tt)*]) => { tokio::select! { $($base)* } }; }
type Driver = Option<LocalBoxFuture<'static, io::Result<()>>>;
async fn drive(owner: &mut Driver) -> io::Result<()> {
    let result = owner.as_mut().expect("active native driver").await;
    *owner = None;
    result
}
async fn sequential(slot: &mut SequentialWork<'_>) -> fatal::Result<()> {
    let result = slot.as_mut().expect("retained source operation").await;
    *slot = None;
    result
}
fn driver(future: impl std::future::Future<Output = io::Result<()>> + 'static) -> Driver {
    Some(
        async move {
            AssertUnwindSafe(future)
                .catch_unwind()
                .await
                .unwrap_or_else(|_| Err(io::Error::other("critical driver panicked")))
        }
        .boxed_local(),
    )
}
fn failed(fatal: &Fatal, role: &str, error: impl std::fmt::Display) {
    fatal.fail(format!("{role}: {error}"));
}

pub async fn run(config: Configuration, signals: &ShutdownSignals) -> io::Result<()> {
    #[cfg(feature = "test-support")]
    if config.acl_fault.is_some() && config.fixture.is_none() {
        return Err(io::Error::other(
            "ACL fault injection requires a disposable fixture backend",
        ));
    }
    let workers = Arc::new(Semaphore::new(4));
    let resources = Arc::new(Resources::new(4096)?);
    let (broker, control, broker_events) = Broker::new(
        config.seat.as_str().into(),
        config.fixture.is_some(),
        resources.clone(),
        workers.clone(),
    );
    let fatal = Fatal::new(control.clone());
    let watchdog = Watchdog::start(fatal.clone())?;
    let mut discovery = match discovery::Owner::start(config.fixture, fatal.clone()) {
        Ok(owner) => owner,
        Err(error) => {
            failed(&fatal, "discovery startup", &error);
            return Err(error);
        }
    };
    let discovery_events = discovery.take_events()?;
    #[cfg(feature = "vt")]
    let mut terminal = match linux_vt::Owner::claim_all(&config.vts) {
        Ok(owner) => owner,
        Err(error) => {
            failed(&fatal, "native terminal startup", &error);
            abort_startup(&mut discovery, None).await;
            return Err(error);
        }
    };
    #[cfg(feature = "vt")]
    {
        let end = Instant::now() + fatal::EFFECT_LIMIT;
        let token = fatal.begin_effect(end);
        let result = tokio::time::timeout_at(end, terminal.ready()).await;
        fatal.end_effect(token);
        let result = result
            .map_err(|_| io::Error::other("native startup claim deadline expired"))
            .and_then(|result| result);
        if result.is_err() || fatal.failed() {
            let error = result
                .err()
                .unwrap_or_else(|| io::Error::other("independent startup claim watchdog expired"));
            failed(&fatal, "native terminal readiness", &error);
            abort_startup(&mut discovery, Some(&mut terminal)).await;
            return Err(error);
        }
    }
    #[cfg(feature = "vt")]
    let vt_control = terminal.control();
    #[cfg(feature = "vt")]
    let vt_notices = terminal.take_notices()?;
    let seat = match Seat::new(
        config.seat.clone(),
        control.clone(),
        discovery.control(),
        fatal.clone(),
        workers,
        #[cfg(feature = "vt")]
        vt_control.clone(),
        #[cfg(feature = "vt")]
        config.vts,
    ) {
        Ok(seat) => seat,
        Err(error) => {
            failed(&fatal, "seat construction", &error);
            abort_startup(
                &mut discovery,
                #[cfg(feature = "vt")]
                Some(&mut terminal),
            )
            .await;
            return Err(error);
        }
    };
    #[cfg(feature = "test-support")]
    if let Some(fault) = config.acl_fault {
        seat.inject_acl_fault(fault)?;
    }
    let mut broker_driver = driver(broker.run());
    let mut bus_driver = None;
    let (stop_bus, stopping_bus) = watch::channel(false);
    let mut startup = Some(sources::operation(&seat, seat.initialize()));
    let mut controls = ControlWork::new();
    let mut broker_work = BrokerWork::new();
    let mut udev_work = None;
    #[cfg(feature = "vt")]
    let mut vt_work = None;
    let mut broker_done = false;
    // Startup remains parent-owned even if an independent owner fails first.
    tokio::select! {
        result = sequential(&mut startup) => if let Err(error) = result { failed(&fatal, "initial inventory", error); },
        result = drive(&mut broker_driver) => { broker_done = result.is_ok(); failed(&fatal, "startup broker exit", result.err().map_or_else(|| "unexpected normal exit".into(), |error| error.to_string())); },
        _ = fatal.wait_stopping() => {},
        result = signals.requested() => match result { Ok(_) => fatal.stop(), Err(error) => failed(&fatal, "shutdown signal owner", error) },
    }
    if !fatal.stopping() {
        match BusIo::connect(
            libmultiseatd::bus_name(config.seat.as_str()).map_err(io::Error::other)?,
            config.bus_address.as_deref(),
            fatal.clone(),
        ) {
            Err(error) => failed(&fatal, "D-Bus connection", error),
            Ok((bus, requests, replies)) => {
                // The parent retains the output port through reply/cleanup
                // barriers even when capture exits with no pending callers.
                let _reply_owner = replies.clone();
                let (ready, _ready_receiver) = oneshot::channel();
                bus_driver = driver(bus.run(stopping_bus, ready));
                // Adapter futures borrow parent-owned work storage. Dropping a
                // failed capture future never discards an admitted operation.
                {
                    let control_source = AssertUnwindSafe(sources::run_control(
                        &seat,
                        requests,
                        replies,
                        &mut controls,
                    ))
                    .catch_unwind();
                    let udev_source = AssertUnwindSafe(sources::run_udev(
                        &seat,
                        discovery_events,
                        &mut udev_work,
                    ))
                    .catch_unwind();
                    let broker_source = AssertUnwindSafe(sources::run_broker(
                        &seat,
                        &control,
                        broker_events,
                        &mut broker_work,
                    ))
                    .catch_unwind();
                    #[cfg(feature = "vt")]
                    let vt_source =
                        AssertUnwindSafe(sources::run_vt(&seat, vt_notices, &mut vt_work))
                            .catch_unwind();
                    tokio::pin!(control_source, udev_source, broker_source);
                    #[cfg(feature = "vt")]
                    tokio::pin!(vt_source);
                    select_sources! {[
                        result = &mut control_source => failed(&fatal, "control adapter", source_result(result)),
                        result = &mut udev_source => failed(&fatal, "udev adapter", source_result(result)),
                        result = &mut broker_source => failed(&fatal, "broker adapter", source_result(result)),
                        result = drive(&mut broker_driver) => { broker_done = result.is_ok(); failed(&fatal, "broker driver", result.err().map_or_else(|| "unexpected normal exit".into(), |error| error.to_string())); },
                        result = drive(&mut bus_driver) => failed(&fatal, "D-Bus driver", result.err().map_or_else(|| "unexpected normal exit".into(), |error| error.to_string())),
                        _ = fatal.wait_stopping() => {},
                        result = signals.requested() => match result { Ok(_) => fatal.stop(), Err(error) => failed(&fatal, "shutdown signal owner", error) },
                    ] [result = &mut vt_source => failed(&fatal, "VT adapter", source_result(result)),]}
                }
                drain_and_cleanup(
                    &seat,
                    &fatal,
                    &mut discovery,
                    &mut broker_driver,
                    &mut bus_driver,
                    stop_bus,
                    &resources,
                    &mut controls,
                    &mut broker_work,
                    &mut startup,
                    &mut udev_work,
                    #[cfg(feature = "vt")]
                    &mut vt_work,
                    #[cfg(feature = "vt")]
                    &mut terminal,
                    #[cfg(feature = "vt")]
                    &vt_control,
                    &mut broker_done,
                )
                .await?;
                if fatal.failed() {
                    return Err(io::Error::other(
                        fatal
                            .reason()
                            .unwrap_or_else(|| "fatal seat failure".into()),
                    ));
                }
                watchdog.finish();
                return Ok(());
            }
        }
    }
    drain_and_cleanup(
        &seat,
        &fatal,
        &mut discovery,
        &mut broker_driver,
        &mut bus_driver,
        stop_bus,
        &resources,
        &mut controls,
        &mut broker_work,
        &mut startup,
        &mut udev_work,
        #[cfg(feature = "vt")]
        &mut vt_work,
        #[cfg(feature = "vt")]
        &mut terminal,
        #[cfg(feature = "vt")]
        &vt_control,
        &mut broker_done,
    )
    .await?;
    // Keep the independent exit watchdog armed through fatal diagnostics/exit.
    Err(io::Error::other(
        fatal
            .reason()
            .unwrap_or_else(|| "seat stopped during startup".into()),
    ))
}
async fn abort_startup(
    discovery: &mut discovery::Owner,
    #[cfg(feature = "vt")] terminal: Option<&mut linux_vt::Owner>,
) {
    // No broker driver/admission has ever run here. Native restoration cannot
    // precede an outstanding device barrier because none has been admitted.
    let _ = discovery.control().stop();
    #[cfg(feature = "vt")]
    if let Some(owner) = terminal {
        let _ = tokio::time::timeout(fatal::FLUSH_LIMIT, owner.control().shutdown()).await;
        let end = Instant::now() + fatal::FLUSH_LIMIT;
        while Instant::now() < end {
            match owner.join_if_finished() {
                Ok(true) | Err(_) => break,
                Ok(false) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    }
    let end = Instant::now() + fatal::FLUSH_LIMIT;
    while Instant::now() < end {
        match discovery.join_if_finished() {
            Ok(true) | Err(_) => break,
            Ok(false) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
}
fn source_result(
    result: std::result::Result<fatal::Result<()>, Box<dyn std::any::Any + Send>>,
) -> String {
    match result {
        Ok(Ok(())) => "unexpected adapter exit".into(),
        Ok(Err(error)) => error.to_string(),
        Err(_) => "adapter panicked; admitted operations retained".into(),
    }
}
#[allow(clippy::too_many_arguments)]
async fn drain_and_cleanup<'a>(
    seat: &'a Seat,
    fatal: &Fatal,
    discovery: &mut discovery::Owner,
    broker_driver: &mut Driver,
    bus_driver: &mut Driver,
    stop_bus: watch::Sender<bool>,
    resources: &Arc<Resources>,
    controls: &mut ControlWork<'a>,
    broker_work: &mut BrokerWork<'a>,
    startup: &mut SequentialWork<'a>,
    udev: &mut SequentialWork<'a>,
    #[cfg(feature = "vt")] vt: &mut SequentialWork<'a>,
    #[cfg(feature = "vt")] terminal: &mut linux_vt::Owner,
    #[cfg(feature = "vt")] vt_control: &linux_vt::Control,
    broker_done: &mut bool,
) -> io::Result<()> {
    fatal.stop();
    // FIRST keep polling requests and the actual bus flush pump. Neither State
    // nor an unresponsive worker is needed to send the explicit fatal response.
    let reply_barrier = Instant::now() + Duration::from_millis(750);
    loop {
        select_sources! {[
            _ = sleep_until(reply_barrier) => break,
            _ = controls.next(), if !controls.is_empty() => {},
            _ = broker_work.next(), if !broker_work.is_empty() => {},
            _ = sequential(startup), if startup.is_some() => {},
            _ = sequential(udev), if udev.is_some() => {},
            result = drive(broker_driver), if broker_driver.is_some() => { *broker_done = result.is_ok(); if let Err(error) = result { failed(fatal, "broker during reply barrier", error); } },
            result = drive(bus_driver), if bus_driver.is_some() => if let Err(error) = result { failed(fatal, "bus during reply barrier", error); },
        ] [_ = sequential(vt), if vt.is_some() => {},]}
    }
    // Only now begin all-context/resource/terminal cleanup. Started workers and
    // their guard/pins remain owned while this independent bound is polled.
    let end = Instant::now() + fatal::CLEANUP_LIMIT;
    let cleanup = seat.cleanup();
    tokio::pin!(cleanup);
    let mut acl_done = false;
    #[cfg(feature = "vt")]
    let mut acl_clean = false;
    let mut cleanup_errors = Vec::new();
    let mut fallback: Option<tokio::task::JoinHandle<Vec<io::Error>>> = None;
    let mut fallback_done = false;
    let mut discovery_done = false;
    if let Err(error) = discovery.control().stop() {
        cleanup_errors.push(error.to_string());
    }
    #[cfg(feature = "vt")]
    let mut native_shutdown: Option<LocalBoxFuture<'_, io::Result<()>>> = None;
    #[cfg(feature = "vt")]
    let mut terminal_done = false;
    loop {
        if broker_driver.is_none() && !*broker_done && !fallback_done && fallback.is_none() {
            let resources = resources.clone();
            fallback = Some(tokio::task::spawn_blocking(move || resources.cleanup()));
        }
        if !discovery_done {
            match discovery.join_if_finished() {
                Ok(done) => discovery_done = done,
                Err(error) => {
                    discovery_done = true;
                    cleanup_errors.push(error.to_string());
                }
            }
        }
        #[cfg(feature = "vt")]
        if acl_clean
            && broker_driver.is_none()
            && (*broker_done || fallback_done)
            && resources.pending() == 0
            && native_shutdown.is_none()
            && !terminal_done
        {
            native_shutdown = Some(vt_control.shutdown().boxed_local());
        }
        #[cfg(feature = "vt")]
        if terminal_done {
            match terminal.join_if_finished() {
                Ok(_) => {}
                Err(error) => cleanup_errors.push(error.to_string()),
            }
        }
        #[cfg(not(feature = "vt"))]
        let terminal_joined = true;
        #[cfg(feature = "vt")]
        let terminal_joined = terminal_done && terminal.join_if_finished().unwrap_or(false);
        if acl_done
            && discovery_done
            && broker_driver.is_none()
            && resources.pending() == 0
            && terminal_joined
            && controls.is_empty()
            && broker_work.is_empty()
            && startup.is_none()
            && udev.is_none()
            && {
                #[cfg(feature = "vt")]
                {
                    vt.is_none()
                }
                #[cfg(not(feature = "vt"))]
                {
                    true
                }
            }
        {
            break;
        }
        select_sources! {[
            _ = sleep_until(end) => { cleanup_errors.push(format!("cleanup bound expired: {} retained broker originals; ACL/operations/native owners may remain unsettled", resources.pending())); break; },
            result = &mut cleanup, if !acl_done => {
                let (settled,errors)=result;
                acl_done = true;
                #[cfg(feature = "vt")]
                { acl_clean = settled; }
                #[cfg(not(feature = "vt"))]
                let _ = settled;
                cleanup_errors.extend(errors.into_iter().map(|error| error.to_string()));
            },
            result = drive(broker_driver), if broker_driver.is_some() => { *broker_done = result.is_ok(); if let Err(error) = result { cleanup_errors.push(error.to_string()); } },
            result = drive(bus_driver), if bus_driver.is_some() => if let Err(error) = result { cleanup_errors.push(error.to_string()); },
            result = async { fallback.as_mut().expect("retained cleanup worker").await }, if fallback.is_some() => {
                fallback_done = true; fallback.take();
                match result { Ok(errors) => cleanup_errors.extend(errors.into_iter().map(|error| error.to_string())), Err(error) => cleanup_errors.push(error.to_string()) }
            }
            _ = controls.next(), if !controls.is_empty() => {},
            _ = broker_work.next(), if !broker_work.is_empty() => {},
            _ = sequential(startup), if startup.is_some() => {},
            _ = sequential(udev), if udev.is_some() => {},
            _ = tokio::time::sleep(Duration::from_millis(10)) => {},
        ] [
            result = async { native_shutdown.as_mut().expect("retained native restoration").await }, if native_shutdown.is_some() => {
                native_shutdown.take(); terminal_done = true; if let Err(error) = result { cleanup_errors.push(error.to_string()); }
            },
            _ = sequential(vt), if vt.is_some() => {},
        ]}
    }
    stop_bus.send_replace(true);
    if bus_driver.is_some() {
        match tokio::time::timeout(fatal::FLUSH_LIMIT, drive(bus_driver)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => cleanup_errors.push(error.to_string()),
            Err(_) => cleanup_errors.push("bus owner did not join".into()),
        }
    }
    if cleanup_errors.is_empty() {
        Ok(())
    } else {
        failed(fatal, "bounded cleanup", cleanup_errors.join("; "));
        Err(io::Error::other(cleanup_errors.join("; ")))
    }
}
