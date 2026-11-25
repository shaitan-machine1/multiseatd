//! Direct borrowing adapters. All admitted futures live in parent-owned storage.
use crate::{
    dbus::{
        manager,
        reactor::{Replies, Request},
    },
    discovery,
    fatal::{Error, Result},
    seat::Seat,
};
use dev_broker::broker;
use futures_util::{FutureExt, StreamExt, future::LocalBoxFuture, stream::FuturesUnordered};
use libmultiseatd::ErrorKind;
use std::{future::Future, io, panic::AssertUnwindSafe};
use tokio::sync::mpsc;
use tokio::time::{Duration, interval, sleep_until};

pub enum ControlDone {
    Call,
    Prune,
}
pub type ControlWork<'a> = FuturesUnordered<LocalBoxFuture<'a, ControlDone>>;
pub type BrokerWork<'a> = FuturesUnordered<LocalBoxFuture<'a, Result<()>>>;
pub type SequentialWork<'a> = Option<LocalBoxFuture<'a, Result<()>>>;

pub fn operation<'a>(
    seat: &'a Seat,
    work: impl Future<Output = Result<()>> + 'a,
) -> LocalBoxFuture<'a, Result<()>> {
    async move {
        match AssertUnwindSafe(work).catch_unwind().await {
            Ok(result) => result,
            Err(_) => Err(seat
                .fatal()
                .fail("source operation panicked; State guard fenced before unlock")),
        }
    }
    .boxed_local()
}
async fn call(request: Request, seat: &Seat, replies: Replies) -> ControlDone {
    let dispatch = AssertUnwindSafe(manager::dispatch(&request, seat)).catch_unwind();
    tokio::pin!(dispatch);
    let completed = if seat.fatal().stopping() {
        None
    } else {
        tokio::select! {
            biased;
            result = &mut dispatch => Some(result),
            _ = seat.fatal().wait_stopping() => None,
            _ = sleep_until(request.received + crate::fatal::SERVER_WAIT) => {
                seat.fatal().fail("control operation exceeded all bounded completion paths"); None
            }
        }
    };
    let (reply, unfinished) = match completed {
        Some(Ok(Ok(message))) => (message, false),
        Some(Ok(Err(error))) => (manager::failure(&request.message, &error), false),
        Some(Err(_)) => {
            let error = seat.fatal().fail("control operation panicked");
            (manager::failure(&request.message, &error), false)
        }
        None => {
            let error = Error::new(
                if seat.fatal().failed() {
                    ErrorKind::CriticalFailure
                } else {
                    ErrorKind::Stopping
                },
                "seat stopped; admitted work remains owned for bounded cleanup",
            );
            (manager::failure(&request.message, &error), true)
        }
    };
    if let Err(error) = replies.send_flush(reply).await {
        seat.fatal()
            .fail(format!("bounded D-Bus reply send/flush: {error}"));
    }
    // A fatal notice/reply is NOT cancellation. This operation may still own
    // State and uncancellable workers. Parent supervision continues polling it.
    if unfinished {
        let _ = dispatch.await;
    }
    ControlDone::Call
}
pub async fn run_control<'a>(
    seat: &'a Seat,
    mut requests: mpsc::Receiver<Request>,
    replies: Replies,
    work: &mut ControlWork<'a>,
) -> Result<()> {
    let mut prune = false;
    let mut tick = interval(Duration::from_millis(100));
    let mut changes = seat.changes();
    let mut incoming = seat.take_master_watches();
    let mut masters = FuturesUnordered::new();
    loop {
        tokio::select! {
            finished = work.next(), if !work.is_empty() => if matches!(finished, Some(ControlDone::Prune)) { prune = false; },
            request = requests.recv(), if work.len() < 64 => {
                let request = request.ok_or_else(|| seat.fatal().fail("control capture owner stopped"))?;
                work.push(call(request, seat, replies.clone()).boxed_local());
            }
            watch = incoming.recv(), if masters.len() < 128 => {
                if let Some(watch) = watch { masters.push(watch.wait().boxed_local()); }
            }
            result = masters.next(), if !masters.is_empty() && work.len() < 64 => {
                match result {
                    Some(Ok(Some(id))) => work.push(async move {
                        let _ = operation(seat, seat.master_exited(id)).await;
                        ControlDone::Call
                    }.boxed_local()),
                    Some(Err(e)) => return Err(seat.fatal().fail(format!("master observation: {e}"))),
                    _ => {},
                }
            }
            _ = changes.changed() => replies.state_changed(*changes.borrow_and_update()),
            _ = tick.tick(), if !prune && work.len() < 64 => {
                prune = true;
                work.push(async move { let _ = operation(seat, seat.prune_authorities()).await; ControlDone::Prune }.boxed_local());
            }
        }
    }
}
pub async fn run_udev<'a>(
    seat: &'a Seat,
    mut events: mpsc::Receiver<discovery::Event>,
    slot: &mut SequentialWork<'a>,
) -> Result<()> {
    loop {
        if let Some(work) = slot.as_mut() {
            let result = work.await;
            *slot = None;
            result?;
        }
        let event = events
            .recv()
            .await
            .ok_or_else(|| seat.fatal().fail("udev capture owner stopped"))?;
        *slot = Some(operation(seat, seat.physical_event(event)));
    }
}
pub async fn run_broker<'a>(
    seat: &'a Seat,
    control: &'a broker::Control,
    mut events: mpsc::Receiver<broker::Event>,
    work: &mut BrokerWork<'a>,
) -> Result<()> {
    loop {
        tokio::select! {
            result = work.next(), if !work.is_empty() => {
                if let Some(Err(error)) = result && error.kind == ErrorKind::CriticalFailure { return Err(error); }
            }
            event = events.recv(), if work.len() < 64 => {
                let event = event.ok_or_else(|| seat.fatal().fail("broker capture owner stopped"))?;
                let future: LocalBoxFuture<'a, Result<()>> = match event {
                    broker::Event::Open { key, path, permission, done } => operation(seat, seat.broker_open(key, path, permission, done)),
                    broker::Event::Publish { key, slot, permission, output, done } => operation(seat, seat.publish_device(key, slot, permission, output, done)),
                    broker::Event::Gone(key) => operation(seat, seat.connection_gone(key)),
                    broker::Event::Switch { key, target, permission, done } => operation(seat, async move {
                        let result = seat.protocol_switch(key, target, permission).await;
                        let result = result.map_err(|error| io::Error::from_raw_os_error(match error.kind {
                            ErrorKind::InvalidArgument => libc::EINVAL, ErrorKind::NotAuthorized => libc::EACCES,
                            ErrorKind::Busy | ErrorKind::LimitExceeded => libc::EAGAIN, _ => libc::EIO,
                        }));
                        control.switch_completed(key, result, done).await.map_err(|error| seat.fatal().fail(format!("broker switch completion: {error}")))
                    }),
                };
                work.push(future);
            }
        }
    }
}
#[cfg(feature = "vt")]
pub async fn run_vt<'a>(
    seat: &'a Seat,
    notices: linux_vt::Notices,
    slot: &mut SequentialWork<'a>,
) -> Result<()> {
    use std::os::fd::AsFd;
    let descriptor = notices
        .fd()
        .try_clone_to_owned()
        .map_err(|error| seat.fatal().fail(error.to_string()))?;
    let watched = unsafe {
        tokio::io::unix::AsyncFd::register_with_interest(
            descriptor.as_fd(),
            tokio::io::Interest::READABLE,
        )
    }
    .map_err(|error| seat.fatal().fail(error.to_string()))?;
    loop {
        if let Some(work) = slot.as_mut() {
            let result = work.await;
            *slot = None;
            result?;
        }
        match notices
            .try_next()
            .map_err(|error| seat.fatal().fail(format!("native VT capture: {error}")))?
        {
            Some(linux_vt::Notice::ReleaseRequested) => {
                *slot = Some(operation(seat, seat.release_requested()))
            }
            Some(linux_vt::Notice::ForegroundAcquired) => {
                *slot = Some(operation(seat, seat.foreground_observed()))
            }
            None => {
                let mut ready = watched
                    .readable()
                    .await
                    .map_err(|error| seat.fatal().fail(error.to_string()))?;
                notices
                    .clear_ready()
                    .map_err(|error| seat.fatal().fail(error.to_string()))?;
                ready.clear_ready();
            }
        }
    }
}
