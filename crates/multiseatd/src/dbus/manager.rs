//! Argument/authentication boundary and typed routing; no seat policy here.

use super::reactor::{Replies, Request, error_reply, requires_root};
use crate::authority::AuthorityError;
use crate::registry::{Registry, RegistryError};
use crate::seat::{Command, Port};
use dbus::Message;
use dbus::arg::{ArgType, ReadAll};
use libmultiseatd::contract::{self, ErrorKind};
use libmultiseatd::{ConnectionId, ContextId};
use seat_udev::SeatName;
use std::collections::BTreeMap;
use std::future::Future;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::pin::Pin;
use tokio::sync::oneshot;
use tokio::time::{Duration, timeout};

pub type Pending = Pin<Box<dyn Future<Output = ()> + Send>>;
type Failure = (ErrorKind, String);

pub fn arguments<T: ReadAll>(message: &Message) -> Result<T, Failure> {
    let mut iter = message.iter_init();
    let value =
        T::read(&mut iter).map_err(|error| (ErrorKind::InvalidArgument, error.to_string()))?;
    if iter.arg_type() != ArgType::Invalid {
        return Err((ErrorKind::InvalidArgument, "trailing arguments".into()));
    }
    Ok(value)
}

pub fn dispatch(
    request: Request,
    registry: &mut Registry,
    seats: &BTreeMap<SeatName, Port>,
    replies: Replies,
) -> Pending {
    let message = request.message;
    match admit(&message, request.uid, registry, seats, replies.clone()) {
        Ok(Work::Immediate(reply)) => Box::pin(async move {
            let _ = replies.send(reply);
        }),
        Ok(Work::Deferred(work)) => work,
        Err((kind, reason)) => Box::pin(async move {
            let _ = replies.send(error_reply(&message, kind, &reason));
        }),
    }
}

enum Work {
    Immediate(Message),
    Deferred(Pending),
}

fn admit(
    message: &Message,
    uid: Option<u32>,
    registry: &mut Registry,
    seats: &BTreeMap<SeatName, Port>,
    replies: Replies,
) -> Result<Work, Failure> {
    if message.path().as_deref() != Some(contract::OBJECT_PATH) {
        return Err((ErrorKind::InvalidArgument, "unknown object".into()));
    }
    let member = message
        .member()
        .map(|value| value.to_string())
        .unwrap_or_default();
    let interface = message
        .interface()
        .map(|value| value.to_string())
        .unwrap_or_default();
    if (interface.as_str(), member.as_str())
        == ("org.freedesktop.DBus.Introspectable", "Introspect")
    {
        arguments::<()>(message)?;
        return Ok(Work::Immediate(
            message.method_return().append1(contract::INTROSPECTION),
        ));
    }
    if (interface.as_str(), member.as_str()) == ("org.freedesktop.DBus.Peer", "Ping") {
        arguments::<()>(message)?;
        return Ok(Work::Immediate(message.method_return()));
    }
    if interface != contract::INTERFACE_NAME {
        return Err((ErrorKind::InvalidArgument, "unknown interface".into()));
    }
    if requires_root(&member) && uid != Some(0) {
        return Err((
            ErrorKind::AccessDenied,
            "authenticated root is required".into(),
        ));
    }
    match member.as_str() {
        "CreateContext" => {
            let (name,): (String,) = arguments(message)?;
            let name = SeatName::parse(name)
                .map_err(|error| (ErrorKind::InvalidArgument, error.to_string()))?;
            let port = seats
                .get(&name)
                .ok_or_else(|| (ErrorKind::UnknownSeat, "seat is not ready".into()))?;
            let publication = registry.begin_context(&name).map_err(registry_error)?;
            let (sender, receiver) = oneshot::channel();
            port.send(Command::Register {
                context: publication.context(),
                lifetime: publication.registration(),
                reply: sender,
            })
            .map_err(|kind| (kind, "seat admission failed".into()))?;
            let message = request_copy(message)?;
            Ok(Work::Deferred(Box::pin(async move {
                match timeout(Duration::from_secs(10), receiver).await {
                    Ok(Ok(Ok(()))) => {
                        let result = publication.publish(|id, fd| {
                            // SAFETY: ownership is transferred exactly once.
                            let fd = unsafe { dbus::arg::OwnedFd::from_raw_fd(fd.into_raw_fd()) };
                            replies.send(message.method_return().append2(fd, id.to_string()))
                        });
                        if result.is_err() {
                            let _ = replies.send(error_reply(
                                &message,
                                ErrorKind::CleanupPending,
                                "creation response could not be published",
                            ));
                        }
                    }
                    Ok(Ok(Err(kind))) => {
                        let _ = replies.send(error_reply(
                            &message,
                            kind,
                            "context registration failed",
                        ));
                    }
                    _ => {
                        let _ = replies.send(error_reply(
                            &message,
                            ErrorKind::CleanupPending,
                            "context registration did not complete",
                        ));
                    }
                }
            })))
        }
        "ActivateContext"
        | "DeactivateContext"
        | "ActivateContextById"
        | "DeactivateContextById" => {
            let id = context_argument(message, registry, member.ends_with("ById"))?;
            let name = registry
                .context_seat(id)
                .ok_or_else(|| (ErrorKind::UnknownContext, "unknown context".into()))?;
            let port = seats
                .get(name)
                .ok_or_else(|| (ErrorKind::ContextRemoving, "seat is retiring".into()))?;
            let (sender, receiver) = oneshot::channel();
            let command = if member.starts_with("Activate") {
                Command::Activate {
                    context: id,
                    reply: sender,
                }
            } else {
                Command::Deactivate {
                    context: id,
                    reply: sender,
                }
            };
            port.send(command)
                .map_err(|kind| (kind, "seat admission failed".into()))?;
            Ok(Work::Deferred(wait_reply(
                request_copy(message)?,
                receiver,
                replies,
                ErrorKind::TransitionPending,
            )))
        }
        "GrantAccess" | "RevokeAccess" => {
            let (fd, uid): (dbus::arg::OwnedFd, u32) = arguments(message)?;
            let fd = owned(fd);
            let context = registry
                .resolve(std::os::fd::AsFd::as_fd(&fd))
                .map_err(authority_error)?;
            let name = registry.context_seat(context).expect("verified route");
            let port = seats
                .get(name)
                .ok_or_else(|| (ErrorKind::ContextRemoving, "seat is retiring".into()))?;
            let (reply, receiver) = oneshot::channel();
            port.send(Command::Grant {
                context,
                uid,
                grant: member == "GrantAccess",
                reply,
            })
            .map_err(|kind| (kind, "seat admission failed".into()))?;
            Ok(Work::Deferred(wait_reply(
                request_copy(message)?,
                receiver,
                replies,
                ErrorKind::CleanupPending,
            )))
        }
        "GetSeatMetadata" => {
            let id = context_argument(message, registry, false)?;
            let name = registry.context_seat(id).expect("verified route");
            let port = seats
                .get(name)
                .ok_or_else(|| (ErrorKind::ContextRemoving, "seat is retiring".into()))?;
            let status = port.status.borrow();
            Ok(Work::Immediate(
                message
                    .method_return()
                    .append2(status.seat.0.clone(), status.seat.1),
            ))
        }
        "CreateConnection" => {
            let id = context_argument(message, registry, false)?;
            let name = registry.context_seat(id).expect("verified route");
            let port = seats
                .get(name)
                .ok_or_else(|| (ErrorKind::ContextRemoving, "seat is retiring".into()))?;
            let (sender, receiver) = oneshot::channel();
            port.send(Command::CreateConnection {
                context: id,
                reply: sender,
            })
            .map_err(|kind| (kind, "seat admission failed".into()))?;
            let message = request_copy(message)?;
            Ok(Work::Deferred(Box::pin(async move {
                match timeout(Duration::from_secs(10), receiver).await {
                    Ok(Ok(Ok(publication))) => {
                        let result = publication.publish(|id, fd| {
                            // SAFETY: ownership is transferred once to libdbus.
                            let fd = unsafe { dbus::arg::OwnedFd::from_raw_fd(fd.into_raw_fd()) };
                            replies.send(message.method_return().append2(fd, id.to_string()))
                        });
                        if result.is_err() {
                            let _ = replies.send(error_reply(
                                &message,
                                ErrorKind::CleanupPending,
                                "connection publication failed",
                            ));
                        }
                    }
                    Ok(Ok(Err(kind))) => {
                        let _ = replies.send(error_reply(
                            &message,
                            kind,
                            "connection registration failed",
                        ));
                    }
                    _ => {
                        let _ = replies.send(error_reply(
                            &message,
                            ErrorKind::CleanupPending,
                            "connection registration pending",
                        ));
                    }
                }
            })))
        }
        "RemoveConnection" | "RemoveConnectionById" => {
            let (context, connection) = if member.ends_with("ById") {
                let (text,): (String,) = arguments(message)?;
                let connection = text
                    .parse::<ConnectionId>()
                    .map_err(|error| (ErrorKind::InvalidArgument, error.to_string()))?;
                let parent = seats.values().find_map(|port| {
                    port.status
                        .borrow()
                        .connections
                        .get(&connection)
                        .map(|row| row.1.parse::<ContextId>().expect("typed context ID"))
                });
                let Some(parent) = parent else {
                    return Ok(Work::Immediate(message.method_return()));
                };
                (parent, connection)
            } else {
                let (fd, text): (dbus::arg::OwnedFd, String) = arguments(message)?;
                let fd = owned(fd);
                let context = registry
                    .resolve(std::os::fd::AsFd::as_fd(&fd))
                    .map_err(authority_error)?;
                let connection = text
                    .parse::<ConnectionId>()
                    .map_err(|error| (ErrorKind::InvalidArgument, error.to_string()))?;
                (context, connection)
            };
            let name = registry
                .context_seat(context)
                .ok_or_else(|| (ErrorKind::UnknownConnection, "unknown connection".into()))?;
            let port = seats
                .get(name)
                .ok_or_else(|| (ErrorKind::UnknownConnection, "unknown connection".into()))?;
            let (sender, receiver) = oneshot::channel();
            port.send(Command::RemoveConnection {
                context,
                connection,
                reply: sender,
            })
            .map_err(|kind| (kind, "seat admission failed".into()))?;
            Ok(Work::Deferred(wait_reply(
                request_copy(message)?,
                receiver,
                replies,
                ErrorKind::CleanupPending,
            )))
        }
        "RemoveContext" | "RemoveContextById" => {
            let id = if member == "RemoveContext" {
                let (fd,): (dbus::arg::OwnedFd,) = arguments(message)?;
                let fd = owned(fd);
                registry
                    .resolve_removal(std::os::fd::AsFd::as_fd(&fd))
                    .map_err(authority_error)?
            } else {
                let (id,): (String,) = arguments(message)?;
                id.parse::<ContextId>()
                    .map_err(|error| (ErrorKind::InvalidArgument, error.to_string()))?
            };
            registry.remove(id);
            // No resources are attached by registration itself. The caller's
            // completion is handled by the controller-removal barrier below.
            let Some(name) = registry.context_seat(id) else {
                return Ok(Work::Immediate(message.method_return()));
            };
            let port = seats
                .get(name)
                .ok_or_else(|| (ErrorKind::CleanupPending, "seat is retiring".into()))?;
            let (sender, receiver) = oneshot::channel();
            port.send(Command::Remove {
                context: id,
                reply: sender,
            })
            .map_err(|kind| (kind, "removal remains pending".into()))?;
            let message = request_copy(message)?;
            Ok(Work::Deferred(Box::pin(async move {
                let reply = match timeout(Duration::from_secs(10), receiver).await {
                    Ok(Ok(Ok(()))) => message.method_return(),
                    _ => error_reply(
                        &message,
                        ErrorKind::CleanupPending,
                        "removal remains pending",
                    ),
                };
                let _ = replies.send(reply);
            })))
        }
        "GetContext" => {
            let (fd,): (dbus::arg::OwnedFd,) = arguments(message)?;
            let fd = owned(fd);
            let id = registry
                .resolve(std::os::fd::AsFd::as_fd(&fd))
                .map_err(authority_error)?;
            let name = registry.context_seat(id).expect("verified route");
            let port = seats
                .get(name)
                .ok_or_else(|| (ErrorKind::ContextRemoving, "seat is retiring".into()))?;
            let row = port
                .status
                .borrow()
                .contexts
                .get(&id)
                .cloned()
                .ok_or_else(|| {
                    (
                        ErrorKind::ContextRemoving,
                        "context is not available".into(),
                    )
                })?;
            Ok(Work::Immediate(message.method_return().append1(row)))
        }
        "ListSeats" => {
            arguments::<()>(message)?;
            let rows: Vec<_> = seats
                .values()
                .map(|port| port.status.borrow().seat.clone())
                .collect();
            Ok(Work::Immediate(message.method_return().append1(rows)))
        }
        "ListContexts" => {
            arguments::<()>(message)?;
            let rows: Vec<_> = seats
                .values()
                .flat_map(|port| {
                    port.status
                        .borrow()
                        .contexts
                        .values()
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .collect();
            Ok(Work::Immediate(message.method_return().append1(rows)))
        }
        "ListConnections" => {
            arguments::<()>(message)?;
            let rows: Vec<_> = seats
                .values()
                .flat_map(|port| {
                    port.status
                        .borrow()
                        .connections
                        .values()
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .collect();
            Ok(Work::Immediate(message.method_return().append1(rows)))
        }
        _ => Err((ErrorKind::InvalidArgument, "unknown method".into())),
    }
}

fn context_argument(
    message: &Message,
    registry: &Registry,
    by_id: bool,
) -> Result<ContextId, Failure> {
    if by_id {
        let (text,): (String,) = arguments(message)?;
        text.parse().map_err(|error: libmultiseatd::InvalidId| {
            (ErrorKind::InvalidArgument, error.to_string())
        })
    } else {
        let (fd,): (dbus::arg::OwnedFd,) = arguments(message)?;
        let fd = owned(fd);
        registry
            .resolve(std::os::fd::AsFd::as_fd(&fd))
            .map_err(authority_error)
    }
}

fn wait_reply(
    message: Message,
    receiver: oneshot::Receiver<Result<(), ErrorKind>>,
    replies: Replies,
    pending: ErrorKind,
) -> Pending {
    Box::pin(async move {
        let reply = match timeout(Duration::from_secs(10), receiver).await {
            Ok(Ok(Ok(()))) => message.method_return(),
            Ok(Ok(Err(kind))) => error_reply(&message, kind, "seat operation did not complete"),
            _ => error_reply(
                &message,
                pending,
                "operation remains owned; query state before retrying",
            ),
        };
        let _ = replies.send(reply);
    })
}

fn request_copy(message: &Message) -> Result<Message, Failure> {
    let mut copy = message
        .duplicate()
        .map_err(|error| (ErrorKind::BackendFailure, error))?;
    // libdbus deliberately clears the serial on copy. Deferred replies must
    // retain the original request serial; zero would abort inside libdbus.
    copy.set_serial(
        message
            .get_serial()
            .ok_or_else(|| (ErrorKind::InvalidArgument, "request has no serial".into()))?,
    );
    Ok(copy)
}

fn owned(fd: dbus::arg::OwnedFd) -> OwnedFd {
    // SAFETY: move ownership out of the libdbus wrapper, exactly once.
    unsafe { OwnedFd::from_raw_fd(fd.into_raw_fd()) }
}

fn authority_error(error: AuthorityError) -> Failure {
    match error {
        AuthorityError::AccessDenied => {
            (ErrorKind::AccessDenied, "invalid context authority".into())
        }
        AuthorityError::LimitExceeded => (ErrorKind::LimitExceeded, error.to_string()),
        _ => (ErrorKind::BackendFailure, error.to_string()),
    }
}
fn registry_error(error: RegistryError) -> Failure {
    let kind = match error {
        RegistryError::UnknownSeat => ErrorKind::UnknownSeat,
        RegistryError::LimitExceeded => ErrorKind::LimitExceeded,
        RegistryError::CleanupPending => ErrorKind::CleanupPending,
        RegistryError::Authority(error) => return authority_error(error),
        _ => ErrorKind::BackendFailure,
    };
    (kind, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_request_copy_preserves_reply_serial() {
        let mut request = Message::new_method_call(
            contract::BUS_NAME,
            contract::OBJECT_PATH,
            contract::INTERFACE_NAME,
            "CreateContext",
        )
        .unwrap()
        .append1("seat-test");
        request.set_serial(42);
        let copied = request_copy(&request).unwrap();
        assert_eq!(copied.get_serial(), Some(42));
        assert_eq!(copied.method_return().get_reply_serial(), Some(42));
        assert_eq!(arguments::<(String,)>(&copied).unwrap().0, "seat-test");
    }
}
