//! Exact common wire contract; policy and locking stay inside Seat.
use super::reactor::{Request, error_reply, requires_root};
use crate::{
    fatal::{Budget, Error, Result},
    seat::Seat,
};
use dbus::{
    Message,
    arg::{ArgType, ReadAll},
};
use libmultiseatd::{ContextId, ErrorKind, contract};
use std::os::fd::{AsFd, FromRawFd, IntoRawFd, OwnedFd};

fn arguments<T: ReadAll>(message: &Message) -> Result<T> {
    let mut iter = message.iter_init();
    let result = T::read(&mut iter).map_err(|error| Error::invalid(error.to_string()))?;
    if iter.arg_type() != ArgType::Invalid {
        return Err(Error::invalid("trailing arguments"));
    }
    Ok(result)
}
fn id(message: &Message) -> Result<ContextId> {
    let (text,): (String,) = arguments(message)?;
    text.parse()
        .map_err(|error: libmultiseatd::InvalidId| Error::invalid(error.to_string()))
}
fn fd(descriptor: dbus::arg::OwnedFd) -> OwnedFd {
    unsafe { OwnedFd::from_raw_fd(descriptor.into_raw_fd()) }
}
fn wire_fd(descriptor: OwnedFd) -> dbus::arg::OwnedFd {
    unsafe { dbus::arg::OwnedFd::from_raw_fd(descriptor.into_raw_fd()) }
}

pub async fn dispatch(request: &Request, seat: &Seat) -> Result<Message> {
    let message = &request.message;
    let budget = Budget {
        reply: request.received + crate::fatal::SERVER_WAIT,
    };
    if message.path().as_deref() != Some(contract::OBJECT_PATH) {
        return Err(Error::invalid("unknown object"));
    }
    let member = message
        .member()
        .map(|member| member.to_string())
        .unwrap_or_default();
    let interface = message
        .interface()
        .map(|interface| interface.to_string())
        .unwrap_or_default();
    if (interface.as_str(), member.as_str())
        == ("org.freedesktop.DBus.Introspectable", "Introspect")
    {
        arguments::<()>(message)?;
        return Ok(message.method_return().append1(contract::INTROSPECTION));
    }
    if (interface.as_str(), member.as_str()) == ("org.freedesktop.DBus.Peer", "Ping") {
        arguments::<()>(message)?;
        return Ok(message.method_return());
    }
    if interface != contract::INTERFACE_NAME {
        return Err(Error::invalid("unknown interface"));
    }
    if requires_root(&member) && request.uid != Some(0) {
        return Err(Error::new(
            ErrorKind::NotAuthorized,
            "authenticated root is required",
        ));
    }
    match member.as_str() {
        "CreateContext" => {
            let (vt,): (u32,) = arguments(message)?;
            let master = request.master.clone().ok_or_else(|| {
                Error::new(
                    ErrorKind::NotAuthorized,
                    "authenticated ProcessFD is required",
                )
            })?;
            let (authority, id) = seat.create_context_for_master(vt, master, budget).await?;
            Ok(message
                .method_return()
                .append2(wire_fd(authority), id.to_string()))
        }
        "ActivateContext" => {
            seat.activate_context(id(message)?, budget).await?;
            Ok(message.method_return())
        }
        "DeactivateContext" => {
            seat.deactivate_context(id(message)?, budget).await?;
            Ok(message.method_return())
        }
        "RemoveContextById" => {
            seat.remove_context_by_id(id(message)?, budget).await?;
            Ok(message.method_return())
        }
        "MoveToForeground" => {
            seat.move_to_foreground(id(message)?, budget).await?;
            Ok(message.method_return())
        }
        "RemoveContext" => {
            let (authority,): (dbus::arg::OwnedFd,) = arguments(message)?;
            seat.remove_context(fd(authority).as_fd(), budget).await?;
            Ok(message.method_return())
        }
        "AddAclGrant" | "RemoveAclGrant" => {
            let (authority, uid): (dbus::arg::OwnedFd, u32) = arguments(message)?;
            seat.set_grant(fd(authority).as_fd(), uid, member == "AddAclGrant", budget)
                .await?;
            Ok(message.method_return())
        }
        "CreateConnection" => {
            let (authority,): (dbus::arg::OwnedFd,) = arguments(message)?;
            let (connection, handle) = seat
                .create_connection(fd(authority).as_fd(), budget)
                .await?;
            Ok(message.method_return().append2(wire_fd(connection), handle))
        }
        "GetContext" => {
            let (authority,): (dbus::arg::OwnedFd,) = arguments(message)?;
            Ok(message
                .method_return()
                .append1(seat.get_context(fd(authority).as_fd(), budget).await?))
        }
        "GetSeatMetadata" => {
            let (authority,): (dbus::arg::OwnedFd,) = arguments(message)?;
            let (name, vt) = seat.seat_metadata(fd(authority).as_fd(), budget).await?;
            Ok(message.method_return().append2(name, vt))
        }
        "GetContextByMasterPid" => {
            let (pid, start): (u32, u64) = arguments(message)?;
            Ok(message
                .method_return()
                .append1(seat.get_context_by_master_pid(pid, start, budget).await?))
        }
        "ListContexts" => {
            arguments::<()>(message)?;
            Ok(message
                .method_return()
                .append1(seat.list_contexts(budget).await?))
        }
        "RemoveUnassignedDevices" | "AddAssignedDevices" => {
            arguments::<()>(message)?;
            seat.refresh_devices(member == "AddAssignedDevices", budget)
                .await?;
            Ok(message.method_return())
        }
        _ => Err(Error::invalid("unknown method")),
    }
}
pub fn failure(message: &Message, error: &Error) -> Message {
    error_reply(message, error.kind, &error.text)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn call() -> Message {
        Message::new_method_call(
            "org.SGLogin.Multiseatd1.Seat_seat0",
            contract::OBJECT_PATH,
            contract::INTERFACE_NAME,
            "CreateContext",
        )
        .unwrap()
    }
    #[test]
    fn exact_arguments_reject_wrong_type_and_trailing_data() {
        assert!(arguments::<(u32,)>(&call().append1(7u32)).is_ok());
        assert!(arguments::<(u32,)>(&call().append1("7")).is_err());
        assert!(arguments::<(u32,)>(&call().append2(7u32, 0u32)).is_err());
        assert!(arguments::<()>(&call().append1(0u32)).is_err());
    }
}
