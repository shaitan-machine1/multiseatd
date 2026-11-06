use super::*;
use crate::connection::channel;

fn packet(opcode: u16, payload: &[u8]) -> wire::Packet {
    wire::Packet {
        opcode,
        payload: payload.to_vec(),
    }
}

#[test]
fn membership_starts_disabled_without_selecting_or_granting_anything() {
    let mut connections = Connections::new(2);
    let (port, _output, _closed) = channel();
    connections.add(7, port);
    assert_eq!(connections[&7].membership, Membership::Connected);
    assert!(connections.valid_packet(7, &packet(wire::CLIENT_OPEN_SEAT, &[])));
    assert!(!connections.valid_packet(7, &packet(wire::CLIENT_CLOSE_SEAT, &[])));
    assert!(!connections.valid_packet(7, &packet(wire::CLIENT_PING, &[0])));
    assert!(connections.open_seat(7));
    assert_eq!(connections[&7].membership, Membership::Disabled);
    assert!(connections[&7].epoch.is_none());
    assert!(!connections.enable(7, None).unwrap());
    assert!(!connections.valid_packet(7, &packet(wire::CLIENT_OPEN_SEAT, &[])));
}

#[test]
fn pending_disable_and_permanent_close_cannot_be_reenabled_by_a_late_ack() {
    let mut connections = Connections::new(2);
    let (port, mut output, _closed) = channel();
    let close = connections.add(7, port);
    assert!(connections.open_seat(7));
    assert!(connections.enable(7, Some(&Permit::new())).unwrap());
    let tag = output.try_recv().unwrap().tag.unwrap();
    assert!(!connections.delivered(7, tag + 1));
    assert!(connections.delivered(7, tag));
    let old_epoch = connections[&7].epoch.clone().unwrap();
    assert!(connections.pause(7));
    assert!(!old_epoch.is_open());
    assert_eq!(connections[&7].membership, Membership::PendingDisable);
    assert!(connections.prepare(7, &Permit::new()).is_none());
    assert!(!connections.enable(7, Some(&Permit::new())).unwrap());
    connections.acknowledge(7);
    assert_eq!(connections[&7].membership, Membership::Disabled);
    assert!(connections.enable(7, Some(&Permit::new())).unwrap());
    assert!(connections.pause(7));
    connections.close(7); // caller's shared deadline expired
    connections.acknowledge(7);
    assert!(close.is_closed());
    assert_eq!(connections[&7].membership, Membership::PendingDisable);
    assert!(!connections.enable(7, Some(&Permit::new())).unwrap());
    assert!(!connections.valid_packet(7, &packet(wire::CLIENT_PING, &[])));
}

#[test]
fn protocol_reopen_waits_for_retained_cleanup_and_reports_close_exactly_once() {
    let mut connections = Connections::new(1);
    let (port, mut output, _closed) = channel();
    connections.add(7, port);
    connections.open_seat(7);
    let (done, mut receiver) = oneshot::channel();
    connections.close_seat(7, done);
    connections.cleanup_started(7);
    assert!(!connections.open_seat(7));
    assert!(!connections.cleanup_completed(7, Some("injected refusal".into())));
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(connections[&7].error, "injected refusal");
    assert!(connections.remove(7).is_err());
    connections.cleanup_started(7);
    assert!(connections.cleanup_completed(7, None));
    assert!(receiver.try_recv().is_ok());
    assert_eq!(
        output.try_recv().unwrap().bytes,
        wire::empty(wire::SERVER_SEAT_CLOSED)
    );
    assert!(output.try_recv().is_err());
    assert!(connections.open_seat(7));
    assert_eq!(connections[&7].membership, Membership::Disabled);
    assert!(connections[&7].epoch.is_none());
}

#[test]
fn disconnect_keeps_cleanup_owned_until_explicit_success() {
    let mut connections = Connections::new(1);
    let (port, _output, _closed) = channel();
    connections.add(7, port);
    connections.gone(7);
    assert!(connections[&7].cleanup);
    assert!(!connections[&7].live());
    assert!(connections.remove(7).is_err());
    connections.cleanup_started(7);
    assert!(!connections.cleanup_completed(7, Some("retry me".into())));
    assert!(connections.remove(7).is_err());
    connections.cleanup_started(7);
    assert!(connections.cleanup_completed(7, None));
    connections.remove(7).unwrap();
    assert!(connections.get(&7).is_none());
}
