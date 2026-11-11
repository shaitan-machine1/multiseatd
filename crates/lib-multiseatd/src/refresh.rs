use crate::{Client, ErrorKind, bus_name};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshStage {
    Configuration,
    Owner,
    Removal,
    Addition,
}
#[derive(Debug)]
pub struct SeatFailure {
    pub seat: String,
    pub stage: RefreshStage,
    pub error: dbus::Error,
}
#[derive(Debug)]
pub struct RefreshError {
    pub failures: Vec<SeatFailure>,
    pub addition_started: bool,
}
impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, failure) in self.failures.iter().enumerate() {
            if index != 0 {
                f.write_str("; ")?;
            }
            write!(f, "{} {:?}: {}", failure.seat, failure.stage, failure.error)?;
        }
        Ok(())
    }
}
impl std::error::Error for RefreshError {}

/// Explicit participants only. No discovery, bus autostart, retries or rollback.
pub fn refresh_devices(configured_seats: &[String]) -> Result<(), RefreshError> {
    refresh_with(configured_seats, Client::system)
}
/// Explicit caller-supplied per-seat RPC budget, without changing participants.
pub fn refresh_devices_with_timeout(
    configured_seats: &[String],
    timeout: std::time::Duration,
) -> Result<(), RefreshError> {
    refresh_with(configured_seats, |seat| {
        Client::system_with_timeout(seat, timeout)
    })
}
trait Participant {
    fn verify(&self) -> Result<(), dbus::Error>;
    fn remove(&self) -> Result<(), dbus::Error>;
    fn add(&self) -> Result<(), dbus::Error>;
}
impl Participant for Client {
    fn verify(&self) -> Result<(), dbus::Error> {
        self.verify_owner()
    }
    fn remove(&self) -> Result<(), dbus::Error> {
        self.remove_unassigned_devices()
    }
    fn add(&self) -> Result<(), dbus::Error> {
        self.add_assigned_devices()
    }
}
fn refresh_with<P: Participant>(
    seats: &[String],
    mut connect: impl FnMut(&str) -> Result<P, dbus::Error>,
) -> Result<(), RefreshError> {
    let mut names = BTreeSet::new();
    if seats.is_empty()
        || seats.len() > 256
        || seats
            .iter()
            .any(|s| bus_name(s).is_err() || !names.insert(s))
    {
        return Err(RefreshError {
            failures: vec![SeatFailure {
                seat: String::new(),
                stage: RefreshStage::Configuration,
                error: ErrorKind::InvalidArgument
                    .error("supply 1..256 unique valid configured seats"),
            }],
            addition_started: false,
        });
    }
    let mut failures = Vec::new();
    let mut participants = Vec::new();
    // Resolve and authenticate ALL owners before the first mutation.
    for seat in seats {
        match connect(seat) {
            Ok(client) => participants.push((seat, client)),
            Err(error) => failures.push(SeatFailure {
                seat: seat.clone(),
                stage: RefreshStage::Owner,
                error,
            }),
        }
    }
    // Attempt every reachable configured participant despite another failure.
    for (seat, participant) in &participants {
        if let Err(error) = participant.remove() {
            failures.push(SeatFailure {
                seat: (*seat).clone(),
                stage: RefreshStage::Removal,
                error,
            });
        }
    }
    if !failures.is_empty() {
        return Err(RefreshError {
            failures,
            addition_started: false,
        });
    }
    // A known owner change after removal also suppresses ALL additions.
    for (seat, participant) in &participants {
        if let Err(error) = participant.verify() {
            failures.push(SeatFailure {
                seat: (*seat).clone(),
                stage: RefreshStage::Owner,
                error,
            });
        }
    }
    if !failures.is_empty() {
        return Err(RefreshError {
            failures,
            addition_started: false,
        });
    }
    for (seat, participant) in &participants {
        if let Err(error) = participant.add() {
            failures.push(SeatFailure {
                seat: (*seat).clone(),
                stage: RefreshStage::Addition,
                error,
            });
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(RefreshError {
            failures,
            addition_started: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    struct Fake {
        seat: String,
        log: Rc<RefCell<Vec<String>>>,
        fail: Option<RefreshStage>,
    }
    impl Fake {
        fn action(&self, stage: RefreshStage) -> Result<(), dbus::Error> {
            self.log
                .borrow_mut()
                .push(format!("{}:{stage:?}", self.seat));
            if self.fail == Some(stage) {
                Err(ErrorKind::CriticalFailure.error("injected"))
            } else {
                Ok(())
            }
        }
    }
    impl Participant for Fake {
        fn verify(&self) -> Result<(), dbus::Error> {
            self.action(RefreshStage::Owner)
        }
        fn remove(&self) -> Result<(), dbus::Error> {
            self.action(RefreshStage::Removal)
        }
        fn add(&self) -> Result<(), dbus::Error> {
            self.action(RefreshStage::Addition)
        }
    }
    fn execute(
        absent: bool,
        failure: Option<RefreshStage>,
    ) -> (Result<(), RefreshError>, Vec<String>) {
        let log = Rc::new(RefCell::new(Vec::new()));
        let result = refresh_with(&["seat0".into(), "seat1".into()], |seat| {
            log.borrow_mut().push(format!("pin:{seat}"));
            if absent && seat == "seat0" {
                return Err(dbus::Error::new_failed("offline"));
            }
            Ok(Fake {
                seat: seat.into(),
                log: log.clone(),
                fail: if seat == "seat0" { failure } else { None },
            })
        });
        let messages = log.borrow().clone();
        (result, messages)
    }
    #[test]
    fn all_pins_and_removals_precede_any_addition() {
        let (result, log) = execute(false, None);
        result.unwrap();
        assert_eq!(
            log,
            [
                "pin:seat0",
                "pin:seat1",
                "seat0:Removal",
                "seat1:Removal",
                "seat0:Owner",
                "seat1:Owner",
                "seat0:Addition",
                "seat1:Addition"
            ]
        );
    }
    #[test]
    fn missing_removal_failure_and_owner_change_each_block_all_additions() {
        for (absent, stage) in [
            (true, None),
            (false, Some(RefreshStage::Removal)),
            (false, Some(RefreshStage::Owner)),
        ] {
            let (result, log) = execute(absent, stage);
            assert!(!result.unwrap_err().addition_started);
            assert!(log.iter().any(|s| s == "seat1:Removal"));
            assert!(!log.iter().any(|s| s.ends_with(":Addition")));
        }
    }
    #[test]
    fn addition_errors_preserve_critical_category_and_do_not_skip_remaining_seats() {
        let (result, log) = execute(false, Some(RefreshStage::Addition));
        let error = result.unwrap_err();
        assert!(error.addition_started);
        assert_eq!(
            error.failures[0].error.name(),
            Some(ErrorKind::CriticalFailure.name())
        );
        assert_eq!(log.last().unwrap(), "seat1:Addition");
    }
    #[test]
    fn invalid_configuration_never_connects_or_mutates() {
        for seats in [
            vec![],
            vec!["seat0".into(), "seat0".into()],
            vec!["bad".into()],
        ] {
            let result = refresh_with::<Fake>(&seats, |_| panic!("must validate first"));
            assert_eq!(
                result.unwrap_err().failures[0].stage,
                RefreshStage::Configuration
            );
        }
    }
}
