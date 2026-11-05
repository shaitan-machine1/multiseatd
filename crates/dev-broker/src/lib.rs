//! Context-unaware broker mechanisms: defensive kernel device operations and
//! bounded seatd framing/descriptor transport. The caller supplies validated
//! device descriptions; this crate does not discover devices or classify udev
//! tags, select contexts, apply ACLs, or construct an executor.
pub mod device;
pub mod inventory;
pub mod permit;
pub mod resources;
pub mod seatd;
