//! Control-plane routing specialization of the context-unaware broker driver.
//! The legacy identifier specialization disappears with the coordinated v2 API
//! migration; transport code itself has no SDK or context dependency.
pub use dev_broker::connection::{Close, Output, Port, channel, run};
pub type Request = dev_broker::connection::Request<libmultiseatd::ConnectionId>;
pub type Event = dev_broker::connection::Event<libmultiseatd::ConnectionId>;
