# Context API v2

Service `org.decoupling.multiseatd2`, object `/org/decoupling/multiseatd2`, interface
`org.decoupling.multiseatd2.Manager`. The canonical introspection XML is
[`crates/lib-multiseatd/dbus/org.decoupling.multiseatd2.Manager.xml`](../crates/lib-multiseatd/dbus/org.decoupling.multiseatd2.Manager.xml).

## Authority and lifetime

Root creates a context for a ready seat and receives `(authority FD, ContextId)`.
The FD is a transferable capability, not a protocol socket. Its registered Linux
SO_COOKIE identity survives dup/fork/SCM_RIGHTS. The opposite endpoint is retained
for lifetime observation; unrelated sockets, wrong endpoints and previous-daemon
capabilities fail. IDs/UIDs/FD numbers and SO_PEERCRED are not authority.

Final endpoint close, shutdown or unexpected data irreversibly removes the context.
Explicit removal invalidates all copies before cleanup. Bus-owner loss alone does
not remove it. In-flight descriptor copies can extend lifetime; leaked copies can
be overridden by root ID removal. Bounded tombstones authorize removal retries only.
Restart invalidates every capability, ID and connection.

A holder has full context control, including arbitrary UID registrations and
activation while inactive. This does not authorize another context or arbitrary
paths. Trusted controllers may deliberately delegate authority; ordinary compositor
and greeter application lineages must not retain it.

## Methods

Root only:

* `CreateContext(s seat) -> (h authority, s context_id)`; no options/VT argument.
* `ActivateContextById(s)`, `DeactivateContextById(s)`, `RemoveContextById(s)`.
* `RemoveConnectionById(s)`.
* `ListSeats() -> a(subssss)`.
* `ListContexts() -> a(sssauasbbs)`.
* `ListConnections() -> a(sssss)`.

Full authority:

* `ActivateContext(h)`, `DeactivateContext(h)`, `RemoveContext(h)`.
* `GrantAccess(h, u uid)`, `RevokeAccess(h, u uid)`.
* `CreateConnection(h) -> (h seatd, s connection_id)`.
* `RemoveConnection(h, s connection_id)` verifies parent membership.
* `GetContext(h) -> (sssauasbbs)`.
* `GetSeatMetadata(h) -> (s seat, u graphical_vt)` discloses no other context IDs.

Seat fields: name, VT (zero means non-VT), settled foreground, selected ID, effective
ID, transition phase, cleanup diagnostic. Context fields: ID, seat, phase, desired
UIDs, connection IDs, selected/effective flags, cleanup diagnostic. Connection fields:
ID, permanent parent context, seat, membership phase, cleanup diagnostic. Empty IDs
mean none. Desired permissions are not a claim about current effective access.

`StateChanged(t revision)` is a private root-visible hint, not authorization or a
transaction log. Subscribe then query; revisions are daemon-lifetime only. The
synchronous client's owner-specific subscription must be rebuilt after bus-owner
change. Notifications are coalesced/bounded and contain no inventory body.

Unknown/trailing/mistyped arguments are errors. IDs are canonical lowercase UUIDv4.
Invalid authority returns AccessDenied without disclosing its former context. A
foreign connection under a live authority returns UnknownConnection. Unknown valid
root removal IDs succeed. There is no creator UID, login-session ID or leader PID
fallback.

## Completion and errors

Errors use `org.decoupling.multiseatd2.Error.` with InvalidArgument, AccessDenied,
UnknownSeat, UnknownContext, UnknownConnection, ContextRemoving, ResourceConflict,
LimitExceeded, TransitionPending, CleanupPending or BackendFailure.

A successful transition confirms its resource and delivery barriers, not queued
intent. A ten-second server response-wait budget does not cancel admitted work;
query state after timeout/pending errors. Two-second disable deadlines are separate.
Revocation removes desired permission before cleanup. Failed active addition removes
its new desired UID and compensates uncertain writes; it is not silently retried as
a desired grant. Removal/cleanup is irreversible and may remain pending on driver
failure. No context operation terminates application processes.

## Client and launch usage

`libmultiseatd::Client` uses dbus::blocking directly. Authority arguments are borrowed;
owned CLOEXEC duplicates are sent. Returned descriptors are owned, CLOEXEC and at
least FD 3. There are no async features, executors, adapters or hidden worker threads.

```rust,no_run
use libmultiseatd::Client;
use std::{os::fd::AsFd, time::Duration};
let client = Client::system(Duration::from_secs(11))?;
let context = client.create_context("seat0")?; // root
client.grant_access(context.as_fd(), 1000)?;
client.activate_context(context.as_fd())?;
let connection = client.create_connection(context.as_fd())?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

A trusted, already credential-dropped/detached worker execs with-seat using an
explicit inherited `MULTISEATD_AUTHORITY_FD` (or `--authority-fd`). Safe standard
streams/PTYs are permitted; Linux VT/control-terminal inheritance is rejected.
Only the new seatd FD survives ordinary-app exec. Exec failure closes that connection,
not its context, siblings or registrations. Do not delegate authority through
untrusted loader environment, shell startup hooks or unrelated helpers.

Internal admission bounds: 256 ready seats/retained contexts globally, 64 contexts
per seat, 64 connections/context and 4096 globally, 64 UID registrations/context,
128 open records/connection and 4096 authority retry tombstones. Pending/removing
objects count until actual cleanup; all control/output/resource queues are bounded.
See [behavior](BEHAVIOR.md) for kernel and same-UID isolation limits.
