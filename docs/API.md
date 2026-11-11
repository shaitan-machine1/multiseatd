# Per-seat API

Bus name: `org.SGLogin.Multiseatd1.Seat_<encoded-seat>`.
Object: `/org/SGLogin/Multiseatd1`.
Interface: `org.SGLogin.Multiseatd1.Manager`.
[Canonical XML](../crates/lib-multiseatd/dbus/org.SGLogin.Multiseatd1.Manager.xml).

Seat names begin `seat`, contain only ASCII alphanumerics, underscore or hyphen,
and are at most 63 bytes. Bare `seat` is valid. Encode every non-alphanumeric byte
as `_xx` with lowercase hexadecimal: `seat-a_b` becomes `seat_2da_5fb`.

Both builds expose exactly these methods:

| Method | Input | Output | Authority |
| --- | --- | --- | --- |
| CreateContext | `u vt` | `h authority, s id` | root |
| ActivateContext | `s id` | — | root |
| DeactivateContext | `s id` | — | root |
| RemoveContext | `h authority` | — | capability |
| AddAclGrant | `h authority, u uid` | — | capability |
| RemoveAclGrant | `h authority, u uid` | — | capability |
| CreateConnection | `h authority` | `h endpoint, u handle` | capability |
| GetContext | `h authority` | `(suauaubbb)` | capability |
| GetSeatMetadata | `h authority` | `s seat, u vt` | capability |
| RemoveContextById | `s id` | — | root |
| ListContexts | — | `a(suauaubbb)` | root |
| MoveToForeground | `s id` | — | root |
| RemoveUnassignedDevices | — | — | root |
| AddAssignedDevices | — | — | root |

IDs are canonical lowercase RFC4122 UUIDv7, not credentials/session IDs. The
seven record fields are `id`, `vt`, sorted unique desired UIDs, sorted unique
connection handles, `active`, `foreground`, `effective`. No cleanup/phase/diagnostic
fields exist. Immutable VT must be in the startup set; non-VT creation accepts
only zero. Foreground is false at VT zero. Background active contexts retain
intent but have no applied access. Effective implies active.

Only root selects/clears active associations. Occupied activation, including
same-ID activation, is Busy before effects. Deactivation retains its association
until withdrawal succeeds. MoveToForeground requests/observes kernel switching
without holding State while waiting; it does not activate. Non-VT returns
InvalidArgument, not a no-op or absent method. Authority-backed removal is
idempotent through bounded removal-only tombstones; those cannot authorize grants,
queries or connections after invalidation.

An authority is the exact root-peer Unix stream endpoint registered for a
context. Duplicates keep it alive until final close; write shutdown or unexpected
data invalidates it. No endpoint held by the daemon keeps its peer alive. A
connection is a separate inherited C libseat stream, not authority. Closing one
connection never removes/deactivates its context or closes a sibling. The SDK's
local `remove_connection(BorrowedFd)` calls shutdown without closing the borrowed
FD; ordinary duplicate drop does not shut down the endpoint.

`StateChanged(t revision)` is a root-only invalidation hint; query current state.
Clients pin a root-owned unique bus owner, disable autostart, and reject owner
replacement. The synchronous SDK has explicit seat routing, borrowed/owned FD
APIs and manually driven signal subscriptions, without background threads.

## Assignment refresh

The SDK accepts an explicit nonempty unique list of at most 256 seats; it neither
reads configuration nor discovers participants. Pin owners and attempt removal on
all reachable participants. An absent seat, removal failure or changed owner
blocks **all additions**. Only after every removal succeeds and owners are
rechecked may additions start. Preserve per-seat remote errors, including fatal
categories; do not retry automatically. Retire/recover an old owner before
omitting it from configuration. Startup is not a live move.

## Errors and deadlines

Prefix `org.SGLogin.Multiseatd1.Error.`:
`InvalidArgument`, `NotAuthorized`, `NotFound`, `NotReady`, `Busy`,
`LimitExceeded`, `Pending`, `Stopping`, `DeviceRemovalFailed`,
`DeviceAdditionFailed`, `VTActivationFailed`, `CriticalFailure`.

Default SDK call budget is 10 seconds. Server receipt/reply budget is 8 seconds;
required effects share a cumulative maximum 6 seconds, shortened by admission
waits to preserve 1 second reply headroom. An operation needs at least 100ms
remaining effect window before starting. Kernel disable ACK deadline is 2 seconds.
Critical reply flush is bounded at 500ms, before best-effort cleanup (5 seconds).
An independent native watchdog fences stalled-runtime effects and bounds exit.

Ordinary rejection precedes irreversible work. Unexpected required effect failure,
including timeout/panic, fences before unlock, attempts CriticalFailure and exits
nonzero after bounded cleanup. No rollback or completed revocation is claimed.
Reply expiry/disconnect does not cancel admitted parent-owned work; expired
unadmitted lock waits never mutate later. Pending is not successful teardown and
must never authorize a successor login.
