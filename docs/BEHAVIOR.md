# Wire, kernel and launch behavior

The maintained C libseat ABI and seatd inherited `SEATD_FD` protocol remain the
client interface. There is no Rust libseat replacement. Reference:
https://github.com/shaitan-machine1/seatd.git at
`42fe3abfdcaefd2d5cbd21f9db803b9da6a2ca6c`.

## Ownership and admission

One parent-owned Seat has one State RwLock containing policy, DeviceCatalog and
AclRegistry. All writes exclude every reader through required effects/commit;
even catalog queries can wait behind slow ACL work. Serialization is not a
kernel transaction. Control, physical udev, broker and optional VT sources borrow
Seat directly. Parent-retained operations survive reply expiry/adapter failure.
No policy inbox, per-call spawning, Arc<Seat>, ACL actor or independent catalog
lock exists.

One helper derives the eligible foreground active context. Broker resources see
an opaque revocable permission, never context/VT/ACL policy. Open admission lasts
through cleanup/job registration; kernel work starts only after guard release.
Final FD publication holds State admission through actual transport flush and
checks the permission again immediately before send. Broker ACK/EOF/jobs and
withdrawal do not need State callbacks. A disable ACK can bypass a pending policy
admission without reordering ordinary requests. Non-acknowledging transports are
disconnected after two seconds, never re-enabled by late untagged ACKs.

Arrival/EOF never selects a context. Multiple connections in one context may be
enabled. Inactive membership succeeds without access. Connection cleanup retains
originals/jobs until actual revocation settles. Required revoke errors fail-stop;
there is no autonomous retry or persistent failed-context barrier.

## Devices, ACLs and assignments

Broker paths must be catalog-authorized canonical nodes. O_PATH pins retain the
original incarnation; opened type, device number, filesystem/inode and defensive
flags are checked. DRM primary uses retained master-owning resources; render nodes
use direct ACL access. Evdev opens are independent and permanently retired on
revoke. Unsupported hidraw revocation fails closed. Conclusive disappearance is
normal; other required failures retain originals and are fatal.

ACL reconciliation removes all unexpected named users/groups, preserves base
owner/group/other, and recalculates the mask. Removal-only passes never add or
expand access, including on fresh unremembered live nodes. Broker-only nodes have
empty named targets. Only actual successful application creates a managed row;
started/uncertain writes retain distinct original pins. Queued grants check opaque
access/target lifetime; started writes are joined and compensated if it expires.
Changing target epochs fences obsolete work. Fatal cleanup retains one bounded
original-pin clear batch with reserved blocking capacity, so independent pins
can be cleared while the original write is still stalled; its own incarnation
is cleared only after actual settlement. Results/jobs survive cleanup expiry.
No old path is reopened onto a replacement and no extra ACL history/recovery
journal exists.

Startup and explicit RemoveUnassignedDevices/AddAssignedDevices load assignments.
Physical ADD/REMOVE uses that loaded mapping; CHANGE is ignored. Fresh scans are
ordered with captured hints and old hints are revalidated. Offline persisted
ports remain known. Destination-first hotplug does not add admission before the
explicit addition phase. Every configured owner must certify removal before
any participant adds; owner loss/offline seats block additions. Assignments must
finish before destination startup: enumeration is not live movement.

## Native terminals

The optional linux-vt library claims the entire configured set until shutdown.
It owns terminal modes, signalfd/native signal ordering, ioctls and one native
thread, but no policy or executor. Cooperating services reserve disjoint sets;
there is no new claim lock. Do not reserve a recovery getty accidentally.

Release/current-acquisition notices are generic hints, not historical transition
IDs. Release withdraws applied access if any and always acknowledges native
release, including an empty/contextless VT. Acquisition revalidates current kernel
foreground after State write admission. Acquisition acknowledgement is a native
no-op: **never VT_ACKACQ**. Only release allow/deny uses VT_RELDISP. Obsolete EINVAL
is harmless only after validating current ownership/no pending release.

Native failure retains claims until explicit broker/ACL-before-terminal cleanup.
Startup claims have an owned readiness receipt. No Drop restoration can bypass
the withdrawal barrier; restoration and actual native joins are explicitly bounded.

## Security and acceptance limits

Launch workers detach, sanitize standard streams and close unlisted descriptors.
Only compositor lineages receive fresh seatd FDs. Authority never reaches ordinary
applications; neither do Linux controlling terminals/VT FDs. Safe PTYs are allowed.

Master drop is not general DRM/render revocation. ACL removal limits future opens,
not existing direct FDs; base permissions still apply. Same-UID contexts are not
isolated. Unfinished writes/removals may permit new direct opens. No app is killed
on udev removal/inactivity. SIGKILL, abort, persistent drivers or kernel stalls can
defeat cleanup. Tokens/EOF/timeouts are not proof of revocation. Fatal cleanup is
best effort and unresolved ownership is reported, never certified clean.

Unit tests cover framing/ancillary ownership, retained broker jobs/identities,
exact real temporary-file ACLs, cancellation/panic/adapter lifetimes, deadline
watchdog and synthetic VT policy. Root private-bus harnesses cover real SDK calls,
credentials, sibling/authority lifetimes, post-write faults and maintained C
libseat/with-seat execution. /dev/null and fake-VT fixtures do not establish
physical DRM/input/hidraw revocation, real native VT switching or authenticated
graphical-login acceptance; those require separately reviewed isolated deployment.
