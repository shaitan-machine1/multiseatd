# Wire, kernel and launch behavior

The daemon implements the maintained C libseat seatd wire protocol and inherited
`SEATD_FD` interface. The C client remains authoritative for its client ABI; this
repository does not provide a Rust libseat replacement. The C reference source is
https://github.com/shaitan-machine1/seatd.git at
`7813c08e35cbff69069dbdecda97f7c7ff506cc2`.

## Deliberate differences

* Context selection is explicit, independent of transport arrival, EOF and
  protocol membership. Multiple connections in one context can be enabled.
* Inactive membership succeeds without enabling or granting device access.
* A shared two-second disable deadline disconnects every non-acknowledging
  transport. It is never re-enabled: untagged wire ACKs cannot identify cycles.
* Seat0 has one explicitly configured, seat-owned graphical VT. Context opens
  do not sample/bind the foreground VT. Non-VT seats allocate no terminals.
* Managed graphical lineages receive no Linux controlling terminal or VT FD.
  Trusted launch workers detach/sanitize standard streams; with-seat closes full
  authority and unlisted descriptors before compositor exec. PTYs are allowed.
* Protocol switching requires an enabled, unfenced effective connection. Switch
  acceptance does not prove acquisition. External/kernel switches remain possible.
* Broker paths must name a published canonical node. Type, device number and
  filesystem/inode are checked after open. Caller-controlled filesystem walks
  are not a device-authorization mechanism.

These replace v1 connection takeover, per-connection UID leases and terminal
binding; no v1 adapter or old bus name is retained.

## Preserved safety and limits

Revocations, old UID clears and started mutations settle before successor access
or kernel release. Actual kernel identities serialize conflicts; generation tags
are additional checks, not side-effect cancellation. Failed revocations retain
originals/conflict fences and retry autonomously. Caller timeout only ends its
wait. Source cleanup precedes destination grants, including reclassification.

DRM primary nodes are brokered, with one master-owning description per card;
render nodes are ordinary direct access. Input descriptions are independent and
permanently retired on revoke. Unsupported hidraw revoke fails closed. ENODEV
means the kernel device is already gone; other revoke errors retain cleanup.

Master drop is not general DRM/render revocation. UID ACL removal controls future
opens, not existing direct FDs; base permissions still apply. Same-UID contexts
are not mutually isolated. No process suspension/termination follows inactivity
or context removal. SIGKILL, abort, lost kernel ownership and persistent driver
failure can defeat cleanup. EOF alone is not proof of revocation.

VT operations/signals stay on one native task. It retains ownership across a
caught failure until outer device/ACL cleanup; normal restoration and actual joins
are explicit. Final failure cleanup is best effort, never certified as success.

## Regression migration

Correct framing, malformed/fragmented traffic, ancillary truncation/ownership and
terminal EOF tests were moved from the former server crate to `seatd/` in the
daemon. Kernel device routines/tests were retained and extended with inode checks
and required primary master acquisition. ACL owner/group/mask tests remain.

The old server/coordinator policy tests have been replaced, not silently retained
as v2 guarantees:

| Contract | Current coverage |
| --- | --- |
| capability identity/lifetime/publication | `authority` and `registry` tests; private-bus harness |
| no takeover, inactive/parallel membership, close/reopen | `seat::tests`; real C libseat fixture |
| disable timeout/disconnect, delayed ACKs and late enable failure | controller tests |
| retained failed revoke, late open, master conflicts, unwind | `resources` and broker tests |
| desired grants, compensation/no resurrection, idle/active reconciliation | grant/controller ACL tests |
| source-first movement and replacement identities | topology/paused-worker controller tests |
| seat VT, kernel barriers, away selection, native failure/joins | fake native/controller VT tests |
| detached exec, stdio/PTYs, inherited FD allowlist | `tests/launch-hygiene.sh` |

Old newcomer takeover and foreground-at-open expectations were intentionally
removed. Synthetic /dev/null and fake-kernel tests do not establish physical
DRM/input/hidraw or graphical-login acceptance.
