# multiseatd

Capability-authorized seat contexts, independent C libseat/seatd connections and
explicit UID access grants. Installable pieces are `multiseatd`, `seat-udev`,
`lib-multiseatd` (Rust library `libmultiseatd`) and the `seat-launch` exec wrapper.

The incompatible v2 API replaces the former client-lease interface. No old bus
name, compatibility adapter or separate server daemon remains. Seat-launch is
the fresh-connection exec wrapper, not the retired per-client launcher API.
See [API](docs/API.md) and [behavior/security limits](docs/BEHAVIOR.md).

The per-seat rewrite is in progress: the CLI/API below still describe the global
v2 implementation. The five-crate workspace now includes context-unaware
`dev-broker` kernel/framing/descriptor primitives, retained broker resources and
the authoritative authorization inventory, separate from daemon-owned ACLs.
Connection/membership ownership and the per-seat control-plane migration are
not yet complete.

## Operation

Multiseatd must run as root. Configure seat0's single graphical terminal explicitly:

```sh
multiseatd --graphical-vt 7
```

Coordinate the terminal with gettys/display managers first. The configured VT,
`/dev/tty0` and `/dev/console` must be root-owned without group/other access; the
daemon rejects conflicting ownership. It does not chmod nodes or seize terminals.
`--non-vt-only` explicitly leaves seat0 unmanaged and conflicts with graphical VT
configuration. Other seats do not use Linux VTs. The persistent singleton inode
is `/run/multiseatd.lock` and is never unlinked by the daemon.

Topology is monitored continuously. Context creation is root-only; possession of
a returned Unix FD authorizes full control of that one context. Contexts begin
inactive, and transport arrival/EOF never selects a context. UID grants are
explicit context registrations, not inferred from process/session/connection UID.

Trusted graphical launch code drops credentials/PAM and detaches/sanitizes its
lineage. At the final compositor exec boundary it delegates authority explicitly:

```sh
MULTISEATD_AUTHORITY_FD=3 /usr/libexec/multiseatd/seat-launch /usr/bin/weston
```

FD 3 must really be inherited from an authorized controller; the number/environment
is not authentication. Seat-launch obtains a fresh connection, sets seat/VT metadata
from the daemon, closes authority/unlisted FDs and execs. It does not activate,
perform PAM, change credentials or create a session supervisor. Ordinary programs
receive only the intended seatd endpoint, not full authority or a Linux VT.
Never pass authority through untrusted scripts or environment-controlled loaders.

## Build and test

Requires Rust 1.88+, libudev, libdbus and libacl development files.

```sh
cargo build --workspace
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
tests/launch-hygiene.sh
tests/root-context-control.sh
tests/context-libseat.sh
```

Run build harnesses as a normal user. Root harnesses require passwordless sudo,
create a private bus/disposable fixtures, and return 77 for missing prerequisites.
They never change host PAM/services/udev/VTs or production device ACLs. The C
harness fetches the exact maintained libseat revision recorded in
`tests/libseat-source.sh`; `LIBSEAT_REPO` supplies an explicit alternative checkout.
There is no implicit checkout-layout dependency.

`test-support` only enables explicit synthetic fixtures; /dev/null is not evidence
of real driver revocation. Fake VT and exec fixtures are not authenticated graphical
login or physical-hardware acceptance. The session/client libraries and wrapper
remain synchronous and executor-free; Tokio is confined to the daemon.
