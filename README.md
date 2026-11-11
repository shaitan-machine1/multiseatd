# multiseatd

Per-seat context policy, native C libseat transports and explicit device ACL
access. Each independently configured daemon owns one seat. There is no global
controller, peer discovery, automatic takeover or compatibility API.

The seven crates are `multiseatd`, `lib-multiseatd` (Rust `libmultiseatd`),
`dev-broker`, `dev-acl`, `linux-vt`, `seat-udev` and `seat-wrapper`.
`seat-wrapper` builds `with-seat` and `without-seat`, installed under
`/usr/libexec/multiseatd/`.
[API](docs/API.md) · [behavior and limits](docs/BEHAVIOR.md).

## Operation

Run as root. Build non-VT and VT executables separately:

```sh
cargo build --release --workspace --target-dir target/no-vt
cargo build --release -p multiseatd --features vt --target-dir target/vt
# Install target/no-vt/release/multiseatd as /usr/bin/multiseatd,
# target/vt/release/multiseatd as /usr/bin/multiseatd-vt.
multiseatd --seat seat1
multiseatd-vt --seat seat0 --vts 7,8,9,10,11,12
```

Coordinate the complete reserved terminal set with gettys/other display managers
first; preserve a recovery terminal outside it. Nodes must already have safe
ownership/modes. The daemon never chmods nodes or seizes occupied terminals.
The non-VT executable has no VT options, signal ownership or linux-vt dependency.
Install `dist/dbus/org.SGLogin.Multiseatd1.conf` as system-bus policy. Per-seat
locks are retained through cleanup; locked inodes are never unlinked.

Finish assignments before destination startup. Live assignment changes require
explicit removal on **every configured seat**, then addition on all seats; use
loginctl and its explicit participant configuration. Hotplug does not adopt new
assignments and CHANGE events do not refresh policy.

Root creates a context with immutable VT binding, adds explicit final-UID grants,
and activates its ID. Contexts start inactive. An occupied VT (including the same
context) returns Busy; activation never replaces another context. Only the active
foreground context is effective. Non-VT seats have one active association.
Authority/connection EOF never selects a successor.

Trusted launch code performs PAM, credential changes and detachment. At the final
compositor exec boundary it explicitly delegates authority:

```sh
MULTISEATD_AUTHORITY_FD=3 /usr/libexec/multiseatd/with-seat --seat seat0 /usr/bin/weston
```

FD 3 must actually be inherited from the privileged host. `with-seat` obtains a
fresh connection, verifies immutable metadata, closes authority/unlisted FDs and
execs. It never activates, performs PAM or changes credentials. Alternatively,
a compositor linked against the maintained native libseat backend may directly
consume the authority with `LIBSEAT_BACKEND=multiseatd`, without a wrapper.

`without-seat COMMAND ...` closes all nonstandard inherited FDs and clears seat
capabilities/backend overrides before exec. It refuses socket standard IO because
that could retain a capability duplicate, while allowing files, pipes and PTYs.
Ordinary session metadata such as `XDG_SEAT` is retained. It does not remove UID
ACL grants, revoke another process's access or sandbox the command. Both wrappers
reject a controlling Linux VT. Do not pass authority through untrusted scripts/loaders.

## Build and validation

Requires Rust 1.88+, libudev, libdbus and libacl development files; system-bus policy
requires support for `send_destination_prefix` (D-Bus 1.16 supports it).

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
tests/launch-hygiene.sh
tests/root-context-control.sh
tests/context-libseat.sh
```

Build as a normal user. Root harnesses use passwordless sudo, private buses and
disposable fixtures; missing prerequisites return 77 (skip). They never alter
host services, PAM, udev, real terminals or production device ACLs. The C harness
fetches the exact maintained libseat revision in `tests/libseat-source.sh`;
`LIBSEAT_REPO` explicitly selects an alternative checkout. `TEST_ACL_FAULT=error`,
`panic` or `stall` selects post-write fault validation in the root contract harness.

`test-support` enables only explicit synthetic fixtures. A /dev/null stand-in is
not real device revocation; model VT tests are not native terminal or graphical
login acceptance. SDK/session clients and launcher are synchronous and create no
runtime/worker thread. The daemon drives broker/ACL futures on its runtime;
linux-vt owns only native mechanics and creates no executor.
