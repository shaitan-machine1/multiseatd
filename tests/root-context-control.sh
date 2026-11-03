#!/bin/bash
# Disposable system bus, sockets and ACL inode only. No live seat/cgroup/VT I/O.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if (( EUID != 0 )); then
    for tool in cargo sudo dbus-daemon timeout getfacl setfacl; do
        command -v "$tool" >/dev/null || exit 77
    done
    sudo -n true || exit 77
    cargo build --manifest-path "$repo/Cargo.toml" -p multiseatd --features test-support --bin multiseatd --example context-probe
    cargo build --manifest-path "$repo/Cargo.toml" -p with-seat
    exec sudo -n env CONTEXT_LIBSEAT_CLIENT="${CONTEXT_LIBSEAT_CLIENT:-}" timeout --signal=TERM --kill-after=5s 60s bash "$0" --root
fi
work=$(mktemp -d /tmp/multiseat-context.XXXXXX)
chmod 755 "$work"
cleanup() {
    status=$?
    trap - EXIT
    for pid in $(jobs -pr); do kill "$pid" 2>/dev/null || true; done
    wait || true
    if (( status != 0 )); then tail -n 100 "$work"/*.log >&2 || true; fi
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT
cp "$repo/target/debug/multiseatd" "$work/multiseatd"
cp "$repo/target/debug/examples/context-probe" "$work/probe"
cp "$repo/target/debug/with-seat" "$work/with-seat"
chmod 755 "$work/multiseatd" "$work/probe" "$work/with-seat"
printf '%s\n' '<busconfig>' '<type>system</type>' "<listen>unix:path=$work/bus</listen>" '<auth>EXTERNAL</auth>' '<policy context="default"><allow user="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy>' '<policy user="root"><allow own="*"/></policy>' "<include>$repo/dist/dbus/org.decoupling.multiseatd2.conf</include>" '</busconfig>' >"$work/bus.conf"
dbus-daemon --nofork --config-file="$work/bus.conf" >"$work/bus.log" 2>&1 &
bus=$!
for ((i=0; i<200; i++)); do [[ -S $work/bus ]] && break; sleep .02; done
[[ -S $work/bus ]]
chmod 666 "$work/bus"
export DBUS_SYSTEM_BUS_ADDRESS="unix:path=$work/bus"
touch "$work/direct"
chmod 600 "$work/direct"
setfacl -m u:55555:rw- "$work/direct"
fixture_args=()
if [[ -n ${CONTEXT_LIBSEAT_CLIENT:-} ]]; then fixture_args+=(--test-null-device); fi
start() {
    "$work/multiseatd" "${fixture_args[@]}" --test-only --test-seat seat-test --lock-file "$work/daemon.lock" --test-direct-node "$work/direct" >"$work/daemon.log" 2>&1 &
    daemon=$!
    for ((i=0; i<200; i++)); do
        "$work/probe" ready 2>/dev/null && return
        kill -0 "$daemon" 2>/dev/null || return 1
        sleep .02
    done
    return 1
}
start
! getfacl -cpn "$work/direct" | grep -q '^user:55555:'
timeout 15 "$work/probe" contract
timeout 15 "$work/probe" sdk
timeout 15 "$work/probe" grants "$work/direct" "$(id -u nobody)" "$(id -g nobody)"
if [[ -n ${CONTEXT_LIBSEAT_CLIENT:-} ]]; then
    cp "$CONTEXT_LIBSEAT_CLIENT" "$work/libseat-client"
    chmod 755 "$work/libseat-client"
    timeout 15 "$work/probe" libseat "$work/libseat-client" "$(id -u nobody)" "$(id -g nobody)"
    timeout 15 "$work/probe" wrapper "$work/with-seat" "$work/libseat-client" "$(id -u nobody)" "$(id -g nobody)"
fi
"$work/probe" delegate "$work/delegation" "$(id -u nobody)" >"$work/delegate.log" 2>&1 &
delegator=$!
for ((i=0; i<200; i++)); do [[ -S $work/delegation ]] && break; sleep .02; done
timeout 15 sudo -u nobody env DBUS_SYSTEM_BUS_ADDRESS="$DBUS_SYSTEM_BUS_ADDRESS" "$work/probe" delegated "$work/delegation"
wait "$delegator"
touch "$work/second-direct"
setfacl -m u:55556:rw- "$work/second-direct"
if "$work/multiseatd" --test-only --test-seat seat-test --lock-file "$work/daemon.lock" --test-direct-node "$work/second-direct" >"$work/second.log" 2>&1; then exit 1; fi
grep -q 'instance lock' "$work/second.log"
getfacl -cpn "$work/second-direct" | grep -q '^user:55556:'
setfacl -m u:55557:rw- "$work/direct"
kill -TERM "$daemon"
wait "$daemon"
! getfacl -cpn "$work/direct" | grep -q '^user:55557:'
# The singleton inode persists across process restarts.
[[ -f $work/daemon.lock ]]
start
kill -TERM "$bus"
wait "$bus"
if wait "$daemon"; then echo 'bus loss must fail the daemon' >&2; exit 1; fi
echo 'v2 context creation, cross-UID capability transfer, root separation, final close, startup ACL cleanup, singleton and bus-loss teardown passed'
