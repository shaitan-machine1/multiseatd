#!/bin/sh
# Root-only, private bus/disposable files. No host device ACLs or services.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo 'SKIP: run this disposable harness as root' >&2; exit 77; fi
if [ "$#" -ne 2 ]; then echo 'usage: per-seat-contract.sh DAEMON_WITH_TEST_SUPPORT CONTRACT_PROBE' >&2; exit 2; fi
for command in dbus-daemon getfacl setfacl timeout; do
    command -v "$command" >/dev/null 2>&1 || { echo "SKIP: missing $command" >&2; exit 77; }
done
daemon=$(realpath "$1")
probe=$(realpath "$2")
base=$(mktemp -d /tmp/multiseatd-contract.XXXXXXXX)
chmod 755 "$base"
mkdir -m 700 "$base/fixtures"
mkdir -m 755 "$base/tools"
cp "$probe" "$base/tools/probe"
chmod 755 "$base/tools/probe"
if [ -n "${CONTEXT_LIBSEAT_CLIENT:-}" ]; then
    cp "$CONTEXT_LIBSEAT_CLIENT" "$base/tools/client"; chmod 755 "$base/tools/client"
    CONTEXT_LIBSEAT_CLIENT="$base/tools/client"; export CONTEXT_LIBSEAT_CLIENT
fi
if [ -n "${CONTEXT_NATIVE_CLIENT:-}" ]; then
    cp "$CONTEXT_NATIVE_CLIENT" "$base/tools/native-client"; chmod 755 "$base/tools/native-client"
    CONTEXT_NATIVE_CLIENT="$base/tools/native-client"; export CONTEXT_NATIVE_CLIENT
fi
if [ -n "${CONTEXT_WITH_SEAT:-}" ]; then
    cp "$CONTEXT_WITH_SEAT" "$base/tools/with-seat"; chmod 755 "$base/tools/with-seat"
    CONTEXT_WITH_SEAT="$base/tools/with-seat"; export CONTEXT_WITH_SEAT
fi
: > "$base/fixtures/node"
bus_pid=
daemon_pid=
cleanup() {
    if [ -n "$daemon_pid" ]; then kill "$daemon_pid" 2>/dev/null || :; wait "$daemon_pid" 2>/dev/null || :; fi
    if [ -n "$bus_pid" ]; then kill "$bus_pid" 2>/dev/null || :; fi
    if [ "${KEEP_FIXTURES:-0}" = 1 ]; then echo "fixtures: $base" >&2; else rm -rf "$base"; fi
}
trap cleanup EXIT HUP INT TERM
address="unix:abstract=multiseatd-contract-$$"
# Root must own services, but an unprivileged client can authenticate and prove
# the server's method authorization. The abstract socket needs no host paths.
cat_config="$base/fixtures/bus.conf"
# Use only fixed configuration and the private name.
printf '%s\n' '<busconfig>' "<listen>$address</listen>" '<auth>EXTERNAL</auth>' \
    '<policy context="default"><allow user="*"/><allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/></policy>' \
    "<include>$(dirname "$(realpath "$0")")/../dist/dbus/org.SGLogin.Multiseatd1.conf</include>" \
    '</busconfig>' > "$cat_config"
bus_pid=$(dbus-daemon --config-file="$cat_config" --fork --print-pid)
set -- "$daemon" --seat seat-contract --test-only --test-root "$base/fixtures" --lock-file "$base/fixtures/daemon.lock" \
    --bus-address "$address" --test-direct-node "$base/fixtures/node"
if [ -n "${CONTEXT_LIBSEAT_CLIENT:-}${CONTEXT_NATIVE_CLIENT:-}" ]; then set -- "$@" --test-null-device; fi
case "${TEST_ACL_FAULT:-}" in
    '') ;;
    error|panic|stall) set -- "$@" --test-acl-fault "$TEST_ACL_FAULT" ;;
    *) echo 'invalid TEST_ACL_FAULT' >&2; exit 2 ;;
esac
"$@" > "$base/fixtures/daemon.log" 2>&1 &
daemon_pid=$!
set -- "$base/tools/probe"
if [ -n "${TEST_ACL_FAULT:-}" ]; then set -- "$@" --fatal; fi
if ! timeout 25 "$@" "$address" seat-contract "$base/fixtures/node"; then
    printf '%s\n' 'daemon diagnostics:' >&2
    python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())' "$base/fixtures/daemon.log" >&2
    exit 1
fi
if [ -z "${TEST_ACL_FAULT:-}" ]; then kill -TERM "$daemon_pid"; fi
set +e
wait "$daemon_pid"
result=$?
set -e
daemon_pid=
if [ -n "${TEST_ACL_FAULT:-}" ]; then
    [ "$result" -ne 0 ] || { echo 'fatal daemon incorrectly exited zero' >&2; exit 1; }
    if [ "$TEST_ACL_FAULT" = stall ]; then
        getfacl --numeric --absolute-names "$base/fixtures/node" | grep -q 'user:424242:rw-' || { echo 'stall fixture did not exercise an unfinished ACL write owner' >&2; exit 1; }
        echo 'uncancellable worker and uncertain ACL retained through bounded nonzero exit; no clean-revoke claim'
    else
        if getfacl --numeric --absolute-names "$base/fixtures/node" | grep -q 'user:424242:'; then echo 'fatal pin cleanup did not clear the real write' >&2; exit 1; fi
        echo 'actual post-write error/panic pins cleaned after explicit CriticalFailure; nonzero exit passed'
    fi
else
    if [ "$result" -ne 0 ]; then
        python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())' "$base/fixtures/daemon.log" >&2
        exit 1
    fi
    echo 'normal bounded shutdown and native-owner joins passed'
fi
