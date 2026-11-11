#!/bin/sh
# Build as the normal user; elevate only the disposable private-bus fixture.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$(id -u)" -eq 0 ]; then echo 'SKIP: run the build harness as a normal user' >&2; exit 77; fi
for command in cargo sudo timeout; do command -v "$command" >/dev/null 2>&1 || exit 77; done
sudo -n true || exit 77
cargo build --manifest-path "$repo/Cargo.toml" -p multiseatd --no-default-features --features test-support
cargo build --manifest-path "$repo/Cargo.toml" -p lib-multiseatd --example contract-probe
cargo build --manifest-path "$repo/Cargo.toml" -p seat-launch
sudo -n env TEST_ACL_FAULT="${TEST_ACL_FAULT:-}" CONTEXT_LIBSEAT_CLIENT="${CONTEXT_LIBSEAT_CLIENT:-}" \
    CONTEXT_NATIVE_CLIENT="${CONTEXT_NATIVE_CLIENT:-}" CONTEXT_SEAT_LAUNCH="$repo/target/debug/seat-launch" \
    timeout --signal=TERM --kill-after=5s 60s "$repo/tests/per-seat-contract.sh" \
    "$repo/target/debug/multiseatd" "$repo/target/debug/examples/contract-probe"
