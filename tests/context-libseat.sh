#!/bin/bash
# Real maintained C libseat, new context daemon, inherited FD and close/reopen.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
(( EUID != 0 )) || { echo 'run this build harness as a normal user' >&2; exit 77; }
for tool in cargo cc meson ninja sudo timeout; do command -v "$tool" >/dev/null || exit 77; done
sudo -n true || exit 77
# shellcheck source=tests/libseat-source.sh
. "$repo/tests/libseat-source.sh"
set +e
source_repo=$(resolve_libseat_source)
result=$?
set -e
(( result == 0 )) || exit "$result"
work=$(mktemp -d /tmp/context-libseat.XXXXXX)
trap 'rm -rf "$work"' EXIT
chmod 755 "$work"
meson setup "$work/build" "$source_repo" -Dserver=disabled -Dexamples=disabled -Dman-pages=disabled -Dlibseat-logind=disabled -Dlibseat-builtin=disabled >/dev/null
ninja -C "$work/build" >/dev/null
cc -Wall -Wextra -Werror "$repo/tests/fixtures/context-libseat.c" -I"$source_repo/include" -L"$work/build" -Wl,-rpath,"$work/build" -lseat -o "$work/client"
CONTEXT_LIBSEAT_CLIENT="$work/client" "$repo/tests/root-context-control.sh"
echo 'Maintained C libseat inherited-FD and sequential close/reopen passed against the context daemon'
