#!/bin/bash
# Disposable exec/PTY fixtures; no console, PAM, services or cgroups.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v python3 >/dev/null || exit 77
cargo build --manifest-path "$repo/Cargo.toml" -p lib-multiseatd --example launch-probe
python3 - "$repo/target/debug/examples/launch-probe" <<'PY'
import os, pty, socket, subprocess, sys
for mode in ('worker', 'null'):
    master, slave = pty.openpty()
    read, write = os.pipe()
    sentinel, peer = socket.socketpair()
    process = subprocess.Popen([sys.argv[1], mode, str(write), str(sentinel.fileno())],
        pass_fds=(write, sentinel.fileno()), stdin=slave,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    os.close(write)
    output, error = process.communicate(timeout=5)
    assert process.returncode == 0, (mode, output, error)
    assert os.read(read, 2) == b'ok'
    os.close(read); os.close(master); os.close(slave)
    sentinel.close(); peer.close()
print('Detached post-exec workers, safe stdio/PTYs, FD allowlist and exec inheritance passed')
PY
