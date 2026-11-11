#!/bin/bash
# Disposable exec/PTY fixtures; no console, PAM, services or cgroups.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v python3 >/dev/null || exit 77
cargo build --manifest-path "$repo/Cargo.toml" -p lib-multiseatd --example launch-probe
cargo build --manifest-path "$repo/Cargo.toml" -p seat-wrapper --bins
python3 - "$repo/target/debug/examples/launch-probe" "$repo/target/debug/without-seat" <<'PY'
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
# Capability duplicates must disappear even when the environment names only one.
capability, peer = socket.socketpair()
duplicate = os.dup(capability.fileno())
keys = ('MULTISEATD_AUTHORITY_FD', 'MULTISEATD_CONTEXT_ID', 'SEATD_FD', 'SEATD_SOCK', 'LIBSEAT_BACKEND')
env = dict(os.environ, **dict.fromkeys(keys, str(capability.fileno())), XDG_SEAT='seat-test')
check = '''import errno,os,sys
assert all(key not in os.environ for key in sys.argv[1].split(','))
assert os.environ['XDG_SEAT'] == 'seat-test'
for raw in map(int,sys.argv[2:]):
    try: os.fstat(raw)
    except OSError as e: assert e.errno == errno.EBADF
    else: raise AssertionError('inherited capability escaped')
'''
result = subprocess.run([sys.argv[2], sys.executable, '-c', check, ','.join(keys), str(capability.fileno()), str(duplicate)],
    pass_fds=(capability.fileno(), duplicate), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    start_new_session=True, timeout=5)
assert result.returncode == 0, result.stderr
# Standard-IO socket aliases cannot be claimed safe without authenticating them.
result = subprocess.run([sys.argv[2], '/bin/true'], stdin=capability, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, start_new_session=True, timeout=5)
assert result.returncode != 0 and b'socket standard IO' in result.stderr, result.stderr
os.close(duplicate); capability.close(); peer.close()
print('Detached workers, safe stdio/PTYs, FD allowlist, exec inheritance and without-seat capability stripping passed')
PY
