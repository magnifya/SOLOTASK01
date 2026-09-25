"""Test helper: hold a cross-process provider flock, then exit.

Usage:
    hold_provider_lock.py <data_dir> <intent|state> <shared|excl> <seconds>

Used by the reconnect regression tests to reproduce the exact cross-process
timing an in-process thread cannot: another *process* holding (or killed
while holding) the reconnect intent / state lease.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from keymgr import provider as provider_mod  # noqa: E402


def main() -> int:
    data_dir, which, mode, seconds = sys.argv[1:5]
    name = (
        provider_mod._INTENT_LOCK_NAME
        if which == "intent"
        else provider_mod._STATE_LOCK_NAME
    )
    exclusive = mode == "excl"
    deadline = time.monotonic() + float(seconds) + 5.0
    provider_mod._configured_dir = data_dir
    lease = provider_mod._FileLease(name)
    lease.acquire(exclusive, deadline)
    try:
        # Signal readiness on stdout once the lock is actually held.
        sys.stdout.write("held\n")
        sys.stdout.flush()
        time.sleep(float(seconds))
    finally:
        lease.release()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
