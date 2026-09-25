"""Test helper: attempt one provider-call admission in a fresh process.

Usage:
    attempt_provider_call.py <data_dir> <timeout_seconds>

Exits 0 and prints ``admitted:<provider_id>`` if the call was admitted past
the reconnect gate, or exits 10 and prints ``blocked`` if it waited out the
shared reconnect budget (ProviderReconnectPending) without being admitted.
Nothing is ever called on the backend on the blocked path.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from keymgr import provider as provider_mod  # noqa: E402


def main() -> int:
    data_dir, timeout = sys.argv[1], float(sys.argv[2])
    provider_mod._configured_dir = data_dir
    provider_mod._load_history()
    try:
        with provider_mod.provider_call(timeout=timeout) as provider:
            print("admitted:%s" % provider.provider_id, flush=True)
        return 0
    except provider_mod.ProviderReconnectPending:
        print("blocked", flush=True)
        return 10


if __name__ == "__main__":
    raise SystemExit(main())
