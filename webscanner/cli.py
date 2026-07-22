"""Console entry point for the ``webscan`` command.

    webscan example.com
    python -m webscanner example.com
"""

from __future__ import annotations

import os
import sys

from webscanner.helpers import is_valid_url
from webscanner.ui.app import WebScannerApp


def main() -> None:
    target = sys.argv[1].strip() if len(sys.argv) > 1 else None
    if target and not is_valid_url(target):
        print(f"[!] Not a valid target: {target}")
        raise SystemExit(1)
    WebScannerApp(target).run()
    # Textual has already restored the terminal by the time run() returns.
    # Quitting mid-scan cancels the scan worker's coroutine, but the blocking
    # work it dispatched via asyncio.to_thread (requests/socket/pydig/Wappalyzer,
    # each up to ~12–30s of timeout) keeps running in asyncio's default thread
    # pool. Those are non-daemon threads, so concurrent.futures' atexit handler
    # joins them on interpreter shutdown and the process hangs after the UI is
    # gone. os._exit bypasses that join and terminates now — safe here: the
    # terminal is restored and there is no post-scan state left to flush.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
