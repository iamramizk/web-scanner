"""web-scanner v2 entrypoint.

    python app.py example.com
"""

from __future__ import annotations

import sys

from webscanner.helpers import is_valid_url
from webscanner.ui.app import WebScannerApp


def main() -> None:
    target = sys.argv[1].strip() if len(sys.argv) > 1 else None
    if target and not is_valid_url(target):
        print(f"[!] Not a valid target: {target}")
        raise SystemExit(1)
    WebScannerApp(target).run()


if __name__ == "__main__":
    main()
