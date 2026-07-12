"""web-scanner dev entrypoint — delegates to the packaged CLI.

    python app.py example.com

Equivalent to the installed ``webscan`` command / ``python -m webscanner``.
"""

from webscanner.cli import main

if __name__ == "__main__":
    main()
