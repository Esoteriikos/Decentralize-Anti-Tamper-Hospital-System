"""Convenience entry point: starts the gateway only.

For the full local stack (3 nodes + gateway + web UI), run:

    python scripts/dev.py

This file exists so the project still answers `python app.py` like the
original prototype did.
"""

from gateway.app import main


if __name__ == "__main__":
    main()
