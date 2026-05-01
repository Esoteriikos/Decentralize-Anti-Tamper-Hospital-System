"""Local development launcher.

Spawns three node servers and one gateway as subprocesses, prefixes
their stdout with their service name, and forwards Ctrl+C to all of
them.  This keeps the demo to a single terminal which is what the
recording script expects.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SERVICES = [
    {"name": "node_a", "module": "node_server", "env": {"NODE_ID": "node_a", "NODE_PORT": "5311", "ALLOW_TAMPER": "1", "ALLOW_RESET": "1"}},
    {"name": "node_b", "module": "node_server", "env": {"NODE_ID": "node_b", "NODE_PORT": "5312", "ALLOW_TAMPER": "1", "ALLOW_RESET": "1"}},
    {"name": "node_c", "module": "node_server", "env": {"NODE_ID": "node_c", "NODE_PORT": "5313", "ALLOW_TAMPER": "1", "ALLOW_RESET": "1"}},
    {"name": "gateway", "module": "gateway", "env": {}},
]

COLORS = {
    "node_a": "\033[36m",
    "node_b": "\033[35m",
    "node_c": "\033[33m",
    "gateway": "\033[32m",
}
RESET = "\033[0m"


def stream(proc: subprocess.Popen, name: str) -> None:
    color = COLORS.get(name, "")
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stdout.write(f"{color}[{name}]{RESET} {line}")
        sys.stdout.flush()


def main() -> int:
    procs: list[tuple[str, subprocess.Popen]] = []
    try:
        for svc in SERVICES:
            env = os.environ.copy()
            env.update(svc["env"])
            proc = subprocess.Popen(
                [sys.executable, "-u", "-m", svc["module"]],
                cwd=str(ROOT),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                text=True,
            )
            procs.append((svc["name"], proc))
            threading.Thread(target=stream, args=(proc, svc["name"]), daemon=True).start()
            # small stagger so nodes finish keygen before gateway pings them
            time.sleep(0.6)

        print("\n[dev] All services launched.  Press Ctrl+C to stop.\n")
        while True:
            for name, proc in procs:
                if proc.poll() is not None:
                    print(f"[dev] {name} exited with code {proc.returncode}")
                    return proc.returncode or 1
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[dev] Ctrl+C received, shutting services down...")
        return 0
    finally:
        for name, proc in procs:
            if proc.poll() is None:
                try:
                    if os.name == "nt":
                        proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
                    else:
                        proc.terminate()
                except Exception:
                    pass
        for name, proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
