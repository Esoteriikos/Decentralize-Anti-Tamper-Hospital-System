"""Cross-cutting helpers shared by gateway and node server."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any


def canonical_bytes(payload: Any) -> bytes:
    """Deterministic JSON serialisation used for hashing and signatures.

    Keys are sorted, separators are tight, and unicode is preserved.  Two
    canonically encoded payloads are identical iff their logical content is
    identical.  All hashes and signatures in this project are computed over
    the output of this function so that gateway, nodes and demos all agree.
    """

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
