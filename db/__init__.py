"""Postgres-backed persistence layer for the gateway.

The audit chain itself stays on the node servers (decentralised, append-only
JSONL).  Postgres handles only what the *gateway* owns: user roster, password
hashes, encrypted-at-rest private keys, JWT revocations, login events, and a
read-side audit log of who-queried-what.
"""

from .engine import (
    SessionLocal,
    engine,
    get_session,
    init_db,
)
from .models import (
    Base,
    JwtRevocationRow,
    LoginEventRow,
    QueryAuditRow,
    UserRow,
)

__all__ = [
    "SessionLocal",
    "engine",
    "get_session",
    "init_db",
    "Base",
    "UserRow",
    "JwtRevocationRow",
    "LoginEventRow",
    "QueryAuditRow",
]
