"""SQLAlchemy engine, session factory, and one-shot schema bootstrap.

Postgres is mandatory.  The gateway refuses to start if the database is
unreachable -- we deliberately do **not** fall back to JSON or SQLite, because
mixing a stateful auth surface with a best-effort store hides bugs.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from config import DATABASE_URL


_log = logging.getLogger("audit.db")


def _make_engine() -> Engine:
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is required.  Run `docker compose up -d postgres` or set "
            "DATABASE_URL=postgresql+psycopg://user:pass@host:5432/db before starting."
        )
    # `pool_pre_ping` recovers from transient network drops between gateway and
    # Postgres without surfacing stale-connection errors to the user.
    return create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        future=True,
    )


engine: Engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session, future=True)


@contextmanager
def get_session() -> Iterator[Session]:
    """Yield a transactional session.  Commits on success, rolls back on error."""

    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create tables if they don't exist.  Called once at gateway startup.

    For a real production system we'd use Alembic; for the prototype the DDL
    is small and stable enough that `metadata.create_all` is sufficient.
    """

    from .models import Base  # local import avoids circular import on package init

    try:
        Base.metadata.create_all(bind=engine)
    except OperationalError as exc:
        raise RuntimeError(
            f"Could not connect to Postgres at {DATABASE_URL}.  "
            f"Start it with `docker compose up -d postgres`.  Underlying error: {exc}"
        ) from exc
    _log.info("Database schema is ready at %s", _scrub(DATABASE_URL))


def _scrub(url: str) -> str:
    """Redact the password portion of the URL for logs."""

    if "@" not in url or "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    creds, host = rest.split("@", 1)
    if ":" in creds:
        user, _ = creds.split(":", 1)
        return f"{scheme}://{user}:***@{host}"
    return url
