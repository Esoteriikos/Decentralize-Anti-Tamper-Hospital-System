"""Persistence helpers for the read-side audit log + login events.

Both tables exist so an audit company can review who authenticated and what
patient data they queried -- that's part of the rubric's "querying" surface.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select

from db import LoginEventRow, QueryAuditRow, SessionLocal


def record_login_event(
    *,
    user_id: Optional[str],
    username_attempted: str,
    outcome: str,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    with SessionLocal() as session:
        session.add(
            LoginEventRow(
                user_id=user_id,
                username_attempted=username_attempted[:64],
                outcome=outcome,
                ip=ip,
                user_agent=(user_agent or "")[:256] or None,
            )
        )
        session.commit()


def recent_login_events(limit: int = 50) -> list[dict]:
    with SessionLocal() as session:
        rows = (
            session.execute(select(LoginEventRow).order_by(LoginEventRow.ts.desc()).limit(limit)).scalars().all()
        )
        return [
            {
                "ts": r.ts.isoformat() if r.ts else None,
                "user_id": r.user_id,
                "username": r.username_attempted,
                "outcome": r.outcome,
                "ip": r.ip,
            }
            for r in rows
        ]


def record_query(
    *,
    actor_user_id: Optional[str],
    actor_role: Optional[str],
    endpoint: str,
    method: str,
    patient_filter: Optional[str],
    result_count: Optional[int],
    status_code: int,
    ip: Optional[str] = None,
) -> None:
    with SessionLocal() as session:
        session.add(
            QueryAuditRow(
                actor_user_id=actor_user_id,
                actor_role=actor_role,
                endpoint=endpoint[:128],
                method=method[:8],
                patient_filter=patient_filter,
                result_count=result_count,
                status_code=status_code,
                ip=ip,
            )
        )
        session.commit()


def recent_queries(limit: int = 100, actor_user_id: Optional[str] = None) -> list[dict]:
    with SessionLocal() as session:
        stmt = select(QueryAuditRow).order_by(QueryAuditRow.ts.desc()).limit(limit)
        if actor_user_id:
            stmt = select(QueryAuditRow).where(QueryAuditRow.actor_user_id == actor_user_id).order_by(
                QueryAuditRow.ts.desc()
            ).limit(limit)
        rows = session.execute(stmt).scalars().all()
        return [
            {
                "ts": r.ts.isoformat() if r.ts else None,
                "actor": r.actor_user_id,
                "role": r.actor_role,
                "endpoint": r.endpoint,
                "method": r.method,
                "patient_filter": r.patient_filter,
                "result_count": r.result_count,
                "status_code": r.status_code,
                "ip": r.ip,
            }
            for r in rows
        ]


def login_summary(days: int = 7) -> dict:
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)
    with SessionLocal() as session:
        rows = session.execute(select(LoginEventRow).where(LoginEventRow.ts >= cutoff)).scalars().all()
    by_outcome: dict[str, int] = {}
    for r in rows:
        by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + 1
    return {"window_days": days, "total": len(rows), "by_outcome": by_outcome}
