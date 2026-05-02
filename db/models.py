"""SQLAlchemy ORM models for the gateway's Postgres tables.

Tables
------
users            — user roster, scrypt password hashes, KEK-encrypted private keys
jwt_revocations  — revoked JTI tokens (outlive the JWT TTL, then purged)
login_events     — every login attempt (success + failure) for the audit trail
query_audit      — every read-side query (patient + audit-company + admin) for investigation
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class UserRow(Base):
    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    patient_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # RSA-2048 keypair — only readers (patient, audit_company, admin)
    rsa_public_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    rsa_private_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # Ed25519 keypair — only writers (doctor, admin)
    ed25519_public_b64: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ed25519_private_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    failed_logins: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class JwtRevocationRow(Base):
    __tablename__ = "jwt_revocations"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class LoginEventRow(Base):
    __tablename__ = "login_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(tz=timezone.utc),
    )
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    username_attempted: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)  # "success" | "bad_password" | "locked" | …
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)


class QueryAuditRow(Base):
    __tablename__ = "query_audit"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(tz=timezone.utc),
    )
    actor_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    endpoint: Mapped[str] = mapped_column(String(128), nullable=False)
    method: Mapped[str] = mapped_column(String(8), nullable=False)
    patient_filter: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
