"""SQLAlchemy ORM models for the gateway's persistent state.

Tables:
- users               : roster + scrypt password + encrypted private keys
- login_events        : audit trail of every authentication attempt
- jwt_revocations     : durable replacement for the in-memory JTI deny-list
- query_audit         : who queried what (audit-company-visible read trail)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserRow(Base):
    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    patient_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)

    # scrypt-derived password hash (encoded with parameters, like the legacy store)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    # Public material -- safe to store as-is.
    rsa_public_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ed25519_public_b64: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Private material -- AES-256-GCM-encrypted at rest under the gateway KEK.
    # Format on each blob: 12-byte nonce || ciphertext || 16-byte tag.
    rsa_private_enc: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    ed25519_private_enc: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)

    failed_logins: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, server_default=func.now(), nullable=False
    )

    login_events: Mapped[list["LoginEventRow"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class LoginEventRow(Base):
    __tablename__ = "login_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True)
    username_attempted: Mapped[str] = mapped_column(String(64), nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, server_default=func.now(), nullable=False, index=True)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)  # success | bad_password | unknown_user | locked

    user: Mapped[Optional[UserRow]] = relationship(back_populates="login_events")


class JwtRevocationRow(Base):
    __tablename__ = "jwt_revocations"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class QueryAuditRow(Base):
    """Read-side audit trail.  Audit-company users can review this to see
    every privileged read that hit the gateway.
    """

    __tablename__ = "query_audit"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, server_default=func.now(), nullable=False, index=True)
    actor_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    actor_role: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    endpoint: Mapped[str] = mapped_column(String(128), nullable=False)
    method: Mapped[str] = mapped_column(String(8), nullable=False)
    patient_filter: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    result_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


Index("ix_users_role", UserRow.role)
Index("ix_query_audit_actor_ts", QueryAuditRow.actor_user_id, QueryAuditRow.ts)
