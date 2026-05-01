"""Postgres-backed user + key registry.

Replaces the legacy JSON store.  Public API is preserved so callers (gateway
routes, audit-service, demos, tests) don't need to change:

    list_users(), get(user_id), find_by_username(username),
    authenticate(username, password), register_user(...),
    reader_private_pem(user_id), actor_private_b64(user_id),
    all_reader_pems(patient_id),
    record_failed_login(username), reset_failed_logins(user_id)

New methods used by the admin console / signup route:
    delete_all()
    delete_user(user_id)
    set_locked(user_id, locked)
    create_patient_self_signup(username, password, patient_id)

Private keys are AES-256-GCM-encrypted under the gateway KEK before insert.
"""

from __future__ import annotations

from typing import Mapping, Optional

from sqlalchemy import select

from common import b64d, b64e
from crypto.kek import kek_decrypt, kek_encrypt
from crypto.primitives import (
    ed25519_generate_keypair,
    ed25519_private_b64,
    ed25519_public_b64,
    rsa_generate_keypair,
    rsa_private_pem,
    rsa_public_pem,
    scrypt_hash,
    scrypt_verify,
)
from db import SessionLocal, UserRow
from errors import AuthenticationError, NotFoundError, ValidationError
from models import User


_LOCKOUT_THRESHOLD = 5


def _row_to_user(row: UserRow) -> User:
    return User(
        user_id=row.user_id,
        username=row.username,
        role=row.role,
        password_hash=row.password_hash,
        patient_id=row.patient_id,
        rsa_public_pem=row.rsa_public_pem,
        ed25519_public_b64=row.ed25519_public_b64,
        failed_logins=row.failed_logins,
        locked=row.locked,
    )


class UserStore:
    """Thin facade over the SQLAlchemy ORM."""

    # ---------- listing / lookup ----------

    def list_users(self) -> list[User]:
        with SessionLocal() as session:
            rows = session.execute(select(UserRow).order_by(UserRow.role, UserRow.username)).scalars().all()
            return [_row_to_user(r) for r in rows]

    def get(self, user_id: str) -> User:
        with SessionLocal() as session:
            row = session.get(UserRow, user_id)
            if row is None:
                raise NotFoundError(f"Unknown user: {user_id}")
            return _row_to_user(row)

    def find_by_username(self, username: str) -> Optional[User]:
        with SessionLocal() as session:
            row = session.execute(select(UserRow).where(UserRow.username == username)).scalar_one_or_none()
            return _row_to_user(row) if row is not None else None

    # ---------- creation / authentication ----------

    def authenticate(self, username: str, password: str) -> User:
        user = self.find_by_username(username)
        if user is None or not scrypt_verify(password, user.password_hash):
            raise AuthenticationError("Invalid username or password.")
        if user.locked:
            raise AuthenticationError("Account locked due to too many failed login attempts.")
        return user

    def register_user(
        self,
        user_id: str,
        username: str,
        role: str,
        password: str,
        patient_id: Optional[str] = None,
    ) -> User:
        if role not in {"patient", "doctor", "audit_company", "admin"}:
            raise ValidationError(f"Unknown role: {role}")
        if role == "patient" and not patient_id:
            raise ValidationError("Patients must be associated with a patient_id.")

        with SessionLocal() as session:
            existing = session.execute(select(UserRow).where(UserRow.username == username)).scalar_one_or_none()
            if existing is not None:
                raise ValidationError(f"Username already exists: {username}")

            row = UserRow(
                user_id=user_id,
                username=username,
                role=role,
                password_hash=scrypt_hash(password),
                patient_id=patient_id,
            )

            # Readers (patient, audit_company, admin) get an RSA keypair so the
            # gateway can wrap data keys for them.
            if role in {"patient", "audit_company", "admin"}:
                rsa_priv = rsa_generate_keypair()
                row.rsa_public_pem = rsa_public_pem(rsa_priv)
                row.rsa_private_enc = kek_encrypt(rsa_private_pem(rsa_priv).encode("ascii"))

            # Writers (doctor, admin) get an Ed25519 keypair to sign blocks.
            if role in {"doctor", "admin"}:
                ed_priv = ed25519_generate_keypair()
                row.ed25519_public_b64 = ed25519_public_b64(ed_priv)
                row.ed25519_private_enc = kek_encrypt(b64d(ed25519_private_b64(ed_priv)))

            session.add(row)
            session.commit()
            session.refresh(row)
            return _row_to_user(row)

    def create_patient_self_signup(self, username: str, password: str, patient_id: str) -> User:
        """Public-route helper.  Validates uniqueness of both username and patient_id."""

        if not username or not password or not patient_id:
            raise ValidationError("username, password, and patient_id are required.")
        with SessionLocal() as session:
            clash_user = session.execute(select(UserRow).where(UserRow.username == username)).scalar_one_or_none()
            if clash_user is not None:
                raise ValidationError(f"Username already taken: {username}")
            clash_pid = session.execute(
                select(UserRow).where(UserRow.patient_id == patient_id, UserRow.role == "patient")
            ).scalar_one_or_none()
            if clash_pid is not None:
                raise ValidationError(f"Patient ID already registered: {patient_id}")

        return self.register_user(
            user_id=username,
            username=username,
            role="patient",
            password=password,
            patient_id=patient_id,
        )

    # ---------- private key access ----------

    def reader_private_pem(self, user_id: str) -> str:
        with SessionLocal() as session:
            row = session.get(UserRow, user_id)
            if row is None or not row.rsa_private_enc:
                raise NotFoundError(f"No reader key for {user_id}")
            return kek_decrypt(row.rsa_private_enc).decode("ascii")

    def actor_private_b64(self, user_id: str) -> str:
        with SessionLocal() as session:
            row = session.get(UserRow, user_id)
            if row is None or not row.ed25519_private_enc:
                raise NotFoundError(f"No actor key for {user_id}")
            return b64e(kek_decrypt(row.ed25519_private_enc))

    # ---------- helpers used by the gateway when sealing records ----------

    def all_reader_pems(self, owning_patient_id: str) -> Mapping[str, str]:
        """Public keys that should receive a wrapped data key for a record.

        Includes the patient that owns the record + every audit company +
        every admin.  Doctors are intentionally NOT included; they create
        records but cannot read them back -- only the patient or an audit
        company should be able to pull the audit log.
        """

        out: dict[str, str] = {}
        with SessionLocal() as session:
            rows = session.execute(select(UserRow).where(UserRow.rsa_public_pem.is_not(None))).scalars().all()
            for row in rows:
                if row.role == "patient" and row.patient_id == owning_patient_id:
                    out[row.user_id] = row.rsa_public_pem  # type: ignore[assignment]
                elif row.role in {"audit_company", "admin"}:
                    out[row.user_id] = row.rsa_public_pem  # type: ignore[assignment]
        return out

    # ---------- failed login bookkeeping ----------

    def record_failed_login(self, username: str) -> None:
        with SessionLocal() as session:
            row = session.execute(select(UserRow).where(UserRow.username == username)).scalar_one_or_none()
            if row is None:
                return
            row.failed_logins += 1
            if row.failed_logins >= _LOCKOUT_THRESHOLD:
                row.locked = True
            session.commit()

    def reset_failed_logins(self, user_id: str) -> None:
        with SessionLocal() as session:
            row = session.get(UserRow, user_id)
            if row is None:
                return
            if row.failed_logins or row.locked:
                row.failed_logins = 0
                row.locked = False
                session.commit()

    # ---------- admin operations ----------

    def delete_all(self) -> None:
        """Used by `bootstrap(reset=True)` and the admin reset button."""

        with SessionLocal() as session:
            session.query(UserRow).delete()
            session.commit()

    def delete_user(self, user_id: str) -> None:
        with SessionLocal() as session:
            row = session.get(UserRow, user_id)
            if row is None:
                raise NotFoundError(f"Unknown user: {user_id}")
            session.delete(row)
            session.commit()

    def set_locked(self, user_id: str, locked: bool) -> None:
        with SessionLocal() as session:
            row = session.get(UserRow, user_id)
            if row is None:
                raise NotFoundError(f"Unknown user: {user_id}")
            row.locked = locked
            if not locked:
                row.failed_logins = 0
            session.commit()
