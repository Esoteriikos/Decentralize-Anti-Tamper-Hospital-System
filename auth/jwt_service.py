"""JWT issuance + verification with database-backed revocation.

Tokens are HS256 signed with a per-deployment secret persisted under
data/gateway/keys.json.  Every token carries `exp`, `iat`, `nbf`, `jti`
plus the user's role and (for patients) their patient_id so the policy
layer can authorise without an extra DB roundtrip.

Revocations live in Postgres (`jwt_revocations`) so a gateway restart no
longer wipes the deny-list.
"""

from __future__ import annotations

import base64
import os
import time
import uuid
from datetime import datetime, timezone

import jwt
from sqlalchemy import select

from common import b64e
from config import GATEWAY_DATA_DIR, GATEWAY_JWT_SECRET_ENV, JWT_ALGORITHM, JWT_TTL_SECONDS
from db import JwtRevocationRow, SessionLocal
from errors import AuthenticationError
from models import User
from storage import read_json, write_json


_KEYS_PATH = GATEWAY_DATA_DIR / "keys.json"


def _load_or_create_secret() -> bytes:
    if GATEWAY_JWT_SECRET_ENV:
        try:
            return base64.b64decode(GATEWAY_JWT_SECRET_ENV.encode("ascii"))
        except Exception:
            return GATEWAY_JWT_SECRET_ENV.encode("utf-8")

    keys = read_json(_KEYS_PATH, default={})
    if "jwt_secret" in keys:
        return base64.b64decode(keys["jwt_secret"].encode("ascii"))

    secret = os.urandom(32)
    keys["jwt_secret"] = b64e(secret)
    write_json(_KEYS_PATH, keys)
    return secret


class JwtService:
    def __init__(self, secret: bytes | None = None) -> None:
        self.secret = secret or _load_or_create_secret()

    def issue(self, user: User) -> dict:
        now = int(time.time())
        jti = uuid.uuid4().hex
        payload = {
            "sub": user.user_id,
            "username": user.username,
            "role": user.role,
            "patient_id": user.patient_id,
            "iat": now,
            "nbf": now,
            "exp": now + JWT_TTL_SECONDS,
            "jti": jti,
        }
        token = jwt.encode(payload, self.secret, algorithm=JWT_ALGORITHM)
        return {"token": token, "expires_at": payload["exp"], "jti": jti}

    def verify(self, token: str) -> dict:
        try:
            payload = jwt.decode(token, self.secret, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationError("Token expired.") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthenticationError(f"Invalid token: {exc}") from exc
        if self._is_revoked(payload.get("jti", "")):
            raise AuthenticationError("Token has been revoked.")
        return payload

    def revoke(self, jti: str, user_id: str | None = None, expires_at: int | None = None) -> None:
        if not jti:
            return
        expires = datetime.fromtimestamp(expires_at or int(time.time()) + JWT_TTL_SECONDS, tz=timezone.utc)
        with SessionLocal() as session:
            existing = session.get(JwtRevocationRow, jti)
            if existing is not None:
                return
            session.add(JwtRevocationRow(jti=jti, user_id=user_id, expires_at=expires))
            session.commit()

    def purge_expired(self) -> int:
        """House-keeping: drop revocation rows whose target tokens have already
        expired.  The deny-list only needs to outlive the JWT TTL."""

        now = datetime.now(tz=timezone.utc)
        with SessionLocal() as session:
            stale = session.execute(select(JwtRevocationRow).where(JwtRevocationRow.expires_at < now)).scalars().all()
            for row in stale:
                session.delete(row)
            session.commit()
            return len(stale)

    def _is_revoked(self, jti: str) -> bool:
        if not jti:
            return False
        with SessionLocal() as session:
            return session.get(JwtRevocationRow, jti) is not None
