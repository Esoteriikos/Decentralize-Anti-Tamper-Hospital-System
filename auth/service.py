import base64
import hashlib
import hmac
import json
import time
from typing import Iterable

from werkzeug.security import check_password_hash, generate_password_hash

from config import USERS_FILE
from errors import AuthenticationError
from models import User
from storage import read_json, write_json


class AuthService:
    def __init__(self, token_key: bytes) -> None:
        self.token_key = token_key

    def list_users(self) -> list[User]:
        raw_users = read_json(USERS_FILE, default=[])
        return [User(**raw_user) for raw_user in raw_users]

    def save_users(self, users: Iterable[User]) -> None:
        write_json(USERS_FILE, [user.to_dict() for user in users])

    def create_sample_users(self, reset: bool = False) -> list[User]:
        if USERS_FILE.exists() and not reset:
            return self.list_users()

        users: list[User] = []

        for index in range(1, 11):
            patient_number = f"{index:02d}"
            users.append(
                User(
                    user_id=f"patient_{patient_number}",
                    username=f"patient_{patient_number}",
                    role="patient",
                    password_hash=generate_password_hash("PatientPass!"),
                    patient_id=f"P{index:03d}",
                )
            )

        for index in range(1, 3):
            users.append(
                User(
                    user_id=f"doctor_{index:02d}",
                    username=f"doctor_{index:02d}",
                    role="doctor",
                    password_hash=generate_password_hash("DoctorPass!"),
                )
            )

        for index in range(1, 4):
            users.append(
                User(
                    user_id=f"audit_company_{index:02d}",
                    username=f"audit_company_{index:02d}",
                    role="audit_company",
                    password_hash=generate_password_hash("AuditPass!"),
                )
            )

        users.append(
            User(
                user_id="admin_01",
                username="admin_01",
                role="admin",
                password_hash=generate_password_hash("AdminPass!"),
            )
        )

        self.save_users(users)
        return users

    def authenticate(self, username: str, password: str) -> User:
        for user in self.list_users():
            if user.username == username and check_password_hash(user.password_hash, password):
                return user
        raise AuthenticationError("Invalid username or password.")

    def get_user_by_id(self, user_id: str) -> User:
        for user in self.list_users():
            if user.user_id == user_id:
                return user
        raise AuthenticationError(f"Unknown user: {user_id}")

    def issue_token(self, user: User) -> str:
        payload = {
            "user_id": user.user_id,
            "role": user.role,
            "patient_id": user.patient_id,
            "issued_at": int(time.time()),
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("utf-8")
        signature = hmac.new(self.token_key, payload_bytes, hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode("utf-8")
        return f"{payload_b64}.{signature_b64}"

    def verify_token(self, token: str) -> User:
        payload_b64, signature_b64 = token.split(".", maxsplit=1)
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        provided_signature = base64.urlsafe_b64decode(signature_b64.encode("utf-8"))
        expected_signature = hmac.new(self.token_key, payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(provided_signature, expected_signature):
            raise AuthenticationError("Invalid token signature.")
        payload = json.loads(payload_bytes.decode("utf-8"))
        return self.get_user_by_id(payload["user_id"])

