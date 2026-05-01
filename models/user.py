from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class User:
    """User record persisted in the gateway's users.json file.

    Only the gateway sees this struct; nodes only ever see public keys
    referenced by `user_id` inside signed blocks.
    """

    user_id: str
    username: str
    role: str
    password_hash: str  # scrypt-derived; format documented in auth.user_store
    patient_id: Optional[str] = None

    # Public halves of the user's keypairs.  Private halves are persisted
    # separately under data/gateway/private_keys/<user_id>/.
    rsa_public_pem: Optional[str] = None  # for envelope key wrapping (readers)
    ed25519_public_b64: Optional[str] = None  # for actor block signing (writers)

    failed_logins: int = 0
    locked: bool = False
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "User":
        return cls(**raw)

    def is_writer(self) -> bool:
        return self.role in {"doctor", "admin"}

    def is_reader_of(self, patient_id: str) -> bool:
        if self.role in {"audit_company", "admin"}:
            return True
        if self.role == "patient":
            return self.patient_id == patient_id
        return False
