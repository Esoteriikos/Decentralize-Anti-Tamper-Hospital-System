from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class User:
    user_id: str
    username: str
    role: str
    password_hash: str
    patient_id: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

