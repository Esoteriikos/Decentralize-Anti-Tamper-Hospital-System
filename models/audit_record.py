from dataclasses import asdict, dataclass


@dataclass
class AuditRecord:
    record_id: str
    node_id: str
    nonce: str
    ciphertext: str
    tag: str
    previous_hash: str
    current_hash: str

    def to_dict(self) -> dict:
        return asdict(self)

