import base64
import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import SECRETS_FILE
from storage import read_json, write_json


class CryptoManager:
    def __init__(self) -> None:
        secrets = read_json(SECRETS_FILE, default={})
        if "aes_key" not in secrets:
            secrets["aes_key"] = base64.b64encode(AESGCM.generate_key(bit_length=256)).decode("utf-8")
        if "token_key" not in secrets:
            secrets["token_key"] = base64.b64encode(os.urandom(32)).decode("utf-8")
        write_json(SECRETS_FILE, secrets)

        self.aes_key = base64.b64decode(secrets["aes_key"])
        self.token_key = base64.b64decode(secrets["token_key"])
        self.aesgcm = AESGCM(self.aes_key)

    def encrypt_sensitive_payload(self, payload: dict[str, Any]) -> dict[str, str]:
        # The full audit payload is encrypted before replication so it stays confidential
        # during simulated transit and while stored on each node.
        nonce = os.urandom(12)
        plaintext = json.dumps(payload, sort_keys=True).encode("utf-8")
        encrypted = self.aesgcm.encrypt(nonce, plaintext, associated_data=None)
        ciphertext = encrypted[:-16]
        tag = encrypted[-16:]
        return {
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
        }

    def decrypt_sensitive_payload(self, encrypted_payload: dict[str, str]) -> dict[str, Any]:
        nonce = base64.b64decode(encrypted_payload["nonce"])
        ciphertext = base64.b64decode(encrypted_payload["ciphertext"])
        tag = base64.b64decode(encrypted_payload["tag"])
        plaintext = self.aesgcm.decrypt(nonce, ciphertext + tag, associated_data=None)
        return json.loads(plaintext.decode("utf-8"))

    @staticmethod
    def compute_record_hash(record_fields: dict[str, str]) -> str:
        canonical = json.dumps(record_fields, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

