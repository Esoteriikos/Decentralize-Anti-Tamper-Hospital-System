"""Per-record envelope encryption.

Workflow on the gateway (write side):
    1. Build the sensitive plaintext (timestamp, patient_id, user_id, ...).
    2. Generate a fresh AES-256 data key.
    3. AES-GCM encrypt the plaintext under that data key.
    4. RSA-OAEP wrap the data key once for each authorised reader (the
       patient who owns the record + every audit company + admin).
    5. Discard the data key.

The wrapped keys travel inside the block so any authorised reader can
recover the data key by decrypting their own wrapped copy with their
private RSA key.  The gateway itself never holds the data keys long
enough to read past records, and no single AES key protects everything.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable, Mapping

from common import b64d, b64e, canonical_bytes
from crypto.primitives import (
    aesgcm_decrypt,
    aesgcm_encrypt,
    rsa_load_private_pem,
    rsa_load_public_pem,
    rsa_oaep_unwrap,
    rsa_oaep_wrap,
    sha256_hex,
)


@dataclass
class EnvelopeResult:
    nonce_b64: str
    ciphertext_b64: str
    tag_b64: str
    wrapped_keys: list[dict]
    patient_id_hash: str


def encrypt_record_payload(
    plaintext_payload: dict,
    patient_id: str,
    reader_public_pems: Mapping[str, str],
) -> EnvelopeResult:
    """Encrypt and wrap for every reader.

    `reader_public_pems` maps `user_id -> RSA public key (PEM)`.  Every
    entry receives a wrapped copy of the freshly generated data key.
    """

    if not reader_public_pems:
        raise ValueError("Need at least one reader to wrap the data key for.")

    data_key = os.urandom(32)
    plaintext = canonical_bytes(plaintext_payload)
    nonce, ciphertext, tag = aesgcm_encrypt(data_key, plaintext)

    wrapped: list[dict] = []
    for reader_id, pem in reader_public_pems.items():
        pub = rsa_load_public_pem(pem)
        wrapped_key = rsa_oaep_wrap(pub, data_key)
        wrapped.append({"reader_id": reader_id, "alg": "RSA-OAEP-SHA256", "value": b64e(wrapped_key)})

    return EnvelopeResult(
        nonce_b64=b64e(nonce),
        ciphertext_b64=b64e(ciphertext),
        tag_b64=b64e(tag),
        wrapped_keys=wrapped,
        patient_id_hash=sha256_hex(patient_id.encode("utf-8")),
    )


def decrypt_record_payload(record: dict, reader_id: str, reader_private_pem: str) -> dict:
    """Recover the plaintext payload as `reader_id`.

    Raises if the reader has no wrapped key in the block, or if the
    AES-GCM authentication tag fails (which is the immutability check
    for the encrypted half of the block).
    """

    import json

    private_key = rsa_load_private_pem(reader_private_pem)
    wrapped_keys: Iterable[dict] = record.get("wrapped_keys", [])

    target = next((wk for wk in wrapped_keys if wk["reader_id"] == reader_id), None)
    if target is None:
        raise PermissionError(f"No wrapped key for reader {reader_id} in this record.")

    data_key = rsa_oaep_unwrap(private_key, b64d(target["value"]))
    nonce = b64d(record["nonce"])
    ciphertext = b64d(record["ciphertext"])
    tag = b64d(record["tag"])
    plaintext = aesgcm_decrypt(data_key, nonce, ciphertext, tag)
    return json.loads(plaintext.decode("utf-8"))
