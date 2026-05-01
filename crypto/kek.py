"""Key-Encryption-Key (KEK) for protecting private-key blobs at rest.

Every user's RSA-OAEP private key (used to unwrap envelope data keys) and
Ed25519 actor private key (used to sign blocks) is stored in Postgres only
after AES-256-GCM encryption under this single KEK.

Operators set the KEK via the `GATEWAY_MASTER_KEY` env var (base64-encoded
32 bytes).  If unset, the gateway generates one on first startup and persists
it under `data/gateway/master.key` -- adequate for the demo, but a production
deployment would inject this from a secret manager / KMS instead.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

from common import b64d, b64e
from config import GATEWAY_MASTER_KEY_ENV, MASTER_KEY_FILE
from crypto.primitives import aesgcm_decrypt, aesgcm_encrypt


_NONCE_LEN = 12
_TAG_LEN = 16


def _load_or_create_master_key() -> bytes:
    if GATEWAY_MASTER_KEY_ENV:
        try:
            key = base64.b64decode(GATEWAY_MASTER_KEY_ENV.encode("ascii"))
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("GATEWAY_MASTER_KEY must be base64-encoded.") from exc
        if len(key) != 32:
            raise RuntimeError("GATEWAY_MASTER_KEY must decode to exactly 32 bytes.")
        return key

    path: Path = MASTER_KEY_FILE
    if path.exists():
        return b64d(path.read_text(encoding="ascii").strip())

    key = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(b64e(key), encoding="ascii")
    try:
        os.chmod(path, 0o600)
    except OSError:
        # On Windows chmod silently no-ops; that's fine for the prototype.
        pass
    return key


_MASTER_KEY: bytes = _load_or_create_master_key()


def kek_encrypt(plaintext: bytes) -> bytes:
    """Encrypt a blob with the gateway KEK.  Output: nonce || ciphertext || tag."""

    if not plaintext:
        return b""
    nonce, ciphertext, tag = aesgcm_encrypt(_MASTER_KEY, plaintext)
    return nonce + ciphertext + tag


def kek_decrypt(blob: bytes) -> bytes:
    """Reverse of :func:`kek_encrypt`."""

    if not blob:
        return b""
    if len(blob) < _NONCE_LEN + _TAG_LEN:
        raise ValueError("KEK ciphertext is too short to contain nonce + tag.")
    nonce = blob[:_NONCE_LEN]
    tag = blob[-_TAG_LEN:]
    ciphertext = blob[_NONCE_LEN:-_TAG_LEN]
    return aesgcm_decrypt(_MASTER_KEY, nonce, ciphertext, tag)
