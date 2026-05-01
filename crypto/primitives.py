"""Low-level cryptographic primitives wrapped behind project-friendly names.

Why each primitive is here:

- AES-256-GCM: confidentiality + integrity of the audit-record payload.
  GCM's authentication tag means tampering with the ciphertext is caught
  by the decryption call itself, before the plaintext is exposed.
- RSA-OAEP-2048 (SHA-256): wraps the per-record AES key for each
  authorised reader.  Patient + audit companies + admin each receive
  their own wrapped copy of the same data key, so no shared master key
  needs to live anywhere.
- Ed25519: actor signatures (doctor/admin who created the record) and
  node endorsement signatures.  Small, fast, deterministic.
- SHA-256: block hash chain plus patient_id indexing hash.
- scrypt (stdlib): password hashing.  Memory-hard, no third-party
  dependency required.

All primitives operate on bytes; the modules above translate to and
from base64 strings for JSON storage.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import b64d, b64e


# ---------- Hashing ----------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def chain_hash(canonical_header_bytes: bytes) -> str:
    """Hash used to link blocks in the chain."""

    return sha256_hex(canonical_header_bytes)


# ---------- AES-256-GCM ----------


def aesgcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> Tuple[bytes, bytes, bytes]:
    """Returns (nonce, ciphertext, tag).  Tag is the trailing 16 bytes of GCM output."""

    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    blob = aesgcm.encrypt(nonce, plaintext, associated_data)
    ciphertext, tag = blob[:-16], blob[-16:]
    return nonce, ciphertext, tag


def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes | None = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, associated_data)


# ---------- RSA-OAEP-2048 ----------


def rsa_generate_keypair(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def rsa_public_pem(private_key: rsa.RSAPrivateKey) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def rsa_private_pem(private_key: rsa.RSAPrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def rsa_load_public_pem(pem: str) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem.encode("ascii"))  # type: ignore[return-value]


def rsa_load_private_pem(pem: str) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem.encode("ascii"), password=None)  # type: ignore[return-value]


def _oaep_padding() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def rsa_oaep_wrap(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    return public_key.encrypt(plaintext, _oaep_padding())


def rsa_oaep_unwrap(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decrypt(ciphertext, _oaep_padding())


# ---------- Ed25519 ----------


def ed25519_generate_keypair() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def ed25519_public_b64(private_key: ed25519.Ed25519PrivateKey) -> str:
    pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64e(pub)


def ed25519_private_b64(private_key: ed25519.Ed25519PrivateKey) -> str:
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return b64e(raw)


def ed25519_load_public_b64(value: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(b64d(value))


def ed25519_load_private_b64(value: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(b64d(value))


def ed25519_sign(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def ed25519_verify(public_key: ed25519.Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


# ---------- Password hashing (scrypt) ----------

_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_SALT_LEN = 16


def scrypt_hash(password: str) -> str:
    salt = secrets.token_bytes(_SCRYPT_SALT_LEN)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${b64e(salt)}${b64e(dk)}"


def scrypt_verify(password: str, encoded: str) -> bool:
    try:
        scheme, n_s, r_s, p_s, salt_b64, dk_b64 = encoded.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    n, r, p = int(n_s), int(r_s), int(p_s)
    salt = b64d(salt_b64)
    expected = b64d(dk_b64)
    candidate = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected))
    return hmac.compare_digest(candidate, expected)
