"""Round-trip tests for the cryptographic primitives + envelope."""

import os
import pytest

from common import b64d, b64e, canonical_bytes
from crypto.envelope import decrypt_record_payload, encrypt_record_payload
from crypto.primitives import (
    aesgcm_decrypt,
    aesgcm_encrypt,
    chain_hash,
    ed25519_generate_keypair,
    ed25519_public_b64,
    ed25519_load_public_b64,
    ed25519_load_private_b64,
    ed25519_private_b64,
    ed25519_sign,
    ed25519_verify,
    rsa_generate_keypair,
    rsa_load_public_pem,
    rsa_load_private_pem,
    rsa_oaep_unwrap,
    rsa_oaep_wrap,
    rsa_private_pem,
    rsa_public_pem,
    scrypt_hash,
    scrypt_verify,
    sha256_hex,
)


def test_aesgcm_roundtrip_and_tamper():
    key = os.urandom(32)
    nonce, ct, tag = aesgcm_encrypt(key, b"hello", b"associated")
    assert aesgcm_decrypt(key, nonce, ct, tag, b"associated") == b"hello"

    # Flip one byte of the tag -> decryption must fail.
    bad_tag = bytes([tag[0] ^ 0x01]) + tag[1:]
    with pytest.raises(Exception):
        aesgcm_decrypt(key, nonce, ct, bad_tag, b"associated")


def test_rsa_oaep_wrap_unwrap():
    priv = rsa_generate_keypair(bits=2048)
    pub_pem = rsa_public_pem(priv)
    priv_pem = rsa_private_pem(priv)

    secret = os.urandom(32)
    wrapped = rsa_oaep_wrap(rsa_load_public_pem(pub_pem), secret)
    assert rsa_oaep_unwrap(rsa_load_private_pem(priv_pem), wrapped) == secret


def test_ed25519_sign_verify():
    priv = ed25519_generate_keypair()
    msg = b"the gateway broadcasts blocks"
    sig = ed25519_sign(priv, msg)
    pub = ed25519_load_public_b64(ed25519_public_b64(priv))
    assert ed25519_verify(pub, msg, sig)
    assert not ed25519_verify(pub, msg + b"x", sig)


def test_ed25519_persisted_keypair_matches():
    priv = ed25519_generate_keypair()
    priv_b64 = ed25519_private_b64(priv)
    reloaded = ed25519_load_private_b64(priv_b64)
    assert ed25519_public_b64(reloaded) == ed25519_public_b64(priv)


def test_chain_hash_determinism():
    payload = {"a": 1, "b": [2, 3], "c": "x"}
    assert chain_hash(canonical_bytes(payload)) == chain_hash(canonical_bytes({"c": "x", "b": [2, 3], "a": 1}))


def test_sha256_hex_known_value():
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_scrypt_password_hash_roundtrip():
    encoded = scrypt_hash("hunter2")
    assert scrypt_verify("hunter2", encoded)
    assert not scrypt_verify("wrong", encoded)


def test_envelope_encrypt_decrypt_for_each_reader():
    readers: dict[str, str] = {}
    private_pems: dict[str, str] = {}
    for reader_id in ("patient_03", "audit_company_01", "audit_company_02", "admin_01"):
        priv = rsa_generate_keypair(bits=2048)
        readers[reader_id] = rsa_public_pem(priv)
        private_pems[reader_id] = rsa_private_pem(priv)

    payload = {"timestamp": "now", "patient_id": "P003", "user_id": "doctor_01", "action_type": "create", "details": "ok"}
    envelope = encrypt_record_payload(payload, "P003", readers)

    record = {
        "nonce": envelope.nonce_b64,
        "ciphertext": envelope.ciphertext_b64,
        "tag": envelope.tag_b64,
        "wrapped_keys": envelope.wrapped_keys,
    }

    for reader_id, priv_pem in private_pems.items():
        out = decrypt_record_payload(record, reader_id, priv_pem)
        assert out == payload

    # Reader not in wrapped_keys cannot decrypt.
    other = rsa_generate_keypair(bits=2048)
    other_priv_pem = rsa_private_pem(other)
    with pytest.raises(PermissionError):
        decrypt_record_payload(record, "stranger", other_priv_pem)


def test_envelope_tamper_detected():
    priv = rsa_generate_keypair(bits=2048)
    readers = {"patient_01": rsa_public_pem(priv)}
    envelope = encrypt_record_payload({"x": 1}, "P001", readers)
    # Flip first b64 character of ciphertext.
    flipped = ("B" if envelope.ciphertext_b64[0] == "A" else "A") + envelope.ciphertext_b64[1:]
    record = {
        "nonce": envelope.nonce_b64,
        "ciphertext": flipped,
        "tag": envelope.tag_b64,
        "wrapped_keys": envelope.wrapped_keys,
    }
    with pytest.raises(Exception):
        decrypt_record_payload(record, "patient_01", rsa_private_pem(priv))
