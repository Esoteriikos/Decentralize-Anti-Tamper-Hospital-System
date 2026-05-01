"""Per-node key persistence."""

from __future__ import annotations

from pathlib import Path

from common import b64e
from config import node_data_dir
from crypto.primitives import (
    ed25519_generate_keypair,
    ed25519_load_private_b64,
    ed25519_private_b64,
    ed25519_public_b64,
)
from cryptography.hazmat.primitives.asymmetric import ed25519


def _key_path(node_id: str) -> Path:
    return node_data_dir(node_id) / "node_key.b64"


def _public_path(node_id: str) -> Path:
    return node_data_dir(node_id) / "node_public.b64"


def load_or_create_node_keypair(node_id: str) -> ed25519.Ed25519PrivateKey:
    priv_path = _key_path(node_id)
    if priv_path.exists():
        return ed25519_load_private_b64(priv_path.read_text(encoding="utf-8").strip())

    priv = ed25519_generate_keypair()
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    priv_path.write_text(ed25519_private_b64(priv), encoding="utf-8")
    _public_path(node_id).write_text(ed25519_public_b64(priv), encoding="utf-8")
    return priv


def get_public_b64(node_id: str) -> str:
    pub_path = _public_path(node_id)
    if pub_path.exists():
        return pub_path.read_text(encoding="utf-8").strip()
    priv = load_or_create_node_keypair(node_id)
    return ed25519_public_b64(priv)
