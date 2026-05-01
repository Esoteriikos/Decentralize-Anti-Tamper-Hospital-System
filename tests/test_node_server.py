"""Lightweight HTTP round-trip test against the node server.

We start the Flask test client (no real socket) and verify that block
submission, head queries, and tamper rejection all behave correctly.
"""

from __future__ import annotations

import json

import pytest

from common import b64e, canonical_bytes
from config import GENESIS_HASH
from crypto.primitives import (
    chain_hash,
    ed25519_generate_keypair,
    ed25519_private_b64,
    ed25519_sign,
)
from models import Block


def _build_block(height: int, prev_hash: str, signer: str = "doctor_01") -> Block:
    record = {
        "record_id": f"AUDIT-{height:04d}.1",
        "patient_id_hash": "0" * 64,
        "nonce": b64e(b"x" * 12),
        "ciphertext": b64e(b"y" * 32),
        "tag": b64e(b"z" * 16),
        "wrapped_keys": [],
    }
    sig_header = {
        "version": 1,
        "block_id": f"AUDIT-{height:04d}",
        "height": height,
        "timestamp": "2026-04-30T00:00:00Z",
        "previous_hash": prev_hash,
        "record": record,
        "signer": signer,
    }
    actor_priv = ed25519_generate_keypair()
    sig_value = b64e(ed25519_sign(actor_priv, canonical_bytes(sig_header)))
    block = Block(
        version=1,
        block_id=f"AUDIT-{height:04d}",
        height=height,
        timestamp="2026-04-30T00:00:00Z",
        previous_hash=prev_hash,
        record=record,
        actor_signature={"signer": signer, "alg": "Ed25519", "value": sig_value},
    )
    block.current_hash = chain_hash(canonical_bytes(block.header_for_hash()))
    return block


@pytest.fixture
def node_client():
    from node_server.app import create_app

    app = create_app(node_id="node_a")
    app.testing = True
    return app.test_client()


def test_health_and_empty_head(node_client):
    response = node_client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["head"]["height"] == 0


def test_submit_block_chain_grows(node_client):
    b1 = _build_block(1, GENESIS_HASH)
    response = node_client.post("/blocks", data=json.dumps(b1.to_dict()), content_type="application/json")
    assert response.status_code == 201
    data = response.get_json()
    assert data["accepted"]
    assert data["head"]["height"] == 1

    b2 = _build_block(2, b1.current_hash)
    response = node_client.post("/blocks", data=json.dumps(b2.to_dict()), content_type="application/json")
    assert response.status_code == 201
    assert response.get_json()["head"]["height"] == 2


def test_submit_block_rejects_bad_prev_hash(node_client):
    b1 = _build_block(1, GENESIS_HASH)
    node_client.post("/blocks", data=json.dumps(b1.to_dict()), content_type="application/json")

    bad = _build_block(2, "deadbeef" + "0" * 56)  # wrong prev hash
    response = node_client.post("/blocks", data=json.dumps(bad.to_dict()), content_type="application/json")
    assert response.status_code in (400, 409)


def test_submit_block_rejects_bad_height(node_client):
    bad = _build_block(5, GENESIS_HASH)  # skipping heights
    response = node_client.post("/blocks", data=json.dumps(bad.to_dict()), content_type="application/json")
    assert response.status_code == 400
