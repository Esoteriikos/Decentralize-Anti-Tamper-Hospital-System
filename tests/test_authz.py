"""Authorization matrix tests.

These run entirely in-process with the gateway's policy module + a
MockNodeClient so we can validate the role decisions without spinning
real HTTP servers.
"""

from __future__ import annotations

import threading

import pytest

from auth.policy import (
    can_create_record,
    can_manage_users,
    can_query_all,
    can_query_patient,
    can_verify_integrity,
)


@pytest.mark.parametrize(
    "role, expected",
    [("patient", False), ("doctor", True), ("audit_company", False), ("admin", True)],
)
def test_can_create_record(role, expected):
    assert can_create_record(role) is expected


def test_patient_can_only_query_self():
    assert can_query_patient("patient", "P001", "P001") is True
    assert can_query_patient("patient", "P001", "P002") is False


def test_audit_company_can_query_any_patient():
    assert can_query_patient("audit_company", None, "P007") is True


def test_doctor_cannot_query():
    assert can_query_patient("doctor", None, "P001") is False
    assert can_query_all("doctor") is False


def test_only_audit_or_admin_can_verify():
    assert can_verify_integrity("admin") is True
    assert can_verify_integrity("audit_company") is True
    assert can_verify_integrity("doctor") is False
    assert can_verify_integrity("patient") is False


def test_only_admin_can_manage_users():
    assert can_manage_users("admin") is True
    assert can_manage_users("audit_company") is False


# ------- end-to-end pieces using a real UserStore + AuditService against fake nodes -------


class FakeNode:
    """Stub that mimics a node's append-only chain + endorsement."""

    def __init__(self, node_id: str):
        from gateway.node_client import NodeStatus
        from node_server.chain import Chain
        from node_server.keys import load_or_create_node_keypair

        self.node_id = node_id
        self.chain = Chain(node_id)
        self.private = load_or_create_node_keypair(node_id)
        self._status_cls = NodeStatus

    def health(self):
        return self._status_cls(
            node_id=self.node_id,
            url=f"fake://{self.node_id}",
            online=True,
            head=self.chain.head_info(),
            public_key=None,
        )

    def get_blocks(self, start=1):
        return self.chain.slice_from(start)

    def get_head(self):
        return self.chain.head_info()

    def submit_block(self, block):
        from common import b64e, canonical_bytes
        from crypto.primitives import ed25519_sign

        recomputed = self.chain.validate_candidate(block)
        self.chain.append(block)
        sig = ed25519_sign(self.private, canonical_bytes(block.header_for_hash()))
        return {
            "accepted": True,
            "endorsement": {
                "node_id": self.node_id,
                "alg": "Ed25519",
                "value": b64e(sig),
                "covered_hash": recomputed,
            },
            "head": self.chain.head_info(),
        }

    def reset(self):
        self.chain.reset()


@pytest.fixture
def gateway_audit():
    from auth.user_store import UserStore
    from gateway.audit_service import AuditService
    from gateway.bootstrap import create_sample_users

    user_store = UserStore()
    create_sample_users(user_store)

    clients = {nid: FakeNode(nid) for nid in ("node_a", "node_b", "node_c")}
    return user_store, AuditService(user_store=user_store, clients=clients), clients


def test_full_flow_with_three_fake_nodes(gateway_audit):
    user_store, audit_service, clients = gateway_audit
    doctor = user_store.get("doctor_01")
    patient = user_store.get("patient_03")
    audit_co = user_store.get("audit_company_01")

    result = audit_service.create_audit_record(
        actor=doctor,
        patient_id=patient.patient_id,
        action_type="create",
        details="Initial chart",
    )
    assert result["height"] == 1
    assert len(result["endorsements"]) == 3

    # Patient can read their own record.
    rows = audit_service.query_records_for_reader(patient, patient.patient_id)
    assert len(rows) == 1
    assert rows[0]["patient_id"] == patient.patient_id
    assert rows[0]["details"] == "Initial chart"

    # Audit company can read all.
    all_rows = audit_service.query_records_for_reader(audit_co, patient_id=None)
    assert len(all_rows) == 1

    # Verification is clean.
    report = audit_service.verify_integrity()
    assert report["all_checks_passed"] is True

    # Tamper with node_b and re-verify.
    bad_block = clients["node_b"].chain.read_all()[0]
    bad_dict = bad_block.to_dict()
    bad_dict["record"]["ciphertext"] = ("B" if bad_dict["record"]["ciphertext"][0] == "A" else "A") + bad_dict["record"]["ciphertext"][1:]
    from storage import overwrite_jsonl

    overwrite_jsonl(clients["node_b"].chain.path, [bad_dict])
    report = audit_service.verify_integrity()
    assert report["all_checks_passed"] is False
    assert any(report["per_node"]["node_b"].get("issues", [])) or report["divergences"]
