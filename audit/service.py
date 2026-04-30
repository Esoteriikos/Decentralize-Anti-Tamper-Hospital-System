from datetime import datetime, timedelta
from typing import Any

from config import ALLOWED_ACTIONS, NODE_IDS
from crypto import CryptoManager
from errors import AuthorizationError, IntegrityError, ValidationError
from models import User
from nodes import NodeService


class AuditService:
    def __init__(self, crypto_manager: CryptoManager, node_service: NodeService) -> None:
        self.crypto_manager = crypto_manager
        self.node_service = node_service

    def create_audit_record(
        self,
        actor: User,
        patient_id: str,
        action_type: str,
        details: str,
        timestamp: str | None = None,
    ) -> dict[str, str]:
        if actor.role not in {"doctor", "admin"}:
            raise AuthorizationError("Only doctors or admins can generate new audit events.")
        if action_type not in ALLOWED_ACTIONS:
            raise ValidationError(f"Unsupported action type: {action_type}")

        event_timestamp = timestamp or datetime.utcnow().isoformat(timespec="seconds") + "Z"
        sensitive_payload = {
            "timestamp": event_timestamp,
            "patient_id": patient_id,
            "user_id": actor.user_id,
            "action_type": action_type,
            "details": details,
        }

        encrypted = self.crypto_manager.encrypt_sensitive_payload(sensitive_payload)
        record_id = f"AUDIT-{self.node_service.get_record_count() + 1:04d}"
        previous_hash = self.node_service.get_latest_hash()
        hash_fields = {
            "record_id": record_id,
            "previous_hash": previous_hash,
            "nonce": encrypted["nonce"],
            "ciphertext": encrypted["ciphertext"],
            "tag": encrypted["tag"],
        }
        current_hash = self.crypto_manager.compute_record_hash(hash_fields)

        record = {
            "record_id": record_id,
            "nonce": encrypted["nonce"],
            "ciphertext": encrypted["ciphertext"],
            "tag": encrypted["tag"],
            "previous_hash": previous_hash,
            "current_hash": current_hash,
        }
        self.node_service.append_record_to_all_nodes(record)
        return {"record_id": record_id, **sensitive_payload}

    def query_patient_records(self, requester: User, patient_id: str) -> list[dict[str, Any]]:
        if requester.role == "patient" and requester.patient_id != patient_id:
            raise AuthorizationError("Patients may only query their own audit records.")
        if requester.role not in {"patient", "audit_company", "admin"}:
            raise AuthorizationError("Only patients, audit companies, or admins may query audit records.")

        return [record for record in self._decrypt_records_from_primary() if record["patient_id"] == patient_id]

    def query_all_patient_records(self, requester: User) -> list[dict[str, Any]]:
        if requester.role not in {"audit_company", "admin"}:
            raise AuthorizationError("Only audit companies or admins may query all audit records.")
        return self._decrypt_records_from_primary()

    def verify_integrity(self) -> dict[str, Any]:
        ledgers = self.node_service.get_all_ledgers()
        verification = {
            "per_node": {},
            "network_consistent": True,
            "network_mismatches": [],
        }
        baseline_records = [self._canonicalize(record) for record in ledgers[NODE_IDS[0]]["records"]]

        for node_id, ledger in ledgers.items():
            verification["per_node"][node_id] = self._verify_single_node(node_id, ledger["records"])
            candidate_records = [self._canonicalize(record) for record in ledger["records"]]
            if candidate_records != baseline_records:
                verification["network_consistent"] = False
                verification["network_mismatches"].append(
                    f"{node_id} does not match {NODE_IDS[0]} at the ledger content level."
                )

        verification["all_checks_passed"] = verification["network_consistent"] and all(
            node_report["valid"] for node_report in verification["per_node"].values()
        )
        return verification

    def _decrypt_records_from_primary(self) -> list[dict[str, Any]]:
        records = self.node_service.read_ledger(NODE_IDS[0])["records"]
        decrypted_records = []
        for record in records:
            payload = self.crypto_manager.decrypt_sensitive_payload(record)
            decrypted_records.append(
                {
                    "record_id": record["record_id"],
                    "timestamp": payload["timestamp"],
                    "patient_id": payload["patient_id"],
                    "user_id": payload["user_id"],
                    "action_type": payload["action_type"],
                    "details": payload["details"],
                    "node_reference": NODE_IDS[0],
                }
            )
        return decrypted_records

    def _verify_single_node(self, node_id: str, records: list[dict]) -> dict[str, Any]:
        report = {
            "node_id": node_id,
            "record_count": len(records),
            "valid_hashes": True,
            "valid_chain": True,
            "decryptable_records": True,
            "issues": [],
            "valid": True,
        }

        expected_previous_hash = "GENESIS"
        for record in records:
            hash_fields = {
                "record_id": record["record_id"],
                "previous_hash": record["previous_hash"],
                "nonce": record["nonce"],
                "ciphertext": record["ciphertext"],
                "tag": record["tag"],
            }
            expected_hash = self.crypto_manager.compute_record_hash(hash_fields)
            if expected_hash != record["current_hash"]:
                report["valid_hashes"] = False
                report["issues"].append(
                    f"{record['record_id']}: stored current_hash does not match recomputed SHA-256 value."
                )

            if record["previous_hash"] != expected_previous_hash:
                report["valid_chain"] = False
                report["issues"].append(
                    f"{record['record_id']}: previous_hash link is broken (expected {expected_previous_hash})."
                )

            try:
                self.crypto_manager.decrypt_sensitive_payload(record)
            except Exception as exc:  # noqa: BLE001 - demo-friendly integrity reporting
                report["decryptable_records"] = False
                report["issues"].append(f"{record['record_id']}: AES-GCM authentication failed ({exc}).")

            expected_previous_hash = record["current_hash"]

        report["valid"] = report["valid_hashes"] and report["valid_chain"] and report["decryptable_records"]
        return report

    @staticmethod
    def _canonicalize(record: dict) -> dict:
        canonical = dict(record)
        canonical.pop("node_id", None)
        return canonical
