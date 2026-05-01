"""Audit-record service running inside the gateway.

Responsibilities:

- Construct sensitive payloads from doctor / admin requests.
- Apply per-record envelope encryption via crypto.envelope.
- Sign the block header with the actor's Ed25519 key.
- Broadcast to all node servers and require a QUORUM of accepting
  responses before declaring the block committed.
- Collect node endorsements into data/gateway/endorsements.jsonl so the
  /verify endpoint can present cross-node evidence to auditors.
- Read records back from a quorum-majority chain when answering
  patient/audit-company queries.
"""

from __future__ import annotations

import threading
from collections import Counter
from typing import Iterable, Optional

from common import b64e, canonical_bytes, utc_now_iso
from config import (
    ALLOWED_ACTIONS,
    GATEWAY_DATA_DIR,
    GENESIS_HASH,
    NODE_IDS,
    NODE_URLS,
    QUORUM,
    ensure_dirs,
)
from crypto.envelope import decrypt_record_payload, encrypt_record_payload
from crypto.primitives import (
    chain_hash,
    ed25519_load_private_b64,
    ed25519_load_public_b64,
    ed25519_sign,
    ed25519_verify,
    sha256_hex,
)
from errors import (
    AuthorizationError,
    ConsensusError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from models import Block, User
from storage import append_jsonl, iter_jsonl

from .node_client import NodeClient, NodeStatus


_ENDORSEMENT_LOG = GATEWAY_DATA_DIR / "endorsements.jsonl"


class AuditService:
    def __init__(self, user_store, clients: Optional[dict[str, NodeClient]] = None) -> None:
        ensure_dirs()
        self.user_store = user_store
        self.clients: dict[str, NodeClient] = clients or {
            node_id: NodeClient(node_id, NODE_URLS[node_id]) for node_id in NODE_IDS
        }
        self._lock = threading.Lock()

    # ---------- node fan-out helpers ----------

    def node_statuses(self) -> list[NodeStatus]:
        return [client.health() for client in self.clients.values()]

    def _agreed_head(self) -> tuple[int, str]:
        """Pick the head height + hash that a majority of online nodes agree on.

        If no majority exists yet (e.g. divergence), fall back to (0, GENESIS).
        """

        statuses = self.node_statuses()
        candidates = [(s.head.get("height", 0), s.head.get("current_hash", GENESIS_HASH)) for s in statuses if s.online]
        if not candidates:
            return 0, GENESIS_HASH
        counter = Counter(candidates)
        best, count = counter.most_common(1)[0]
        if count >= QUORUM:
            return best
        # No quorum agreement: pick the highest-height candidate to make progress
        # but flag this in /verify (the gateway will surface the divergence).
        best = max(candidates, key=lambda hh: hh[0])
        return best

    # ---------- writes ----------

    def create_audit_record(self, actor: User, patient_id: str, action_type: str, details: str) -> dict:
        if not actor.is_writer():
            raise AuthorizationError("Only doctors or admins can generate audit records.")
        if action_type not in ALLOWED_ACTIONS:
            raise ValidationError(f"Unsupported action type: {action_type}")
        if not patient_id:
            raise ValidationError("patient_id is required.")

        with self._lock:
            agreed_height, agreed_hash = self._agreed_head()
            new_height = agreed_height + 1
            block_id = f"AUDIT-{new_height:04d}"

            sensitive = {
                "timestamp": utc_now_iso(),
                "patient_id": patient_id,
                "user_id": actor.user_id,
                "action_type": action_type,
                "details": details,
            }
            reader_pems = self.user_store.all_reader_pems(patient_id)
            if not reader_pems:
                raise ValidationError(
                    f"No registered readers for patient {patient_id}; create the patient and audit companies first."
                )
            envelope = encrypt_record_payload(sensitive, patient_id, reader_pems)

            record = {
                "record_id": f"{block_id}.1",
                "patient_id_hash": envelope.patient_id_hash,
                "nonce": envelope.nonce_b64,
                "ciphertext": envelope.ciphertext_b64,
                "tag": envelope.tag_b64,
                "wrapped_keys": envelope.wrapped_keys,
            }

            actor_priv_b64 = self.user_store.actor_private_b64(actor.user_id)
            actor_priv = ed25519_load_private_b64(actor_priv_b64)

            block = Block(
                version=1,
                block_id=block_id,
                height=new_height,
                timestamp=sensitive["timestamp"],
                previous_hash=agreed_hash,
                record=record,
                actor_signature={},
            )

            # The actor signs the header bytes that exclude actor_signature itself
            # (otherwise the signature would have to sign over itself).  We use a
            # placeholder header view for signing.
            sig_header = {
                "version": block.version,
                "block_id": block.block_id,
                "height": block.height,
                "timestamp": block.timestamp,
                "previous_hash": block.previous_hash,
                "record": block.record,
                "signer": actor.user_id,
            }
            sig_bytes = canonical_bytes(sig_header)
            actor_sig_value = b64e(ed25519_sign(actor_priv, sig_bytes))
            block.actor_signature = {"signer": actor.user_id, "alg": "Ed25519", "value": actor_sig_value}

            block.current_hash = chain_hash(canonical_bytes(block.header_for_hash()))

            # Broadcast.
            endorsements: list[dict] = []
            errors: dict[str, str] = {}
            for node_id, client in self.clients.items():
                try:
                    response = client.submit_block(block)
                    endorsements.append(response["endorsement"])
                except Exception as exc:  # noqa: BLE001 - tolerated, recorded
                    errors[node_id] = str(exc)

            if len(endorsements) < QUORUM:
                raise ConsensusError(
                    f"Quorum of {QUORUM} not reached; only {len(endorsements)} nodes accepted.  Errors: {errors}"
                )

            # Persist endorsements alongside the block id for audit/verify.
            append_jsonl(
                _ENDORSEMENT_LOG,
                {
                    "block_id": block.block_id,
                    "height": block.height,
                    "current_hash": block.current_hash,
                    "endorsements": endorsements,
                    "broadcast_errors": errors,
                    "actor_signature": block.actor_signature,
                    "sig_header": sig_header,
                },
            )

            return {
                "record_id": record["record_id"],
                "block_id": block.block_id,
                "height": block.height,
                "current_hash": block.current_hash,
                "previous_hash": block.previous_hash,
                "endorsements": endorsements,
                "broadcast_errors": errors,
                "plaintext": sensitive,  # returned to the writer for confirmation only
            }

    # ---------- reads ----------

    def query_records_for_reader(self, requester: User, patient_id: Optional[str]) -> list[dict]:
        """Return decrypted records visible to `requester`.

        If `patient_id` is supplied, results are filtered to that patient.
        """

        if requester.role == "patient":
            if patient_id and patient_id != requester.patient_id:
                raise AuthorizationError("Patients may only query their own audit records.")
            target_pid = requester.patient_id
        elif requester.role in {"audit_company", "admin"}:
            target_pid = patient_id
        else:
            raise AuthorizationError("This role cannot query audit records.")

        chain = self._majority_chain()
        target_hash = sha256_hex(target_pid.encode("utf-8")) if target_pid else None

        try:
            reader_pem = self.user_store.reader_private_pem(requester.user_id)
        except Exception as exc:
            raise AuthorizationError(f"No reader key for {requester.user_id}: {exc}")

        decrypted: list[dict] = []
        for block in chain:
            record = block.record
            if target_hash and record.get("patient_id_hash") != target_hash:
                continue
            try:
                plaintext = decrypt_record_payload(record, requester.user_id, reader_pem)
            except PermissionError:
                # reader is not in the wrapped_keys list for this record - silently skip
                continue
            except Exception as exc:  # noqa: BLE001
                # Decryption failed (tamper, stale key after reset, corrupt blob).
                # Surface as a placeholder so the UI can render "unreadable" without crashing.
                decrypted.append(
                    {
                        "record_id": record.get("record_id"),
                        "block_id": block.block_id,
                        "height": block.height,
                        "current_hash": block.current_hash,
                        "previous_hash": block.previous_hash,
                        "undecryptable": True,
                        "error": f"{type(exc).__name__}: {exc}",
                        "timestamp": None,
                        "patient_id": None,
                        "user_id": None,
                        "action_type": None,
                        "details": None,
                    }
                )
                continue
            decrypted.append(
                {
                    "record_id": record["record_id"],
                    "block_id": block.block_id,
                    "height": block.height,
                    "current_hash": block.current_hash,
                    "previous_hash": block.previous_hash,
                    **plaintext,
                }
            )
        return decrypted

    def _majority_chain(self) -> list[Block]:
        """Pull each node's chain, return the longest chain that ≥QUORUM nodes agree on."""

        per_node: dict[str, list[Block]] = {}
        for node_id, client in self.clients.items():
            try:
                per_node[node_id] = client.get_blocks(start=1)
            except Exception:
                continue

        if not per_node:
            return []

        # Group chains by their head hash + length signature.
        signatures: list[tuple[str, list[Block]]] = []
        for node_id, blocks in per_node.items():
            sig = "|".join(f"{b.height}:{b.current_hash}" for b in blocks)
            signatures.append((sig, blocks))

        counter = Counter(sig for sig, _ in signatures)
        if not counter:
            return []
        # Walk top candidates and pick the longest chain that has quorum.
        for best_sig, count in counter.most_common():
            if count >= QUORUM:
                for sig, blocks in signatures:
                    if sig == best_sig:
                        return blocks
                break

        # No quorum: return the longest available chain so reads still work,
        # but /verify will report the divergence.
        return max((b for _, b in signatures), key=len, default=[])

    # ---------- integrity verification ----------

    def verify_integrity(self) -> dict:
        per_node_report: dict[str, dict] = {}
        chains: dict[str, list[Block]] = {}

        for node_id, client in self.clients.items():
            try:
                blocks = client.get_blocks(start=1)
                chains[node_id] = blocks
                per_node_report[node_id] = self._verify_single_chain(blocks)
            except Exception as exc:
                per_node_report[node_id] = {"online": False, "error": str(exc)}

        # Cross-node consistency.
        signatures = {nid: [(b.height, b.current_hash) for b in chain] for nid, chain in chains.items()}
        max_height = max((len(s) for s in signatures.values()), default=0)
        divergences: list[dict] = []
        for height in range(1, max_height + 1):
            seen = {}
            for nid, sig in signatures.items():
                if height - 1 < len(sig):
                    seen.setdefault(sig[height - 1][1], []).append(nid)
            if len(seen) > 1:
                divergences.append({"height": height, "branches": seen})

        majority_signature = None
        if signatures:
            counter = Counter(tuple(s) for s in signatures.values())
            best, count = counter.most_common(1)[0]
            if count >= QUORUM:
                majority_signature = best

        majority_nodes = [
            nid for nid, sig in signatures.items() if majority_signature is not None and tuple(sig) == majority_signature
        ]

        all_clean = all(
            isinstance(r, dict) and r.get("valid") for r in per_node_report.values()
        )
        return {
            "per_node": per_node_report,
            "divergences": divergences,
            "network_consistent": not divergences,
            "majority_nodes": majority_nodes,
            "majority_height": len(majority_signature) if majority_signature else 0,
            "all_checks_passed": all_clean and not divergences,
        }

    def _verify_single_chain(self, blocks: list[Block]) -> dict:
        report = {
            "online": True,
            "block_count": len(blocks),
            "valid_chain": True,
            "valid_hashes": True,
            "valid_actor_signatures": True,
            "issues": [],
            "valid": True,
        }
        prev = GENESIS_HASH
        actor_pubkeys = self._actor_public_index()

        for index, block in enumerate(blocks, start=1):
            if block.height != index:
                report["valid_chain"] = False
                report["issues"].append(f"{block.block_id}: wrong height {block.height} (expected {index})")
            if block.previous_hash != prev:
                report["valid_chain"] = False
                report["issues"].append(f"{block.block_id}: previous_hash link broken (expected {prev})")
            recomputed = chain_hash(canonical_bytes(block.header_for_hash()))
            if recomputed != block.current_hash:
                report["valid_hashes"] = False
                report["issues"].append(f"{block.block_id}: current_hash mismatch (recomputed {recomputed})")
            # actor signature
            sig = block.actor_signature or {}
            signer = sig.get("signer")
            sig_value = sig.get("value")
            sig_header = {
                "version": block.version,
                "block_id": block.block_id,
                "height": block.height,
                "timestamp": block.timestamp,
                "previous_hash": block.previous_hash,
                "record": block.record,
                "signer": signer,
            }
            pub = actor_pubkeys.get(signer or "")
            if pub is None:
                report["valid_actor_signatures"] = False
                report["issues"].append(f"{block.block_id}: unknown signer {signer}")
            else:
                from common import b64d

                ok = ed25519_verify(ed25519_load_public_b64(pub), canonical_bytes(sig_header), b64d(sig_value or ""))
                if not ok:
                    report["valid_actor_signatures"] = False
                    report["issues"].append(f"{block.block_id}: actor signature failed verification")

            prev = block.current_hash

        report["valid"] = (
            report["valid_chain"] and report["valid_hashes"] and report["valid_actor_signatures"]
        )
        return report

    def _actor_public_index(self) -> dict[str, str]:
        return {
            user.user_id: user.ed25519_public_b64
            for user in self.user_store.list_users()
            if user.ed25519_public_b64
        }

    # ---------- helpers used by the web UI ----------

    def read_endorsement_log(self, filter_signer: Optional[str] = None, limit: Optional[int] = None) -> list[dict]:
        """Return entries from data/gateway/endorsements.jsonl, newest first.

        Each entry contains the canonical sig_header (which carries the
        signer + plaintext block metadata - NOT the encrypted payload),
        the actor signature, the per-node endorsements, and any broadcast
        errors.  The doctor dashboard uses this to show "my recent writes"
        without needing read access to the encrypted record itself.
        """

        entries = list(iter_jsonl(_ENDORSEMENT_LOG))
        if filter_signer:
            entries = [e for e in entries if (e.get("sig_header") or {}).get("signer") == filter_signer]
        entries.reverse()
        if limit:
            entries = entries[:limit]
        return entries

    def list_blocks_per_node(self) -> dict[str, dict]:
        """Pull every node's chain so the web UI can render side-by-side ledgers.

        Returned shape: {node_id: {"online": bool, "blocks": [block_dict, ...], "error": str|None}}
        """

        out: dict[str, dict] = {}
        for node_id, client in self.clients.items():
            try:
                blocks = client.get_blocks(start=1)
                out[node_id] = {
                    "online": True,
                    "blocks": [b.to_dict() for b in blocks],
                    "error": None,
                    "url": client.base_url,
                }
            except Exception as exc:  # noqa: BLE001
                out[node_id] = {"online": False, "blocks": [], "error": str(exc), "url": client.base_url}
        return out

    def get_record_detail(self, record_id: str, requester: User) -> dict:
        """Find a block by record_id on the majority chain and return a rich detail view.

        Decrypts the payload only if the requester is in the wrapped_keys list.
        Doctors / non-readers get the metadata view (no plaintext).
        """

        chain = self._majority_chain()
        target: Optional[Block] = None
        for block in chain:
            if block.record.get("record_id") == record_id:
                target = block
                break
        if target is None:
            raise NotFoundError(f"No record {record_id} on the majority chain.")

        # Locate this block on every node (for the per-node tab on the detail page).
        per_node_block: dict[str, dict] = {}
        for node_id, client in self.clients.items():
            try:
                blocks = client.get_blocks(start=1)
                match = next((b for b in blocks if b.record.get("record_id") == record_id), None)
                per_node_block[node_id] = {
                    "online": True,
                    "present": match is not None,
                    "current_hash": match.current_hash if match else None,
                    "matches_majority": match.current_hash == target.current_hash if match else False,
                }
            except Exception as exc:  # noqa: BLE001
                per_node_block[node_id] = {"online": False, "error": str(exc)}

        # Endorsements from the gateway log.
        endorsement_entry = next(
            (e for e in iter_jsonl(_ENDORSEMENT_LOG) if e.get("block_id") == target.block_id),
            None,
        )

        plaintext = None
        decrypt_status = "not-authorized"
        try:
            reader_pem = self.user_store.reader_private_pem(requester.user_id)
            try:
                plaintext = decrypt_record_payload(target.record, requester.user_id, reader_pem)
                decrypt_status = "ok"
            except PermissionError:
                decrypt_status = "not-in-wrapped-keys"
        except Exception:
            decrypt_status = "no-reader-key"

        return {
            "block": target.to_dict(),
            "plaintext": plaintext,
            "decrypt_status": decrypt_status,
            "per_node": per_node_block,
            "endorsement_entry": endorsement_entry,
            "wrapped_reader_ids": [w.get("reader_id") for w in target.record.get("wrapped_keys", [])],
        }

    def tamper_node_block(self, node_id: str, height: int, field: str = "ciphertext") -> dict:
        """Drive the node's /tamper endpoint.  Admin-only at the gateway."""

        client = self.clients.get(node_id)
        if client is None:
            raise ValidationError(f"Unknown node: {node_id}")
        return client.tamper(height=height, field=field)
