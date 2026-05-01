"""Block + record schema used by both gateway and node server.

A block carries exactly one audit record in this prototype, but the
schema names ("merkle_root", "records") are kept so the design generalises
to batched blocks.  Every block goes through three stages:

1. *Candidate* - built and signed by the gateway, missing node_endorsements.
2. *Endorsed* - one node has validated and added its endorsement.
3. *Committed* - quorum reached; gateway has persisted endorsements from
   ≥QUORUM nodes; the same finalised block is stored on every reachable
   node.

The bytes that get hashed and signed are the canonical JSON of the
"header" view, which excludes node_endorsements (those are computed *over*
the header and appended after).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WrappedKey:
    reader_id: str
    alg: str  # e.g. "RSA-OAEP-SHA256"
    value: str  # b64

    def to_dict(self) -> dict:
        return {"reader_id": self.reader_id, "alg": self.alg, "value": self.value}


@dataclass
class RecordPayload:
    """The encrypted half of a block."""

    record_id: str
    patient_id_hash: str  # sha256 hex of patient_id, lets readers index without leaking
    nonce: str  # b64
    ciphertext: str  # b64
    tag: str  # b64
    wrapped_keys: list[dict]  # list[WrappedKey.to_dict()]

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "patient_id_hash": self.patient_id_hash,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "tag": self.tag,
            "wrapped_keys": list(self.wrapped_keys),
        }


@dataclass
class ActorSignature:
    signer: str  # user_id (doctor or admin who created the record)
    alg: str  # "Ed25519"
    value: str  # b64

    def to_dict(self) -> dict:
        return {"signer": self.signer, "alg": self.alg, "value": self.value}


@dataclass
class NodeEndorsement:
    node_id: str
    alg: str  # "Ed25519"
    value: str  # b64 over the same header bytes the actor signed

    def to_dict(self) -> dict:
        return {"node_id": self.node_id, "alg": self.alg, "value": self.value}


@dataclass
class Block:
    version: int
    block_id: str
    height: int
    timestamp: str
    previous_hash: str
    record: dict  # RecordPayload.to_dict()
    actor_signature: dict  # ActorSignature.to_dict()
    current_hash: str = ""
    node_endorsements: list[dict] = field(default_factory=list)

    def header_for_hash(self) -> dict:
        """The view that previous_hash chains over and that signers sign.

        Excludes current_hash (output of the hash) and node_endorsements
        (added after signing).
        """

        return {
            "version": self.version,
            "block_id": self.block_id,
            "height": self.height,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "record": self.record,
            "actor_signature": self.actor_signature,
        }

    def to_dict(self) -> dict:
        d = self.header_for_hash()
        d["current_hash"] = self.current_hash
        d["node_endorsements"] = list(self.node_endorsements)
        return d

    @classmethod
    def from_dict(cls, raw: dict) -> "Block":
        return cls(
            version=raw["version"],
            block_id=raw["block_id"],
            height=raw["height"],
            timestamp=raw["timestamp"],
            previous_hash=raw["previous_hash"],
            record=raw["record"],
            actor_signature=raw["actor_signature"],
            current_hash=raw.get("current_hash", ""),
            node_endorsements=list(raw.get("node_endorsements", [])),
        )
