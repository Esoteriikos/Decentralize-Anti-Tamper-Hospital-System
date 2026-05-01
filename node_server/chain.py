"""Append-only chain backing one node's audit ledger.

The on-disk format is JSON Lines: one block per line.  We never rewrite
prior lines.  Tampering therefore requires editing the file directly,
which is exactly the scenario the gateway's /verify endpoint catches.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from common import canonical_bytes
from config import GENESIS_HASH, node_data_dir
from crypto.primitives import chain_hash
from errors import IntegrityError, NotFoundError, ValidationError
from models import Block
from storage import append_jsonl, iter_jsonl, overwrite_jsonl


class Chain:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id
        self.path: Path = node_data_dir(node_id) / "chain.jsonl"
        self._lock = threading.RLock()

    # ---------- read ----------

    def read_all(self) -> list[Block]:
        return [Block.from_dict(item) for item in iter_jsonl(self.path)]

    def head(self) -> Optional[Block]:
        last: Optional[Block] = None
        for raw in iter_jsonl(self.path):
            last = Block.from_dict(raw)
        return last

    def head_info(self) -> dict:
        last = self.head()
        if last is None:
            return {"height": 0, "current_hash": GENESIS_HASH, "block_id": None}
        return {"height": last.height, "current_hash": last.current_hash, "block_id": last.block_id}

    def get_by_height(self, height: int) -> Block:
        for raw in iter_jsonl(self.path):
            if raw.get("height") == height:
                return Block.from_dict(raw)
        raise NotFoundError(f"No block at height {height}")

    def get_by_id(self, block_id: str) -> Block:
        for raw in iter_jsonl(self.path):
            if raw.get("block_id") == block_id:
                return Block.from_dict(raw)
        raise NotFoundError(f"No block with id {block_id}")

    def slice_from(self, start_height: int) -> list[Block]:
        out: list[Block] = []
        for raw in iter_jsonl(self.path):
            if raw.get("height", 0) >= start_height:
                out.append(Block.from_dict(raw))
        return out

    # ---------- write ----------

    def validate_candidate(self, candidate: Block) -> str:
        """Validate against current head; raise on rejection.

        Returns the canonical header bytes the candidate hashes/signs over
        (so the caller can re-use them when producing the endorsement).
        """

        head = self.head()
        expected_height = 1 if head is None else head.height + 1
        expected_prev = GENESIS_HASH if head is None else head.current_hash

        if candidate.height != expected_height:
            raise ValidationError(
                f"Wrong height: got {candidate.height}, expected {expected_height} on {self.node_id}."
            )
        if candidate.previous_hash != expected_prev:
            raise IntegrityError(
                f"previous_hash does not match {self.node_id}'s head ({expected_prev})."
            )

        header_bytes = canonical_bytes(candidate.header_for_hash())
        recomputed = chain_hash(header_bytes)
        if recomputed != candidate.current_hash:
            raise IntegrityError("current_hash does not match recomputed SHA-256 of the header.")

        return recomputed

    def append(self, block: Block) -> None:
        with self._lock:
            self.validate_candidate(block)
            append_jsonl(self.path, block.to_dict())

    def reset(self) -> None:
        with self._lock:
            overwrite_jsonl(self.path, [])

    def replace_all(self, blocks: list[Block]) -> None:
        """Used by /sync to catch up from peers.  Validates the full chain
        before persisting so a malicious peer cannot replace our chain
        with garbage."""

        prev = GENESIS_HASH
        for index, block in enumerate(blocks, start=1):
            if block.height != index:
                raise IntegrityError(f"Sync rejected: block {index} has wrong height {block.height}.")
            if block.previous_hash != prev:
                raise IntegrityError(f"Sync rejected: chain link broken at height {index}.")
            recomputed = chain_hash(canonical_bytes(block.header_for_hash()))
            if recomputed != block.current_hash:
                raise IntegrityError(f"Sync rejected: hash mismatch at height {index}.")
            prev = block.current_hash

        with self._lock:
            overwrite_jsonl(self.path, [b.to_dict() for b in blocks])
