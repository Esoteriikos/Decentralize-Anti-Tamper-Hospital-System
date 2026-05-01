"""HTTP client wrapper around an audit node's REST API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import requests

from errors import ConsensusError, IntegrityError
from models import Block


@dataclass
class NodeStatus:
    node_id: str
    url: str
    online: bool
    head: dict
    public_key: Optional[str]
    error: Optional[str] = None


class NodeClient:
    def __init__(self, node_id: str, base_url: str, timeout: float = 3.0) -> None:
        self.node_id = node_id
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def health(self) -> NodeStatus:
        try:
            response = requests.get(f"{self.base_url}/health", timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return NodeStatus(
                node_id=self.node_id,
                url=self.base_url,
                online=True,
                head=data.get("head", {}),
                public_key=data.get("public_key"),
            )
        except requests.RequestException as exc:
            return NodeStatus(
                node_id=self.node_id,
                url=self.base_url,
                online=False,
                head={},
                public_key=None,
                error=str(exc),
            )

    def get_blocks(self, start: int = 1) -> list[Block]:
        response = requests.get(f"{self.base_url}/blocks", params={"from": start}, timeout=self.timeout)
        response.raise_for_status()
        return [Block.from_dict(item) for item in response.json().get("blocks", [])]

    def get_head(self) -> dict:
        response = requests.get(f"{self.base_url}/head", timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def submit_block(self, block: Block) -> dict:
        response = requests.post(f"{self.base_url}/blocks", json=block.to_dict(), timeout=self.timeout)
        if response.status_code in (409, 400):
            raise IntegrityError(f"Node {self.node_id} rejected block: {response.text}")
        response.raise_for_status()
        return response.json()

    def reset(self) -> None:
        requests.post(f"{self.base_url}/reset", timeout=self.timeout)

    def tamper(self, height: int, field: str = "ciphertext") -> dict:
        response = requests.post(
            f"{self.base_url}/tamper",
            json={"height": int(height), "field": field},
            timeout=self.timeout,
        )
        if response.status_code >= 400:
            raise IntegrityError(f"Node {self.node_id} refused tamper: {response.text}")
        return response.json()
