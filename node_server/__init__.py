"""Independent audit-log node server (Flask).

Each running instance of this server is *one* of the three independent
storage replicas in our decentralised system.  Three of these processes
plus the gateway form the full deployment.  Each node:

- has its own Ed25519 keypair (kept under data/nodes/<node_id>/),
- persists blocks to its own append-only chain.jsonl file,
- accepts candidate blocks from the gateway and returns an endorsement
  signed with the node's key,
- exposes a small HTTP API the gateway uses to read the chain and
  cross-check integrity.
"""

from .app import create_app

__all__ = ["create_app"]
