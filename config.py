"""Central configuration for the audit system.

All values can be overridden by environment variables (see .env.example).
The same module is imported by the gateway, the node server, the web UI,
and the demo scripts so paths and URLs stay consistent.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv optional at runtime
    pass


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
NODES_DATA_DIR = DATA_DIR / "nodes"
GATEWAY_DATA_DIR = DATA_DIR / "gateway"
USERS_FILE = GATEWAY_DATA_DIR / "users.json"
GATEWAY_KEYS_FILE = GATEWAY_DATA_DIR / "keys.json"

NODE_IDS = ["node_a", "node_b", "node_c"]
ALLOWED_ACTIONS = ["create", "delete", "change", "query", "print", "copy"]
ROLES = ["patient", "doctor", "audit_company", "admin"]

GATEWAY_HOST = os.environ.get("GATEWAY_HOST", "127.0.0.1")
GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "5310"))
GATEWAY_JWT_SECRET_ENV = os.environ.get("GATEWAY_JWT_SECRET")  # may be None; auto-generated otherwise

# Postgres is mandatory.  The gateway refuses to start without DATABASE_URL.
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg://audit:audit@127.0.0.1:5432/audit",
)
# KEK used to encrypt private-key blobs at rest in the users table.  Auto-
# generated and persisted next to the JWT secret if not supplied.
GATEWAY_MASTER_KEY_ENV = os.environ.get("GATEWAY_MASTER_KEY")
MASTER_KEY_FILE = GATEWAY_DATA_DIR / "master.key"
# Patient self-signup is enabled by default in dev; flip the env to disable.
ALLOW_PATIENT_SIGNUP = os.environ.get("ALLOW_PATIENT_SIGNUP", "1") == "1"

NODE_URLS = {
    "node_a": os.environ.get("NODE_A_URL", "http://127.0.0.1:5311"),
    "node_b": os.environ.get("NODE_B_URL", "http://127.0.0.1:5312"),
    "node_c": os.environ.get("NODE_C_URL", "http://127.0.0.1:5313"),
}

NODE_ID = os.environ.get("NODE_ID", "node_a")
NODE_HOST = os.environ.get("NODE_HOST", "127.0.0.1")
NODE_PORT = int(os.environ.get("NODE_PORT", "5311"))

QUORUM = int(os.environ.get("QUORUM", "2"))

JWT_ALGORITHM = "HS256"
JWT_TTL_SECONDS = 60 * 30  # 30 minutes

GENESIS_HASH = "0" * 64


def node_data_dir(node_id: str) -> Path:
    return NODES_DATA_DIR / node_id


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    GATEWAY_DATA_DIR.mkdir(parents=True, exist_ok=True)
    NODES_DATA_DIR.mkdir(parents=True, exist_ok=True)
    for nid in NODE_IDS:
        node_data_dir(nid).mkdir(parents=True, exist_ok=True)
