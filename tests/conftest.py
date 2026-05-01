"""Pytest fixtures.

We isolate every test run under a tmp_path so the persistent JSON / JSONL
state from manual runs cannot leak into the test environment.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    """Per-test isolation.

    The project enforces Postgres in production but tests run against an
    ephemeral SQLite file under ``tmp_path`` so the suite stays self-contained.
    To run the suite against a real Postgres, export
    ``TEST_DATABASE_URL=postgresql+psycopg://user:pw@host/db`` -- the schema
    is recreated for every test.
    """

    project_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(project_root))

    monkeypatch.setenv("PYTHONHASHSEED", "0")

    # Database URL: prefer TEST_DATABASE_URL, fall back to SQLite per-test file.
    test_db_url = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'test.db'}"
    monkeypatch.setenv("DATABASE_URL", test_db_url)

    # Reload config so it picks up the redirected paths via patching.
    import config

    importlib.reload(config)
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "NODES_DATA_DIR", tmp_path / "data" / "nodes")
    monkeypatch.setattr(config, "GATEWAY_DATA_DIR", tmp_path / "data" / "gateway")
    monkeypatch.setattr(config, "USERS_FILE", tmp_path / "data" / "gateway" / "users.json")
    monkeypatch.setattr(config, "GATEWAY_KEYS_FILE", tmp_path / "data" / "gateway" / "keys.json")
    monkeypatch.setattr(config, "MASTER_KEY_FILE", tmp_path / "data" / "gateway" / "master.key")

    def _node_data_dir(node_id: str) -> Path:
        return tmp_path / "data" / "nodes" / node_id

    monkeypatch.setattr(config, "node_data_dir", _node_data_dir)
    config.ensure_dirs()

    # Reload modules that captured these constants at import time.  Order matters:
    # KEK depends on config; db.engine depends on config; user_store depends on db + KEK.
    for mod_name in [
        "crypto.kek",
        "db.engine",
        "db.models",
        "db",
        "auth.user_store",
        "auth.jwt_service",
        "audit_log",
        "node_server.chain",
        "node_server.keys",
        "gateway.audit_service",
        "gateway.bootstrap",
    ]:
        if mod_name in sys.modules:
            importlib.reload(sys.modules[mod_name])

    # Create schema on the fresh engine.
    from db import init_db

    init_db()

    yield tmp_path
