"""Node Flask app.

API surface (all JSON):

    GET  /health                 - liveness + node public key
    GET  /head                   - {height, current_hash, block_id}
    GET  /blocks                 - full chain (paginated optionally with ?from=N)
    GET  /blocks/<block_id>      - one block
    POST /blocks                 - submit candidate; node validates,
                                   persists, returns endorsement signature
    POST /sync                   - {peer_url}; pull missing blocks from a peer
    POST /reset                  - test-only; only enabled when ALLOW_RESET=1

The node has no concept of users or roles.  Authorisation of the client
is the gateway's job; from the node's perspective the gateway is a
trusted peer (in a real deployment we would add mutual TLS or shared
HMAC).  The node still independently validates the chain link and the
hash recomputation, so a buggy or malicious gateway cannot insert
inconsistent blocks.
"""

from __future__ import annotations

import os

import requests
from flask import Flask, jsonify, request

from common import b64e, canonical_bytes
from config import NODE_HOST, NODE_ID, NODE_PORT, ensure_dirs
from crypto.primitives import ed25519_public_b64, ed25519_sign
from errors import AuditSystemError, IntegrityError, NotFoundError, ValidationError
from models import Block

from .chain import Chain
from .keys import get_public_b64, load_or_create_node_keypair


def create_app(node_id: str | None = None) -> Flask:
    ensure_dirs()
    app = Flask(__name__)
    app.config["NODE_ID"] = node_id or NODE_ID
    app.config["CHAIN"] = Chain(app.config["NODE_ID"])
    app.config["NODE_PRIVATE"] = load_or_create_node_keypair(app.config["NODE_ID"])

    @app.errorhandler(AuditSystemError)
    def handle_known(exc):
        status = 400
        if isinstance(exc, NotFoundError):
            status = 404
        elif isinstance(exc, IntegrityError):
            status = 409
        elif isinstance(exc, ValidationError):
            status = 400
        return jsonify({"error": type(exc).__name__, "message": str(exc)}), status

    @app.errorhandler(Exception)
    def handle_unknown(exc):
        return jsonify({"error": "InternalServerError", "message": str(exc)}), 500

    @app.get("/health")
    def health():
        return jsonify(
            {
                "node_id": app.config["NODE_ID"],
                "status": "ok",
                "public_key": get_public_b64(app.config["NODE_ID"]),
                "head": app.config["CHAIN"].head_info(),
            }
        )

    @app.get("/head")
    def head():
        return jsonify(app.config["CHAIN"].head_info())

    @app.get("/blocks")
    def list_blocks():
        try:
            start = int(request.args.get("from", "1"))
        except ValueError:
            start = 1
        chain: Chain = app.config["CHAIN"]
        blocks = chain.slice_from(start)
        return jsonify({"node_id": app.config["NODE_ID"], "count": len(blocks), "blocks": [b.to_dict() for b in blocks]})

    @app.get("/blocks/<block_id>")
    def get_block(block_id: str):
        chain: Chain = app.config["CHAIN"]
        return jsonify(chain.get_by_id(block_id).to_dict())

    @app.post("/blocks")
    def submit_block():
        chain: Chain = app.config["CHAIN"]
        payload = request.get_json(force=True, silent=False)
        if not isinstance(payload, dict):
            raise ValidationError("Body must be a JSON object representing a block.")

        block = Block.from_dict(payload)
        # Validate first so we know what bytes to sign.
        recomputed_hash = chain.validate_candidate(block)
        chain.append(block)

        header_bytes = canonical_bytes(block.header_for_hash())
        signature = ed25519_sign(app.config["NODE_PRIVATE"], header_bytes)
        endorsement = {
            "node_id": app.config["NODE_ID"],
            "alg": "Ed25519",
            "value": b64e(signature),
            "covered_hash": recomputed_hash,
        }
        return jsonify({"accepted": True, "endorsement": endorsement, "head": chain.head_info()}), 201

    @app.post("/sync")
    def sync_from_peer():
        chain: Chain = app.config["CHAIN"]
        payload = request.get_json(force=True, silent=False) or {}
        peer_url = payload.get("peer_url")
        if not peer_url:
            raise ValidationError("peer_url is required for /sync.")
        my_height = chain.head_info()["height"]
        try:
            response = requests.get(f"{peer_url.rstrip('/')}/blocks", params={"from": my_height + 1}, timeout=5)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise ValidationError(f"Peer {peer_url} unreachable: {exc}") from exc

        peer_blocks = [Block.from_dict(item) for item in response.json().get("blocks", [])]
        applied = 0
        for block in peer_blocks:
            try:
                chain.append(block)
                applied += 1
            except (IntegrityError, ValidationError):
                # Stop at the first divergence; operator can decide what to do.
                break
        return jsonify({"applied": applied, "head": chain.head_info()})

    @app.post("/reset")
    def reset():
        if os.environ.get("ALLOW_RESET") != "1":
            raise ValidationError("Reset is disabled.  Set ALLOW_RESET=1 to enable for tests.")
        app.config["CHAIN"].reset()
        return jsonify({"reset": True, "head": app.config["CHAIN"].head_info()})

    @app.post("/tamper")
    def tamper():
        """Simulate an insider attack on this node's append-only ledger.

        Disabled by default; the launcher (`scripts/dev.py`) exports
        ALLOW_TAMPER=1 in dev so the admin web console can drive the
        immutability demo.  Body: {height: int, field: str ('ciphertext'|'tag'|'nonce'|'previous_hash'|'timestamp')}.
        """
        import json
        from pathlib import Path
        from config import node_data_dir

        if os.environ.get("ALLOW_TAMPER") != "1":
            raise ValidationError("Tamper endpoint is disabled.  Set ALLOW_TAMPER=1 to enable for demos.")
        body = request.get_json(force=True, silent=True) or {}
        try:
            height = int(body.get("height", 0))
        except (TypeError, ValueError) as exc:
            raise ValidationError("height must be an integer.") from exc
        field = (body.get("field") or "ciphertext").strip()
        if height < 1:
            raise ValidationError("height must be >= 1.")

        chain_path: Path = node_data_dir(app.config["NODE_ID"]) / "chain.jsonl"
        if not chain_path.exists():
            raise NotFoundError(f"No chain file at {chain_path}")
        lines = chain_path.read_text(encoding="utf-8").splitlines()
        if len(lines) < height:
            raise NotFoundError(f"Chain has {len(lines)} block(s); cannot tamper height {height}.")
        block = json.loads(lines[height - 1])

        def flip(s: str) -> str:
            if not s:
                return "X"
            return ("B" if s[0] == "A" else "A") + s[1:]

        if field in ("ciphertext", "tag", "nonce"):
            original = block["record"][field]
            block["record"][field] = flip(original)
            mutated = block["record"][field]
        elif field == "previous_hash":
            original = block["previous_hash"]
            block["previous_hash"] = flip(original)
            mutated = block["previous_hash"]
        elif field == "timestamp":
            original = block["timestamp"]
            block["timestamp"] = original + "Z"
            mutated = block["timestamp"]
        else:
            raise ValidationError(f"Unsupported tamper field: {field}")

        lines[height - 1] = json.dumps(block, sort_keys=True)
        chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        # Reload the in-memory chain so subsequent reads see the tamper.
        app.config["CHAIN"] = Chain(app.config["NODE_ID"])
        return jsonify(
            {
                "tampered": True,
                "node_id": app.config["NODE_ID"],
                "height": height,
                "field": field,
                "original_prefix": (original or "")[:24],
                "mutated_prefix": (mutated or "")[:24],
            }
        )

    return app


def main() -> None:  # pragma: no cover - executed only when running the file directly
    app = create_app()
    print(f"[node:{app.config['NODE_ID']}] listening on http://{NODE_HOST}:{NODE_PORT}")
    app.run(host=NODE_HOST, port=NODE_PORT, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":  # pragma: no cover
    main()
