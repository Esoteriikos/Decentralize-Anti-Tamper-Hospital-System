# TODO — Revamp To "Best Of The Best" (Option 2)

> Course: CSCI-531 Applied Cryptography  
> Assignment option: **Option 2 — Extended prototype** (50 pts implementation + 5 % bonus for realistic distributed + web UI)  
> Status: revamp planned, current code is a working but simulated single-process prototype

This file is the actionable checklist. The deeper rationale and architecture are in [PLAN.md](PLAN.md). Work top-down. Each task lists *why* and *acceptance criteria* so they can be checked off independently.

---

## Legend

- [ ] = not started
- [~] = in progress
- [x] = done

Priority tags: **P0** = required to pass / hit core rubric, **P1** = needed for the 5 % bonus and a top score, **P2** = polish.

---

## 0. Project hygiene (P0)

- [ ] Add `LICENSE.md` stating the repo is private to the team for academic use only (assignment forbids public release).
- [ ] Add `.gitignore` entries for `data/`, `*.pem`, `*.key`, `__pycache__/`, `.venv/`, `node_modules/`, `*.log`.
- [ ] Add `pyproject.toml` (or keep `requirements.txt`) and pin versions for `Flask`, `cryptography`, `pynacl` (or stick with `cryptography` Ed25519), `requests`, `pytest`, `python-dotenv`.
- [ ] Add `Makefile` (or `tasks.ps1` for Windows) with targets: `install`, `keys`, `nodes-up`, `gateway-up`, `web-up`, `demo`, `test`, `clean`.
- [ ] Author a top-level `ATTRIBUTION.md` listing every external library + a one-line description of what functionality it provides (the PDF requires this explicitly).

---

## 1. True decentralization — three independent node servers (P0 → P1 for full credit)

The current code writes three JSON files from one Python process. The assignment penalises that as "single trusted entity." Replace with three independent HTTP servers.

- [ ] Create `node_server/` package with its own Flask app exposing:
  - `POST /blocks` — accept a signed block from another node or the gateway, validate, append.
  - `GET  /blocks` — return the full chain (paginated).
  - `GET  /blocks/<id>` — return one block.
  - `GET  /head` — return latest block height + hash + Merkle root.
  - `GET  /health` — liveness + node public key.
- [ ] Each node has its own keypair (Ed25519) stored under `data/nodes/<node_id>/keys/`.
- [ ] Each node persists to `data/nodes/<node_id>/chain.jsonl` (append-only line-delimited JSON, one block per line) instead of a single rewritten JSON file. Append-only on disk is half the immutability story.
- [ ] Run three nodes on three different ports (`5311`, `5312`, `5313`). Node configuration via env vars (`NODE_ID`, `NODE_PORT`, `PEERS`).
- [ ] Provide `scripts/start_nodes.ps1` and `scripts/start_nodes.sh` to launch the three servers locally.
- [ ] Provide `docker-compose.yml` running 3 node containers + 1 gateway + 1 web UI on a shared bridge network (this is what scores the realistic-distributed bonus).

Acceptance: `curl https://127.0.0.1:5311/health` works, all three nodes return their own pubkey, killing one node does not stop replication on the other two (gateway tolerates 1-of-3 down).

---

## 2. Replication + lightweight consensus (P1)

The PDF only requires *detection* of tampering, but for "best of the best" we want a small consensus layer so no single node can rewrite history.

- [ ] Define `Block` schema:
  ```json
  {
    "block_id": "AUDIT-0007",
    "height": 7,
    "previous_hash": "<sha256 of previous block header>",
    "merkle_root": "<sha256 of single-record merkle root>",
    "timestamp": "...",
    "record": { "nonce": "...", "ciphertext": "...", "tag": "...", "wrapped_keys": [...] },
    "actor_signature": { "alg": "Ed25519", "signer": "doctor_01", "value": "..." },
    "node_endorsements": [ { "node_id": "node_a", "value": "..." }, ... ]
  }
  ```
- [ ] Implement Proof-of-Authority style endorsement: gateway broadcasts a candidate block to all 3 nodes; each node verifies actor signature + chain link and returns its own Ed25519 endorsement. Block is committed only when **>= 2 of 3 endorsements** are collected (BFT-1 quorum).
- [ ] On commit, gateway POSTs the fully endorsed block back to every node so all chains converge.
- [ ] If a node rejects (e.g. its head doesn't match), the gateway logs the divergence and surfaces it on `/verify`.

Acceptance: starting two nodes (third offline) still allows new audit records to be created and replicated; bringing the third node back triggers a catch-up sync.

---

## 3. Cryptographic upgrade (P0 + P1)

Current crypto is fine but minimal. Beef it up so the *Cryptographic components* section of the report is rich.

- [ ] **Per-record envelope encryption.** Generate a fresh AES-256-GCM data key for every audit record. Wrap that data key once for *each authorised reader* (the patient that owns the record + every audit company) using their RSA-OAEP-2048 (or X25519+HKDF) public key. Store wrapped keys alongside the ciphertext. This removes the "single master AES key" weakness and lets us cleanly demonstrate role-based decryption.
- [ ] **Actor signatures (non-repudiation).** Every doctor/admin has an Ed25519 signing key. The audit record's hash is signed before submission; nodes refuse blocks whose signatures don't verify against the registered actor pubkey.
- [ ] **Merkle root** per block (only one record per block today, but keep the structure so the report can describe it for batched logs).
- [ ] **Hash chain** stays SHA-256 over the *block header*, not just selected fields, so any change anywhere invalidates the chain.
- [ ] **Token issuer** moves to short-lived JWT (HS256) with `exp`, `iat`, `nbf`, `jti`. Reject expired tokens. Add `POST /refresh`.
- [ ] **Password storage** stays Argon2 (preferred over Werkzeug's pbkdf2 default). Use `argon2-cffi`.
- [ ] **TLS everywhere.** Generate a self-signed CA + per-service certs in `scripts/make_tls.py`. Gateway, nodes and web UI all listen on HTTPS. Document how the professor disables hostname verification for the demo.
- [ ] Document key rotation story in `PLAN.md` even if not implemented (assignment only requires discussion of limitations).

Acceptance: a single `pytest tests/test_crypto.py` covers encrypt/decrypt round-trip, signature verify pass/fail, hash-chain detect, JWT expiry.

---

## 4. Identification + authorization (P0)

- [ ] Replace the hand-rolled HMAC token with a JWT library (`PyJWT`).
- [ ] Add `/register` (admin-only) and `/users/<id>/rotate-keys` endpoints; store user public keys in `users.json`.
- [ ] Enforce role matrix in a single `policy.py` module:
  | Role | Create audit | Read own | Read all | Verify integrity | Manage users |
  |------|--------------|----------|----------|------------------|--------------|
  | patient | no | yes | no | no | no |
  | doctor | yes | no | no | no | no |
  | audit_company | no | n/a | yes | yes | no |
  | admin | yes | n/a | yes | yes | yes |
- [ ] Add rate-limit + lockout after 5 failed logins (Flask-Limiter or homegrown counter).
- [ ] Audit *every* security-relevant API call (login success, login fail, query, verify, tamper attempt) — these go into the audit log too.

Acceptance: `pytest tests/test_authz.py` covers each role positive + negative.

---

## 5. Gateway / API server (P0)

The current `app.py` becomes the *gateway*. It is the only public-facing API; it talks to the three node servers over HTTPS.

- [ ] Move `app.py` → `gateway/app.py`. Endpoints:
  - `POST /login`, `POST /refresh`, `POST /logout`
  - `POST /audit/access` — doctor/admin creates record (gateway signs with actor key, broadcasts to nodes, waits for quorum)
  - `GET  /audit/patient/<id>` — patient/audit_co reads
  - `GET  /audit/all` — audit_co/admin only
  - `GET  /verify` — runs cross-node verification
  - `POST /admin/users` — admin only
- [ ] Gateway never stores audit records itself. It is stateless besides the user store and key registry. (User store can still live in `data/users.json` for the prototype but should be moved behind a small `UserService`.)
- [ ] Gateway uses `requests` with mutual-TLS to talk to nodes; nodes pin gateway's pubkey.

Acceptance: killing the gateway and restarting it must not lose any audit data — proof that nodes are the real source of truth.

---

## 6. Web UI (P1 — required for the 5 % bonus)

Build a small but presentable single-page app. Two reasonable choices, pick one:

**Option A — Plain Flask + Jinja + Bootstrap** (simplest, recommended)  
**Option B — React + Vite served statically by gateway** (nicer demo, more work)

Decision: **start with Option A**. Promote to React only if time allows.

- [ ] Pages:
  - `/` — landing page with login form.
  - `/dashboard/patient` — patient sees their own audit log (decrypted client-side display).
  - `/dashboard/audit-company` — table of all records, filter by patient, "Run integrity check" button, tamper-detection banner.
  - `/dashboard/admin` — user management + integrity report.
- [ ] Pretty styling with Bootstrap 5.
- [ ] Show decentralization visually: a small status panel that pings `/health` of each node and turns red when a node is down or out of sync.
- [ ] All API calls go through the gateway; the browser never talks to a node directly.

Acceptance: a non-technical viewer can run the demo video and immediately understand what the system does.

---

## 7. Demo scripts overhaul (P0)

The current demos call the Python service layer directly. Replace with HTTP-driven scripts so we can prove the client/server architecture.

- [ ] Rewrite each demo under `demo/` to use `requests` against the gateway:
  - `01_create_users.py` (admin bootstrap)
  - `02_doctor_creates_audit.py`
  - `03_patient_queries_own.py`
  - `04_patient_queries_other_patient.py` *(must fail)*
  - `05_audit_company_queries_all.py`
  - `06_doctor_tries_to_query.py` *(must fail)*
  - `07_tamper_node_b.py` *(directly edits `data/nodes/node_b/chain.jsonl` to simulate insider attack)*
  - `08_verify_detects_tamper.py`
  - `09_node_down_quorum.py` *(kills node_c, shows system still works on 2/3)*
- [ ] Each demo prints a short banner explaining what is being demonstrated → makes the recording self-explanatory.
- [ ] Add `demo/run_all.ps1` and `.sh` that chain them.

---

## 8. Testing + CI (P1)

- [ ] Add `tests/`:
  - `test_crypto.py` — AES-GCM, RSA-OAEP wrap/unwrap, Ed25519, hash chain, Merkle.
  - `test_authz.py` — role matrix.
  - `test_node_replication.py` — quorum, divergence detection.
  - `test_e2e.py` — spins the gateway + 3 nodes via subprocess and runs the demo flow.
- [ ] `pytest -q` must pass on a clean checkout.
- [ ] (Optional) GitHub Actions workflow — but the repo is private; skip unless trivially easy.

---

## 9. Documentation + report deliverables (P0)

- [ ] Rewrite `README.md`:
  - State Option 2 + partner name on the very first line (PDF requires this).
  - Architecture diagram (use Mermaid).
  - Sequence diagram for "doctor creates audit record" (Mermaid).
  - Quickstart: `make install && make keys && make nodes-up && make gateway-up && make web-up && make demo`.
  - Section "What we built ourselves vs. what came from libraries" (PDF requires this).
- [ ] Rewrite `report_notes.md` into a 10–20 page report skeleton matching the rubric:
  1. System workflow (5 pts) — bullet steps + sequence diagram.
  2. System architecture (15 pts) — components, comms patterns, diagram.
  3. Cryptographic components (5 pts) — primitives table.
  4. How system meets requirements (10 pts) — map five goals → demo screenshot.
  5. Assumptions and limitations (5 pts) — TLS pinning, key rotation, single-host clock, no real consensus, etc.
  6. Implementation (50 pts) — module-by-module narrative, screenshots, exec instructions.
  7. Demo video (10 pts) — script written in `demo/recording_script.md`.
  8. Realistic distributed + web UI (5 % bonus) — explain compose, ports, web routes.
- [ ] References list at end of report (course PDF, Flask docs, `cryptography` docs, RFC 8032 Ed25519, RFC 7519 JWT, the three blockchain/EHR papers cited in the PDF).

---

## 10. Demo video plan (P0 — 10 pts)

- [ ] `demo/recording_script.md` with a minute-by-minute outline (~6–8 min total):
  1. Intro on webcam — name, partner, option chosen.
  2. Show the architecture diagram from the README.
  3. Spin up nodes + gateway + web UI in three terminals.
  4. Browser walkthrough: login as doctor → create record; login as patient → see own record; login as audit company → see all + integrity check green.
  5. Insider tamper: run `07_tamper_node_b.py`, refresh integrity check → red banner shows which node + which record.
  6. Decentralization proof: kill node_c terminal, create a new record → still works (2/3 quorum).
  7. Closing on webcam — limitations + future work.

---

## 11. Stretch goals (P2)

- [ ] Replace JSON files with SQLite per node for indexed queries (still append-only via triggers).
- [ ] Real Merkle batching: gateway batches records every N seconds into a block.
- [ ] Replace JWT with mutual TLS for gateway↔nodes (already planned) **and** SPKI-pinned client certs for the web UI's admin role.
- [ ] Log redaction policy: patients see action/timestamp but not free-text "details" of other doctors' notes (already covered by per-record envelope encryption, just enforce in UI).
- [ ] Threshold-decryption for audit_company role (k-of-n) using Shamir or a simple threshold ECIES — would directly answer the "no single trusted entity" goal at the cryptographic layer, not just the storage layer.

---

## Done definition

The revamp is complete when, on a clean machine:

1. `make install` then `make keys` succeed.
2. Three node terminals + one gateway terminal + one web terminal run without error.
3. Browser at `https://127.0.0.1:5310` lets a viewer log in as each role and see role-appropriate data.
4. `pytest -q` passes.
5. `demo/run_all.ps1` ends with the integrity report turning red on tamper and green again after rebuilding clean ledgers.
6. Final report PDF renders inside the 10–20 page limit.
