# CSCI-531 Applied Cryptography — Final Project Report

**Title:** Secure Decentralized EHR Audit System
**Option:** 2 — Extended coding prototype with web UI and multi-machine deployment.
**Author:** _(your name)_
**Partner:** _(partner name or "solo")_

---

## 1. System workflow (5%)

The system supports four roles — `patient`, `doctor`, `audit_company`, `admin` — and four core flows:

1. **Authentication.** A user POSTs username + password to `/api/login`.  The gateway looks up the user in `data/gateway/users.json`, scrypt-verifies the password, and returns a JWT (HS256, 30-minute TTL, persistent secret in `data/gateway/keys.json`).
2. **Audit-record creation.** A doctor POSTs `/api/audit/access` with `patient_id`, `action_type`, and `details`.  The gateway:
   - resolves the readers' RSA public keys (patient owner + every audit company + admin),
   - generates a fresh AES-256 key, GCM-encrypts the canonical payload,
   - RSA-OAEP-2048-wraps the AES key per reader,
   - assembles the block (height, prev-hash, record, signer),
   - signs a canonical "sig-header" with the doctor's Ed25519 private key,
   - computes `current_hash` over the full header,
   - broadcasts the block to all three nodes,
   - waits for **2 of 3** Ed25519 endorsements,
   - persists the endorsements to `data/gateway/endorsements.jsonl`,
   - returns 201.
3. **Query.** A patient or audit company GETs `/api/audit/patient/<id>` (or `/api/audit/all`).  The gateway pulls the chain from the majority of nodes, filters by `patient_id_hash`, locates the requesting reader's wrapped key, RSA-OAEP-unwraps it, and AES-GCM-decrypts the payload.  Doctors are forbidden from reading at the policy layer.
4. **Verification.** An audit company or admin GETs `/api/verify`.  The gateway re-pulls every node's chain, re-walks links, recomputes every `current_hash`, re-verifies every actor signature, and computes cross-node divergences (per-height `current_hash` set size > 1).

A web UI (`/web/...`) wraps every flow in a Bootstrap-themed dashboard (see § 7).

## 2. System architecture (15%)

### Components

* **Gateway** — single Flask process, stateless w.r.t. block storage, holds users + JWT secret + endorsement log.  Talks HTTP to the three nodes.
* **Three audit nodes** — each its own Flask process, append-only `chain.jsonl`, persistent Ed25519 node keypair, lock-protected `Chain` data structure.  Containerised independently.
* **Browser / demo scripts** — only ever touch the gateway.

### Trust model

* The gateway is honest-but-curious from the patient's perspective: it can see metadata (`patient_id_hash`, `signer`, `timestamp`, `block_id`, sizes) but cannot decrypt payload content because every payload is encrypted under fresh AES keys it does not retain.  In a stronger deployment the gateway would not hold the readers' private RSA keys at all (we hold them here for one-process demoability — see § 5 limitations).
* Any **single** audit-node operator may be malicious: by signing endorsements with **2-of-3 quorum** and verifying chain hashes + actor signatures at read time, the system tolerates one node tampering or going offline.
* Doctors can write but not read; this is enforced both at the policy layer (`policy.can_query_patient`) and at the cryptographic layer (no wrapped key for the doctor's RSA public key).

### Diagram

```
                          ┌────────────────────┐
                          │   Browser / demo   │
                          └─────────┬──────────┘
                                    │ HTTPS (TLS in prod)
                                    ▼
                       ┌───────────────────────────┐
                       │         Gateway           │
                       │  - login + JWT            │
                       │  - envelope encrypt       │
                       │  - Ed25519 actor sign     │
                       │  - quorum (2/3)           │
                       │  - verify                 │
                       └───────┬───────┬───────────┘
                  POST /blocks │       │ POST /blocks
              ┌────────────────┘       └────────────────┐
              ▼                                          ▼
     ┌─────────────────┐                       ┌─────────────────┐
     │   Node A        │   POST /blocks        │   Node C        │
     │  - validate     │◀─────────────────────▶│  - validate     │
     │  - append       │   (full mesh in prod) │  - append       │
     │  - sign endorsmnt│                      │  - sign endorsmnt│
     └─────────────────┘                       └─────────────────┘
                              ┌─────────────────┐
                              │   Node B        │ … same as A/C
                              └─────────────────┘
```

## 3. Cryptographic components (5%)

| Algorithm | Role | Key size | Library |
|---|---|---|---|
| AES-256-GCM | Confidentiality + integrity of audit payload | 256-bit data key per record | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` |
| RSA-OAEP / SHA-256 | Wrap the AES data key for each authorized reader | 2048-bit | `cryptography.hazmat.primitives.asymmetric.rsa` |
| Ed25519 | Actor signature on each block; node endorsements | 256-bit | `cryptography.hazmat.primitives.asymmetric.ed25519` |
| SHA-256 | Block chain hash; `patient_id_hash` index | 256-bit | `hashlib` |
| scrypt | Password storage (N=2¹⁴, r=8, p=1) | salt 16 B, dk 32 B | `hashlib.scrypt` |
| HS256 JWT | Session token (`exp`, `iat`, `nbf`, `jti`) | 32-byte HMAC secret | `PyJWT` |

Canonicalization for hashes/signatures: `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")` — defined once in `common.canonical_bytes`.

### Why these choices

* **AES-GCM over CBC**: authenticated encryption rules out padding-oracle attacks and bundles MAC + cipher.
* **RSA-OAEP over plain RSA**: OAEP is IND-CCA2; plain RSA-PKCS1-v1.5 has known oracle attacks.
* **Ed25519 over ECDSA**: deterministic, smaller signatures, fewer side channels, fast verify.
* **scrypt over plain SHA-256**: memory-hardness defeats GPU/ASIC password cracking.
* **JWT with `jti` revocation list**: standard, easy to validate, and the `jti` lets us revoke individual sessions on logout.

## 4. How the system meets the five requirements (10%)

### 4.1 Privacy
Every audit payload is encrypted under a fresh 256-bit AES key.  The data key is wrapped with RSA-OAEP for the patient owner, every audit company, and the admin.  **Doctors are not in the wrap list**, so even though doctors write records and have the cleartext at submission time, the persisted ciphertext is unreadable to them after the fact.  Within nodes, only ciphertext + IDs + a `patient_id_hash` are stored; the cleartext patient ID never lands on disk.

### 4.2 Identification + authorization
Users are authenticated with username + scrypt-hashed password.  After login, every request carries a 30-minute HS256 JWT.  The `policy.py` matrix expresses role permissions:

| | create record | query own | query any | query all | verify | manage users |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| patient | – | ✓ | – | – | – | – |
| doctor | ✓ | – | – | – | – | – |
| audit_company | – | ✓ | ✓ | ✓ | ✓ | – |
| admin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Failed-login counter + lockout is implemented in `UserStore`.

### 4.3 Querying
* Patient query: `GET /api/audit/patient/<id>` returns only blocks where `patient_id_hash = SHA-256(<id>)` and where the requester appears in `wrapped_keys`.
* Audit-company query: `GET /api/audit/all` returns every decryptable block.
* Both queries decrypt server-side; the client receives plaintext `record_id`, `patient_id`, `user_id`, `action_type`, `details`, `timestamp`, plus the chain metadata (`block_id`, `height`, `previous_hash`, `current_hash`).

### 4.4 Immutability / tamper detection
* Each block embeds `previous_hash`; `current_hash = SHA-256(canonical(header_for_hash))`.
* The actor signs a canonical sig-header with Ed25519.
* Three independent storage nodes hold the chain; modifying any one diverges the height-keyed `current_hash` set.
* `/api/verify` recomputes everything per-node and reports both per-node failures (chain link, hash, signature) and cross-node divergences.
* Demo `d06_tamper_node_b.py` flips one base64 character on node_b's block 3; demo `d07_verify.py` reports `valid_hashes=False`, `valid_actor_signatures=False` only for node_b.

### 4.5 Decentralization
* Three Flask processes, three independent on-disk ledgers, three independent Ed25519 node keypairs.
* Quorum 2-of-3 means **no single node controls writes or stops them**.
* In docker-compose each node runs in its own container with its own volume.

## 5. Implementation narrative (50%)

### 5.1 Block schema choices
The trickiest design decision was the relationship between the actor signature and the chain hash.  We want:
1. The actor to sign over a *deterministic* representation of the block.
2. The node to be able to recompute the chain hash and reject bad blocks.

We solved this with two views of the block header:
* **`sig_header`** — every header field *except* `actor_signature` and `current_hash`, plus a `signer` field.  The doctor signs `canonical_bytes(sig_header)`.
* **`header_for_hash`** — every header field *except* `current_hash` and `node_endorsements` (we never store endorsements in the per-node ledger; only the gateway logs them).  This view *includes* `actor_signature`, so the chain hash binds the signature into the chain.

A node receives a block, validates the height + prev-hash, recomputes `chain_hash(canonical_bytes(block.header_for_hash()))`, compares against the supplied `current_hash`, appends, and signs `canonical_bytes(block.header_for_hash())` with its Ed25519 private key.  The verifier later reconstructs both the sig-header (from on-disk data) and the chain-hash header to re-check both signatures + the link.

### 5.2 Envelope encryption for many readers
`crypto/envelope.encrypt_record_payload`:
1. Generate a fresh 256-bit AES key with `os.urandom(32)`.
2. AES-GCM-encrypt the canonical payload (12-byte nonce, 16-byte tag, `patient_id_hash` as associated data so the ciphertext is bound to the index).
3. For each reader, RSA-OAEP-2048 wrap the AES key with their public PEM and emit `{reader_id, alg, value}`.

`decrypt_record_payload(record, reader_id, priv_pem)` finds the matching wrapped key, unwraps with the reader's private RSA, AES-GCM-decrypts, and validates `patient_id_hash` matches.

### 5.3 Quorum and consistency
`gateway/audit_service.create_audit_record` calls `client.submit_block(...)` against each node sequentially (could be parallelised).  Successes feed the endorsement list; failures feed `broadcast_errors`.  If `len(endorsements) < QUORUM` the call raises `ConsensusError`.  We do **not** roll back partial writes — append-only by design.  In a partial-write scenario the lagging node will catch up next time it's reachable via the `/sync` endpoint (gateway-driven catch-up is sketched but not auto-triggered in the demo; see § 8 future work).

### 5.4 Verification algorithm
`audit_service.verify_integrity` does, for each node:
* fetch every block,
* walk the chain checking `previous_hash` linkage and recomputing `current_hash`,
* re-verify each block's `actor_signature` using the writer's stored Ed25519 public key,
* collect per-block issues into a list.

Then it groups blocks by height across nodes; if the set of `current_hash` values at any height has size > 1, that's a cross-node divergence (printed under "divergences").  `all_checks_passed` is the AND of every per-node check; `network_consistent` is the absence of divergences.

### 5.5 Limitations / assumptions
* **No TLS in dev mode** — production deployment would terminate TLS at a reverse proxy in front of the gateway and use mTLS or HTTPS-only between gateway and nodes.
* **`patient_id_hash` is plain SHA-256** — vulnerable to ID-guessing.  In production we'd HMAC with a per-tenant key or use blinded tokens.
* **JWT revocation list is in-memory** — a gateway restart wipes it.  Production would use Redis or sticky sessions.
* **Gateway holds reader private keys** — for demo simplicity.  A safer deployment would hold them in a KMS / HSM and forward decryption requests to it, or push decryption fully into the client.
* **No `/sync` auto-replay** — if a node misses a write while offline it must be manually re-synced via `POST /sync`.

### 5.6 Test results
```
tests\test_authz.py ..........                                           [ 43%]
tests\test_crypto.py .........                                           [ 82%]
tests\test_node_server.py ....                                           [100%]
============================= 23 passed in 5.10s ==============================
```

The end-to-end demo run produces:
* `d01` — six blocks created, every one with 3-of-3 endorsements.
* `d02–d05` — patient sees own records; cross-patient read 403; audit company sees all 6; doctor read 403 (twice).
* `d07` (clean) — `all_checks_passed=True`, `network_consistent=True`.
* `d06` — flips one base64 character of `record.ciphertext` on node_b block 3.
* `d07` (post-tamper) — node_b reports `valid_hashes=False`, `valid_actor_signatures=False`; node_a + node_c stay green; the gateway can still serve reads from the majority chain.

## 6. Demo video script (10%)

1. (10 s) Show repo on GitHub, point at `README.md` rubric table.
2. (15 s) `python scripts/dev.py` — three nodes + gateway start in one console.
3. (15 s) Browser → <http://127.0.0.1:5310/> → bootstrap users → log in as `doctor_01`.
4. (20 s) Submit two records via the doctor dashboard; show the JSON response.
5. (20 s) Log out; log in as `patient_01` → see only own two records.  Log in as `patient_02` → empty.  Log in as `audit_company_01` → see all.
6. (15 s) Click "Run integrity check" → green banner.
7. (20 s) Drop to a terminal: `python -m demo.d06_tamper_node_b` → one byte flipped on node_b.
8. (20 s) Click "Run integrity check" again → red banner, node_b card flagged for hash + signature.
9. (15 s) `docker compose up` slide showing the same code on three real containers + a gateway container.
10. (10 s) Wrap-up.

## 7. Web UI walkthrough

* **Login** (`web/templates/login.html`) — Bootstrap card with username + password, "Bootstrap demo users" button visible if no users exist yet.
* **Patient dashboard** — own audit records in a table with hash columns rendered in monospace.
* **Doctor dashboard** — form to create a record (patient dropdown, action select, details).  After submit, shows the new block id + endorsement count.
* **Audit-company / admin dashboard** — query-all by patient filter; "Run integrity check" button hits `/api/verify`.
* **Verify page** (`web/templates/verify.html`) — banner-clean (green) or banner-tamper (red), per-node cards, list of cross-node divergences if any.
* **Node status partial** (`web/templates/_node_status.html`) — three cards (online, head height, head hash) on the dashboard footer.

## 8. Future work

* Auto-replay (gateway pushes missing blocks to a node when it comes back online).
* Move `wrapped_keys` decryption into the client (gateway becomes a true zero-knowledge relay).
* Persistent JWT revocation in Redis.
* HMAC-keyed `patient_id_hash`.
* gRPC instead of JSON-over-HTTP between gateway and nodes for lower latency.
* Threshold signatures for endorsements (one aggregated signature instead of three).

## 9. References

1. CSCI-531 Project specification PDF (course materials).
2. RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA / Ed25519).
3. RFC 7519 — JSON Web Token (JWT).
4. RFC 5116 — An Interface and Algorithms for Authenticated Encryption (AEAD: AES-GCM).
5. RFC 8017 — PKCS #1: RSA Cryptography Specifications Version 2.2 (RSA-OAEP).
6. RFC 7914 — The scrypt Password-Based Key Derivation Function.
7. Boneh & Shoup, *A Graduate Course in Applied Cryptography* (chapters on AEAD and KEM/DEM).
8. Azaria et al., "MedRec: Using Blockchain for Medical Data Access and Permission Management," _OBD 2016_.
9. Yue et al., "Healthcare Data Gateways: Found Healthcare Intelligence on Blockchain with Novel Privacy Risk Control," _Journal of Medical Systems_, 2016.
10. Ekblaw et al., "A Case Study for Blockchain in Healthcare," MIT MEDIA LAB, 2016.
11. `cryptography` library docs — <https://cryptography.io/>.
12. PyJWT docs — <https://pyjwt.readthedocs.io/>.
13. Flask docs — <https://flask.palletsprojects.com/>.
