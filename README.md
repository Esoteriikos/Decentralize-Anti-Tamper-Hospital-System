# Secure Decentralized EHR Audit System

CSCI-531 Applied Cryptography — Spring 2026 — Final Project (Option 2)

> A privacy-preserving, append-only audit log for Electronic Health
> Record (EHR) accesses, replicated across three independent nodes
> with 2-of-3 quorum, end-to-end envelope encryption, actor signatures,
> and tamper-evident chain hashes.

## What this delivers (rubric → feature mapping)

| Rubric requirement | Where it lives |
|---|---|
| **Privacy** of audit records | `crypto/envelope.py` — every record is AES-256-GCM-encrypted with a fresh data key; the data key is RSA-OAEP-2048-wrapped per authorized reader (patient owner + every audit company + admin). Doctors who *write* records cannot *read* them. |
| **Identification & authorization** of users | `auth/user_store.py`, `auth/jwt_service.py`, `auth/policy.py` — scrypt-hashed passwords, 30-min HS256 JWTs with `jti` revocation, role-based policy matrix. |
| **Querying** by patients and audit companies | `gateway/audit_service.py` query path; web dashboards in `web/templates/`. |
| **Immutability / tamper detection** | SHA-256 chain hash linking every block, Ed25519 actor signatures over a canonical sig-header, replication across 3 nodes, `/api/verify` recomputes everything and reports per-node + cross-node divergences. |
| **Decentralization** | 3 independent Flask node servers (`node_server/`) each with their own Ed25519 keypair, append-only `chain.jsonl`, and 2-of-3 quorum endorsement requirement before the gateway considers a write durable. |
| **Option 2 bonus** — multi-machine + web UI | `docker-compose.yml` runs 4 separate containers (3 nodes + gateway), `web/templates/` serves a Bootstrap-styled dashboard, full HTTP-only contract between gateway ↔ nodes (no shared memory). |

All 23 unit tests pass (`python -m pytest`) and the 8-step end-to-end demo is reproducible on Windows + Linux.

## Architecture

```
                        ┌──────────────────────┐
   browser ─── HTTPS ──▶│  Gateway (Flask)     │── REST ──▶ Audit Node A (Flask + chain.jsonl)
                        │  - login / JWT       │── REST ──▶ Audit Node B (Flask + chain.jsonl)
                        │  - envelope encrypt  │── REST ──▶ Audit Node C (Flask + chain.jsonl)
                        │  - actor sign        │
                        │  - quorum (2 of 3)   │
                        │  - verify            │
                        └──────────────────────┘
```

Single-phase commit: the gateway broadcasts the signed block to every node; each node validates height/prev-hash/recomputed-hash, appends to disk, and returns an Ed25519 endorsement over the canonical block header.  The gateway requires **2 of 3** endorsements before reporting success to the actor.  Endorsements are persisted in `data/gateway/endorsements.jsonl` for later auditing.

### Block layout

```jsonc
{
  "version": 1,
  "block_id": "AUDIT-0003",
  "height": 3,
  "timestamp": "2026-04-30T18:27:34Z",
  "previous_hash": "<sha256 of prior block.current_hash>",
  "record": {
    "record_id": "AUDIT-0003.1",
    "patient_id_hash": "<sha256(patient_id)>",
    "nonce":       "<base64 12-byte GCM nonce>",
    "ciphertext":  "<base64 AES-256-GCM ciphertext of payload>",
    "tag":         "<base64 16-byte GCM tag>",
    "wrapped_keys": [
      {"reader_id": "patient_03",       "alg": "RSA-OAEP-SHA256", "value": "<b64>"},
      {"reader_id": "audit_company_01", "alg": "RSA-OAEP-SHA256", "value": "<b64>"},
      ...
    ]
  },
  "actor_signature": {"signer": "doctor_01", "alg": "Ed25519", "value": "<b64>"},
  "current_hash":    "<sha256 over the canonical header above, including actor_signature>"
}
```

The actor signs a canonical "sig-header" (everything above except `actor_signature` and `current_hash`).  Nodes recompute `current_hash` over the full header (including the now-populated `actor_signature`) and store the result.  The verifier reverses both steps independently.

## Quickstart

The gateway requires **Postgres** for its auth surface (users, login events,
JWT revocations, query audit log).  Private RSA / Ed25519 keys are sealed at
rest with AES-256-GCM under a master key (`data/gateway/master.key`, auto
generated, or set `GATEWAY_MASTER_KEY` to a base64 32-byte value).  Node
ledgers (`chain.jsonl`) stay decentralised on each node — only the gateway's
own state is in Postgres.

### Local (Python + Docker for Postgres)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 1. start Postgres in the background
docker compose up -d postgres

# 2. (optional) override the URL — default is the docker-compose service
# $env:DATABASE_URL = "postgresql+psycopg://audit:audit@127.0.0.1:5432/audit"

# 3. start the gateway + 3 nodes
python scripts/dev.py

# in another terminal
python -m demo.d00_bootstrap    
python -m demo.d01_doctor_creates_audits
python -m demo.d02_patient_queries_own
python -m demo.d03_patient_queries_other   
python -m demo.d04_audit_company_queries_all
python -m demo.d05_unauthorized_doctor       
python -m demo.d07_verify                
python -m demo.d06_tamper_node_b        
python -m demo.d07_verify                

# or run them all:
.\scripts\run_demos.ps1
```

Then browse to <http://127.0.0.1:5310/> and log in (sample passwords below).

### Docker (one container per machine, the bonus rubric line)

```powershell
docker compose up --build
```

Spins up four separate containers (`node_a`, `node_b`, `node_c`, `gateway`), each with its own persistent volume.  Browse to <http://127.0.0.1:5310/>.

## Sample users

`POST /api/admin/bootstrap` (or the `Bootstrap demo users` button on the login page) creates:

| Username | Role | Password |
|---|---|---|
| `patient_01` … `patient_10` | patient | `PatientPass!` |
| `doctor_01`, `doctor_02` | doctor | `DoctorPass!` |
| `audit_company_01` … `audit_company_03` | audit_company | `   !` |
| `admin_01` | admin | `AdminPass!` |

The bootstrap endpoint refuses to recreate users if `data/gateway/users.json` is non-empty unless `{"reset": true}` is sent, in which case it requires admin credentials.

## Tests

```powershell
python -m pytest          # 23 tests, ~5s
```

Coverage:
* `tests/test_crypto.py` — AES-GCM roundtrip + tamper, RSA-OAEP wrap/unwrap, Ed25519 sign/verify, chain-hash determinism, scrypt password verify, envelope per-reader decryption.
* `tests/test_authz.py` — full role policy matrix + an in-process end-to-end run (gateway audit-service against three real `Chain` instances, write + patient query + audit-company query + tamper detection).
* `tests/test_node_server.py` — Flask test client: chain growth, bad prev-hash rejection, bad height rejection.

## Repository layout

```
app.py                  # convenience entry, runs the gateway
config.py               # paths, role list, quorum size, JWT TTL
common.py               # canonical_bytes, base64 helpers, UTC timestamp
errors.py               # AuditSystemError hierarchy
storage.py              # atomic write_json + JSONL helpers
models/                 # User, Block dataclasses
crypto/
  primitives.py         # AES-GCM, RSA-OAEP, Ed25519, SHA-256, scrypt
  envelope.py           # encrypt/decrypt audit-record payload for many readers
auth/
  user_store.py         # users.json + per-user RSA + Ed25519 private keys
  jwt_service.py        # HS256 JWT, exp/nbf/jti, in-memory revocation list
  policy.py             # role -> action predicates
node_server/
  app.py                # Flask app, /health /head /blocks (GET+POST) /sync /reset
  chain.py              # append-only Chain with re-validation on append
  keys.py               # per-node Ed25519 keypair (persisted)
gateway/
  app.py                # Flask app: REST + server-rendered web UI
  audit_service.py      # encrypt + sign + broadcast + collect quorum + verify
  bootstrap.py          # create_sample_users
  node_client.py        # tiny REST client + NodeStatus dataclass
web/
  templates/            # Jinja templates (Bootstrap 5 CDN)
  static/app.css        # banners, status pills, hash cells
demo/                   # eight scripted scenarios using only the public HTTP API
scripts/
  dev.py                # spawns 3 nodes + gateway in one console
  start_all.ps1         # 4 separate PowerShell windows
  run_demos.ps1         # runs all demos in order
tests/                  # pytest suite
Dockerfile
docker-compose.yml
report.md               # full project report
```

## What we built ourselves vs. external libraries

We wrote: the block format, the chain-hash construction, the dual-hashing pattern for the actor signature, the envelope encryption for many readers, the quorum protocol, the policy matrix, the verification algorithm, all of the demos, all of the web UI.

We used: `cryptography` (AES-GCM, RSA-OAEP, Ed25519, scrypt), `PyJWT` (HS256 JWT serialization), `Flask` + `Jinja2` + Bootstrap 5 (web layer), `requests` (HTTP client between gateway and nodes), `pytest` (tests).  No blockchain framework, no off-the-shelf consensus engine, no off-the-shelf key-management server.

## Limitations / threat model

* The prototype runs over plain HTTP for local demoability.  In production every link (browser↔gateway, gateway↔node) would be TLS.
* `patient_id_hash` is `SHA-256(patient_id)`.  An attacker who can guess patient IDs can join records to a patient.  Production would key the hash with a per-deployment secret (HMAC) or use a tokenization service.
* JWT `jti` revocation is in-memory in the gateway process.  A single restart wipes the deny-list.  Acceptable for a demo; production would persist it to Redis or a database.
* Single-phase commit means a network partition between the gateway and **two** of three nodes briefly stalls writes (the gateway will return a `ConsensusError`).  We trade availability for safety here, which matches medical-records auditing requirements.

See `report.md` for a deeper treatment.
