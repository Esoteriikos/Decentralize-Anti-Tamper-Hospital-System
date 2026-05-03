# Secure Decentralized EHR Audit System

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

---

### Component Architecture

```mermaid
graph TB
    BROWSER["Browser<br/>Bootstrap 5 Web UI"]
    SCRIPTS["Demo Scripts / API Clients<br/>Bearer JWT over HTTP"]

    subgraph GATEWAY["Gateway  :5310"]

        subgraph GW_ROUTES["Routes  —  gateway/app.py"]
            GWR_AUTH["/api/login  /api/logout<br/>/api/me/writes"]
            GWR_AUDIT["/api/audit/access<br/>/api/audit/patient/:id<br/>/api/audit/all"]
            GWR_VFY["/api/verify<br/>/api/nodes/health<br/>/api/nodes/:id/blocks"]
            GWR_ADM["/api/admin/bootstrap<br/>/api/admin/users  /api/admin/tamper"]
            GWR_WEB["/web/*  role-tailored dashboards<br/>/signup  patient self-signup"]
        end

        subgraph GW_AUTH["Auth Layer  —  auth/"]
            GWA_US["UserStore  user_store.py<br/>scrypt password hashing<br/>RSA-2048 keygen for readers<br/>Ed25519 keygen for writers<br/>KEK-sealed private keys at rest"]
            GWA_JWT["JwtService  jwt_service.py<br/>HS256 issue / verify  exp=30 min<br/>jti revocation via Postgres<br/>purge_expired() cleanup"]
            GWA_POL["Policy  policy.py<br/>can_create_record<br/>can_query_patient / can_query_all<br/>can_verify_integrity<br/>can_manage_users"]
        end

        subgraph GW_CRYPTO["Crypto Layer  —  crypto/"]
            GWC_ENV["Envelope  envelope.py<br/>AES-256-GCM encrypt payload<br/>RSA-OAEP wrap data key per reader<br/>SHA-256 patient_id_hash"]
            GWC_KEK["KEK  kek.py<br/>AES-256-GCM seal of private blobs<br/>nonce + ciphertext + tag format<br/>master.key or GATEWAY_MASTER_KEY env"]
            GWC_PRM["Primitives  primitives.py<br/>AES-GCM  RSA-OAEP  Ed25519<br/>SHA-256  scrypt  base64 helpers"]
        end

        GW_ASVC["AuditService  —  audit_service.py<br/>encrypt -> actor-sign -> broadcast<br/>collect quorum (2-of-3)<br/>verify_integrity  query_records_for_reader<br/>tamper_node_block (admin demo only)"]
        GW_NC["NodeClient x3  —  node_client.py<br/>health / head / get_blocks<br/>submit_block / tamper / reset<br/>HTTP REST  timeout=3 s per call"]
    end

    subgraph POSTGRES["PostgreSQL  :5432"]
        PG_USR[("users<br/>PK user_id  username  role<br/>password_hash  scrypt<br/>rsa_public_pem  cleartext<br/>rsa_private_enc  KEK-sealed<br/>ed25519_public_b64  cleartext<br/>ed25519_private_enc  KEK-sealed<br/>failed_logins  locked")]
        PG_JWT[("jwt_revocations<br/>jti  user_id  expires_at")]
        PG_LOG[("login_events<br/>user_id  success  ip  ts")]
        PG_QRY[("query_audit<br/>actor_user_id  patient_id  ts")]
    end

    subgraph FS["File System  —  data/"]
        FS_MK["gateway/master.key<br/>32-byte AES KEK  chmod 0600"]
        FS_EL["gateway/endorsements.jsonl<br/>Ed25519 quorum proofs per block"]
        FS_NK["nodes/id/node_key.b64<br/>nodes/id/node_public.b64"]
    end

    subgraph NODE_A["Node A  :5311"]
        NA_APP["Flask app.py<br/>GET /health  /head  /blocks<br/>POST /blocks  /sync  /reset  /tamper"]
        NA_CHN["Chain  chain.py<br/>append-only JSONL  threading.RLock<br/>validate_candidate: height + prev_hash + SHA-256<br/>append: atomic write to chain.jsonl"]
        NA_KEY["Ed25519 Keypair  keys.py<br/>persists to data/nodes/node_a/<br/>endorses every committed block"]
        NA_JL[("chain.jsonl<br/>one Block JSON per line")]
    end

    subgraph NODE_B["Node B  :5312"]
        NB_APP["Flask app.py"]
        NB_CHN["Chain  chain.py"]
        NB_KEY["Ed25519 Keypair"]
        NB_JL[("chain.jsonl")]
    end

    subgraph NODE_C["Node C  :5313"]
        NC_APP["Flask app.py"]
        NC_CHN["Chain  chain.py"]
        NC_KEY["Ed25519 Keypair"]
        NC_JL[("chain.jsonl")]
    end

    BROWSER -->|"HTTPS  session cookie + JWT"| GW_ROUTES
    SCRIPTS -->|"Bearer JWT"| GW_ROUTES
    GW_ROUTES --> GW_AUTH
    GW_ROUTES --> GW_ASVC
    GWA_US --> POSTGRES
    GWA_JWT --> POSTGRES
    GW_ASVC --> GW_CRYPTO
    GW_ASVC --> GW_NC
    GWC_KEK --> FS_MK
    GW_ASVC -->|"persist quorum proofs"| FS_EL
    GW_NC -->|"POST /blocks"| NA_APP
    GW_NC -->|"POST /blocks"| NB_APP
    GW_NC -->|"POST /blocks"| NC_APP
    NA_APP --> NA_CHN --> NA_JL
    NA_KEY -.->|"sign endorsement"| NA_APP
    NB_APP --> NB_CHN --> NB_JL
    NB_KEY -.->|"sign endorsement"| NB_APP
    NC_APP --> NC_CHN --> NC_JL
    NC_KEY -.->|"sign endorsement"| NC_APP
    FS_NK -.->|"persisted to disk"| NA_KEY
    FS_NK -.->|"persisted to disk"| NB_KEY
    FS_NK -.->|"persisted to disk"| NC_KEY
```

---

### Envelope Encryption Data Flow

```mermaid
graph LR
    subgraph ENC["encrypt_record_payload()  —  envelope.py"]
        PAYLOAD["Plaintext Payload<br/>timestamp  patient_id<br/>actor  action_type  details"]
        AESKEY["Random 32-byte<br/>AES-256 Data Key<br/>os.urandom(32)"]
        GCMENC["AES-256-GCM Encrypt<br/>nonce = os.urandom(12)<br/>ciphertext + tag (16 B)"]
        PIDHASH["SHA-256(patient_id)<br/>patient_id_hash"]
        WRAP["RSA-OAEP-SHA256 Wrap<br/>for each authorized reader<br/>patient + audit_company + admin<br/>doctors intentionally excluded"]
    end

    subgraph BLOCK["Block  record  field (stored on nodes)"]
        ONONCE["nonce  b64  12 B"]
        OCT["ciphertext  b64"]
        OTAG["tag  b64  16 B"]
        OWK["wrapped_keys<br/>reader_id  alg  value x N"]
        OPID["patient_id_hash"]
    end

    subgraph DEC["decrypt_record_payload()  —  envelope.py"]
        FINDWK["find wrapped_key<br/>where reader_id matches"]
        UNWRAP["RSA-OAEP-SHA256 Unwrap<br/>with reader RSA private key<br/>32-byte AES data key"]
        GCMDEC["AES-256-GCM Decrypt<br/>verify GCM tag  tamper detection<br/>plaintext bytes  JSON parse"]
    end

    PAYLOAD --> GCMENC
    AESKEY --> GCMENC
    AESKEY --> WRAP
    GCMENC --> ONONCE
    GCMENC --> OCT
    GCMENC --> OTAG
    WRAP --> OWK
    PAYLOAD --> PIDHASH --> OPID

    OCT --> GCMDEC
    ONONCE --> GCMDEC
    OTAG --> GCMDEC
    OWK --> FINDWK --> UNWRAP --> GCMDEC
    GCMDEC --> PLAIN["Decrypted Payload dict<br/>accessible only to authorized readers"]
```

---

### KEK At-Rest Key Protection

```mermaid
graph LR
    subgraph KEYGEN["User Registration  —  user_store.py"]
        GENRSA["RSA-2048 keygen<br/>rsa_generate_keypair()"]
        GENED["Ed25519 keygen<br/>ed25519_generate_keypair()"]
    end

    subgraph KEKMOD["Key Sealing  —  kek.py"]
        MASTERKEY["Master Key  32 B<br/>GATEWAY_MASTER_KEY env var<br/>or data/gateway/master.key<br/>auto-generated  chmod 0600"]
        GCMKEK["AES-256-GCM Encrypt<br/>nonce = os.urandom(12)<br/>blob = nonce + ciphertext + tag"]
    end

    subgraph PGSTORE["PostgreSQL  users table"]
        PUBPEM["rsa_public_pem  TEXT<br/>cleartext  public key only"]
        PRIVENC["rsa_private_enc  BYTEA<br/>nonce + ciphertext + tag"]
        EDPUB["ed25519_public_b64  TEXT<br/>cleartext  public key only"]
        EDPRIVENC["ed25519_private_enc  BYTEA<br/>nonce + ciphertext + tag"]
    end

    subgraph KEKDEC["Key Unsealing  —  kek.py"]
        GCMKEKD["AES-256-GCM Decrypt<br/>blob 0-12 = nonce<br/>blob -16 = tag<br/>middle = ciphertext<br/>plaintext private key bytes"]
    end

    GENRSA -->|"export public PEM"| PUBPEM
    GENRSA -->|"export private PEM bytes"| GCMKEK
    MASTERKEY --> GCMKEK
    GCMKEK --> PRIVENC
    GENED -->|"export public b64"| EDPUB
    GENED -->|"export private b64 bytes"| GCMKEK
    GCMKEK --> EDPRIVENC

    PRIVENC --> GCMKEKD
    EDPRIVENC --> GCMKEKD
    MASTERKEY --> GCMKEKD
    GCMKEKD --> PLAINKEY["Plaintext Private Key<br/>RSA: RSA-OAEP unwrap operations<br/>Ed25519: block header signing"]
```

---

## System Workflows

### Login

```mermaid
sequenceDiagram
    actor U as User (any role)
    participant GW as Gateway
    participant US as UserStore
    participant DB as PostgreSQL
    participant JWT as JwtService

    U->>GW: POST /api/login {username, password}
    GW->>US: authenticate(username, password)
    US->>DB: SELECT * FROM users WHERE username = ?
    DB-->>US: UserRow {password_hash, locked, failed_logins, role}

    alt account is locked
        US-->>GW: AuthError: account locked
        GW-->>U: 401 Unauthorized
    else scrypt_verify fails
        US->>DB: UPDATE failed_logins += 1 (lock if >= 5)
        US-->>GW: AuthError: bad credentials
        GW-->>U: 401 Unauthorized
    else credentials valid
        US->>DB: UPDATE failed_logins = 0, locked = False
        US-->>GW: User {user_id, role, patient_id}
        GW->>JWT: issue(user)
        JWT->>JWT: generate jti = UUID4
        JWT->>JWT: HS256 sign {sub, role, patient_id, jti, iat, nbf, exp=+30 min}
        JWT-->>GW: {token, expires_at, jti}
        GW->>DB: INSERT login_events {user_id, success=True, ip, ts}
        GW-->>U: 200 OK {token, role, user_id, expires_at}
    end

    Note over U,GW: Subsequent requests carry  Authorization: Bearer token

    U->>GW: GET /api/audit/... Authorization: Bearer token
    GW->>JWT: verify(token)
    JWT->>JWT: PyJWT decode + expiry check
    JWT->>DB: SELECT FROM jwt_revocations WHERE jti = ?
    DB-->>JWT: not found (token valid)
    JWT-->>GW: {sub, role, patient_id, jti}
    GW-->>GW: proceed with authorized request
```

---

### Write Audit Record

```mermaid
sequenceDiagram
    actor D as Doctor
    participant GW as Gateway
    participant POL as Policy
    participant AS as AuditService
    participant US as UserStore
    participant KEK as KEK
    participant ENV as Envelope
    participant NA as Node A
    participant NB as Node B
    participant NC as Node C
    participant EL as endorsements.jsonl

    D->>GW: POST /api/audit/access {patient_id, action_type, details}
    GW->>GW: verify JWT -> role = doctor
    GW->>POL: can_create_record("doctor")
    POL-->>GW: allowed
    GW->>AS: create_audit_record(actor, patient_id, action_type, details)

    AS->>NA: GET /head
    AS->>NB: GET /head
    AS->>NC: GET /head
    Note over AS: _agreed_head(): pick majority height + prev_hash<br/>guards against split-brain

    AS->>US: all_reader_pems(patient_id)
    Note over US: readers = patient owner<br/>+ all audit_company users<br/>+ all admin users<br/>doctors intentionally excluded from readers
    US-->>AS: {patient_01: RSA_pub, audit_co_01: RSA_pub, admin_01: RSA_pub}

    AS->>ENV: encrypt_record_payload(payload, patient_id, reader_pems)
    ENV->>ENV: generate random 32-byte AES-256 data key
    ENV->>ENV: AES-256-GCM encrypt -> nonce (12 B) + ciphertext + tag (16 B)
    ENV->>ENV: SHA-256(patient_id) -> patient_id_hash
    ENV->>ENV: RSA-OAEP-SHA256 wrap AES key x3 readers
    ENV-->>AS: EnvelopeResult {nonce, ct, tag, wrapped_keys, patient_id_hash}

    AS->>AS: build block {version, block_id, height, timestamp, previous_hash, record}

    AS->>US: actor_private_b64(doctor_id)
    US->>KEK: kek_decrypt(ed25519_private_enc blob)
    KEK-->>US: plaintext Ed25519 private bytes
    US-->>AS: Ed25519 private key

    AS->>AS: Ed25519 sign sig-header (excl actor_sig + current_hash) -> actor_signature
    AS->>AS: SHA-256 full header including actor_signature -> current_hash

    par Broadcast to all 3 nodes simultaneously
        AS->>NA: POST /blocks {complete signed block JSON}
        NA->>NA: validate_candidate: check height + prev_hash + recompute SHA-256
        NA->>NA: chain.append -> write to chain.jsonl (RLock)
        NA->>NA: Ed25519 sign block header with node A private key
        NA-->>AS: {node_id: A, endorsement: Ed25519_sig_b64}
    and
        AS->>NB: POST /blocks {complete signed block JSON}
        NB->>NB: validate_candidate + append + sign with node B key
        NB-->>AS: {node_id: B, endorsement: Ed25519_sig_b64}
    and
        AS->>NC: POST /blocks {complete signed block JSON}
        NC->>NC: validate_candidate + append + sign with node C key
        NC-->>AS: {node_id: C, endorsement: Ed25519_sig_b64}
    end

    AS->>AS: count endorsements = 3, QUORUM = 2 -> committed
    AS->>EL: append {block_id, height, ts, endorsements[3]} to endorsements.jsonl
    AS-->>GW: {block_id, height, endorsements: 3}
    GW-->>D: 201 Created {block_id, height}
```

---

### Query Records

```mermaid
sequenceDiagram
    actor P as Patient or Audit Company
    participant GW as Gateway
    participant POL as Policy
    participant AS as AuditService
    participant NA as Node A
    participant NB as Node B
    participant NC as Node C
    participant US as UserStore
    participant KEK as KEK
    participant ENV as Envelope

    P->>GW: GET /api/audit/patient/patient_01  Bearer token
    GW->>GW: verify JWT -> role, patient_id
    GW->>POL: can_query_patient(role, requester_patient_id, "patient_01")
    Note over POL: patient: only own patient_id<br/>audit_company / admin: any patient_id
    POL-->>GW: allowed

    GW->>AS: query_records_for_reader(requester, "patient_01")
    GW->>AS: record query in query_audit table

    par Fetch chains from all 3 nodes
        AS->>NA: GET /blocks
        NA-->>AS: chain A blocks
    and
        AS->>NB: GET /blocks
        NB-->>AS: chain B blocks
    and
        AS->>NC: GET /blocks
        NC-->>AS: chain C blocks
    end

    AS->>AS: _majority_chain(): pick longest chain agreed by >= 2 nodes
    AS->>AS: filter blocks where patient_id_hash == SHA-256("patient_01")

    loop for each matching block
        AS->>US: reader_private_pem(requester.user_id)
        US->>KEK: kek_decrypt(rsa_private_enc blob)
        KEK-->>US: RSA-2048 private key PEM
        US-->>AS: RSA private PEM

        AS->>ENV: decrypt_record_payload(record, reader_id, private_pem)
        ENV->>ENV: find wrapped_key where reader_id matches
        ENV->>ENV: RSA-OAEP-SHA256 unwrap -> 32-byte AES data key
        ENV->>ENV: AES-256-GCM decrypt -> verify GCM tag -> plaintext JSON
        ENV-->>AS: {timestamp, patient_id, actor, action_type, details}
    end

    AS-->>GW: [decrypted record list]
    GW-->>P: 200 OK {records: [...]}
```

---

### Integrity Verification

```mermaid
sequenceDiagram
    actor A as Audit Company or Admin
    participant GW as Gateway
    participant POL as Policy
    participant AS as AuditService
    participant NA as Node A
    participant NB as Node B
    participant NC as Node C

    A->>GW: GET /api/verify  Bearer token
    GW->>GW: verify JWT
    GW->>POL: can_verify_integrity(role)
    Note over POL: allowed for audit_company and admin only
    POL-->>GW: allowed

    GW->>AS: verify_integrity()

    par Pull full chains from all nodes
        AS->>NA: GET /blocks
        NA-->>AS: [block_1 ... block_N] chain A
    and
        AS->>NB: GET /blocks
        NB-->>AS: [block_1 ... block_N] chain B
    and
        AS->>NC: GET /blocks
        NC-->>AS: [block_1 ... block_N] chain C
    end

    AS->>AS: _actor_public_index(): build {user_id: Ed25519_pub_key} map from UserStore

    loop for each node chain independently
        AS->>AS: _verify_single_chain(blocks)
        Note over AS: 1. Walk blocks in ascending height order<br/>2. Recompute SHA-256 of full block header<br/>   compare to stored current_hash<br/>3. Verify Ed25519 actor signature<br/>   over sig-header (excl actor_sig + current_hash)<br/>   using actor_public_index lookup<br/>4. Verify hash chain link:<br/>   block[i].previous_hash == block[i-1].current_hash<br/>5. Collect per-block PASS / FAIL result
    end

    AS->>AS: cross-node consistency: compare head hashes of A, B, C
    AS->>AS: flag divergences where hashes disagree
    AS->>AS: compute overall verdict: clean or compromised

    AS-->>GW: {nodes: {A: VALID, B: FAILED, C: VALID}, overall: compromised, network_consistent: True, majority: 2-of-3, divergences: [{node_id, height, detail}]}
    GW-->>A: 200 OK {verification result}
```

---

## Screenshots

### Login page

![Login page](screenshots/image.png)

Bootstrap demo users with one click, or sign up as a patient.

---

### Doctor dashboard

![Doctor dashboard](screenshots/image-13.png)

Doctors can create audit records for their patients and drill down into any patient's history. No access to raw chain hashes or node state.

---

### Patient dashboard

![Patient dashboard](screenshots/image-14.png)

Patients see only their own access-history events: when, what action, which doctor, and any notes. No other patient's data is visible.

---

### Audit company — investigator console

![Audit company dashboard](screenshots/image-10.png)

The audit company sees every record across all patients with patient/action/free-text filters and real-time network status (3/3 nodes online).

---

### Storage nodes overview

![Storage nodes](screenshots/image-6.png)

All three nodes report online with matching chain height and head hash, confirming replication consistency.

---

### Integrity verification — all clean

![Integrity verification passed](screenshots/image-15.png)

After a fresh bootstrap every node reports VALID: chain links ✓, recomputed hashes ✓, actor signatures ✓.

---

### Integrity verification — tamper detected

![Integrity verification failed](screenshots/image-11.png)

After the insider-tamper demo, `node_b` shows FAILED (recomputed hashes ✗, actor signatures ✗) while `node_a` and `node_c` remain VALID. Overall verdict: **compromised**.

---

### Demo terminals

#### Demo 01 — doctor creates six audit records

![Demo 01](screenshots/image-7.png)

Each write gets 3/3 endorsements, height increments atomically across all nodes.

#### Demo 02 — patient queries own audit log

![Demo 02](screenshots/image-8.png)

The gateway decrypts each record with the patient's RSA private key and returns the plaintext JSON.

#### Demo 03 + 04 — access control enforcement

![Demo 03 and 04](screenshots/image-9.png)

Demo 03: `patient_01` is denied access to `patient_02`'s records (HTTP 403). Demo 04: `audit_company_01` successfully retrieves all 6 records across P001/P002/P003.

#### Demo 06 — insider tamper attack

![Demo 06 tamper](screenshots/image-12.png)

Flips a single base64 character in `node_b`'s chain file. Demo 07 (integrity check) then catches the mutation.

---

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
| `audit_company_01` … `audit_company_03` | audit_company | `AuditPass!` |
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


## Limitations / threat model

* The prototype runs over plain HTTP for local demoability.  In production every link (browser↔gateway, gateway↔node) would be TLS.
* `patient_id_hash` is `SHA-256(patient_id)`.  An attacker who can guess patient IDs can join records to a patient.  Production would key the hash with a per-deployment secret (HMAC) or use a tokenization service.
* JWT `jti` revocation is in-memory in the gateway process.  A single restart wipes the deny-list.  Acceptable for a demo; production would persist it to Redis or a database.
* Single-phase commit means a network partition between the gateway and **two** of three nodes briefly stalls writes (the gateway will return a `ConsensusError`).  We trade availability for safety here, which matches medical-records auditing requirements.
