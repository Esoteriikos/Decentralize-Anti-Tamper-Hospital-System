# Designing a Secure Decentralized Audit System

Course: `CSCI-531 Applied Cryptography`  
Selected option: `Option 2`  
Project scope: `Secure decentralized audit system for EHR audit logs`

This repository contains a complete semester-project prototype for the assignment described in `Crypto-Final Project.pdf`. The system generates audit records when EHR data is accessed, encrypts sensitive audit contents, authenticates users, enforces role-based authorization, replicates logs across three independent audit nodes, and detects tampering through authenticated encryption plus SHA-256 hash chaining.

## Project Overview

The prototype simulates a decentralized healthcare audit system with four user roles:

- `patient`
- `doctor`
- `audit_company`
- `admin`

Each audit event is split into:

- Plaintext metadata: `record_id`, `node_id`, `nonce`, `tag`, `previous_hash`, `current_hash`
- Encrypted sensitive payload: `timestamp`, `patient_id`, `user_id`, `action_type`, `details`

Every new audit event is encrypted with AES-GCM, hash-linked to the previous event, and replicated to three independent audit ledgers stored under `data/nodes/`.

## Assignment Compliance Checklist

This section maps the implementation directly to the assignment requirements for Option 2.

| Requirement / Goal | Status | Where It Is Implemented | Demo Command That Proves It | Notes |
| --- | --- | --- | --- | --- |
| Privacy: protect sensitive audit records at rest and in transit | Satisfied | `crypto/crypto_manager.py`, `audit/service.py`, `data/nodes/*.json` | `python3 demo/generate_audit_logs_demo.py` | Sensitive fields are encrypted with AES-GCM before replication and storage. |
| Privacy: separate encrypted data from plaintext metadata | Satisfied | `audit/service.py`, `demo/generate_audit_logs_demo.py` | `python3 demo/generate_audit_logs_demo.py` | Stored records expose only `record_id`, `node_id`, nonce, tag, and hash-chain metadata. |
| Identification and authorization: login/authentication | Satisfied | `auth/service.py`, `app.py` | `python3 demo/query_as_patient_demo.py`, `python3 demo/query_as_audit_company_demo.py` | Demo scripts authenticate specific users before queries. |
| Identification and authorization: roles for patient, doctor, audit_company, admin | Satisfied | `auth/service.py`, `audit/service.py` | `python3 demo/create_users_demo.py` | Sample users are created for all required roles. |
| Patients can query only their own audit records | Satisfied | `audit/service.py` | `python3 demo/query_as_patient_demo.py` | Patient role is restricted to `requester.patient_id`. |
| Audit companies can query all patient audit records | Satisfied | `audit/service.py`, `app.py` | `python3 demo/query_as_audit_company_demo.py` | Audit-company role can retrieve all decrypted records. |
| Unauthorized users must be denied access | Satisfied | `audit/service.py`, `app.py` | `python3 demo/unauthorized_query_demo.py` | Doctor query attempt is rejected with an authorization error. |
| Queries return decrypted results only to authorized users | Satisfied | `audit/service.py` | `python3 demo/query_as_patient_demo.py`, `python3 demo/query_as_audit_company_demo.py` | Decryption happens only after authorization checks pass. |
| Audit record fields: timestamp, patient ID, user ID, action type | Satisfied | `audit/service.py`, `demo/bootstrap.py` | `python3 demo/generate_audit_logs_demo.py` | Action types are generated from the required set. |
| Encrypt audit record contents before storage | Satisfied | `crypto/crypto_manager.py`, `audit/service.py` | `python3 demo/generate_audit_logs_demo.py` | The ledger stores ciphertext rather than plaintext payloads. |
| Store encrypted record, nonce/IV, authentication tag, previous hash, current hash, node ID | Satisfied | `audit/service.py`, `nodes/service.py` | `python3 demo/generate_audit_logs_demo.py` | Demo prints a stored node record showing these fields. |
| Immutability / tamper detection with hash chaining | Satisfied | `crypto/crypto_manager.py`, `audit/service.py` | `python3 demo/tamper_demo.py` | Each record includes `previous_hash` and `current_hash`. |
| Demo scenario where attacker tampers with an audit record and verification reports attack | Satisfied | `demo/tamper_demo.py`, `audit/service.py`, `nodes/service.py` | `python3 demo/tamper_demo.py` | Tampering breaks both hash verification and AES-GCM authentication. |
| Decentralization: three independent audit nodes | Satisfied | `config.py`, `nodes/service.py`, `data/nodes/` | `python3 demo/generate_audit_logs_demo.py`, `python3 demo/verify_integrity_demo.py` | Three separate ledger files simulate independent audit companies. |
| New audit records replicated across all three nodes | Satisfied | `nodes/service.py`, `audit/service.py` | `python3 demo/generate_audit_logs_demo.py` | Writes are replicated to `node_a`, `node_b`, and `node_c`. |
| Verification compares chains across nodes and detects mismatch | Satisfied | `audit/service.py` | `python3 demo/verify_integrity_demo.py`, `python3 demo/tamper_demo.py` | Verification reports per-node integrity and cross-node mismatch. |
| Client/server style demonstration, even on one machine | Mostly satisfied | `app.py`, `demo/*.py` | `python3 app.py` plus any demo script | Flask provides the server stub; demos mostly exercise the shared service layer directly. |

## Review Findings Against The PDF

### Strongly satisfied areas

- The prototype covers all five project goals named in the PDF: privacy, identification and authorization, queries, immutability, and decentralization.
- The required user counts are implemented exactly: 10 patients, 2 doctors, 3 audit companies, and 1 admin.
- The required demo flows are present and runnable with separate scripts.
- The tamper-detection story is clear and screenshot-friendly, which is useful for both the report and the demo video.

### Missing requirement or weak area

- Weak area: API authentication tokens do not expire. `auth/service.py` includes `issued_at`, but `verify_token()` does not enforce expiration. This is not a failure of the assignment, but it is weaker than a production-grade authentication design.
- Weak area: queries always decrypt from `node_a`. If `node_a` is the corrupted replica while the other two are healthy, the system does not attempt quorum reads or fail over to a clean node. The assignment requires tamper detection, not fault tolerance, so this is acceptable but worth disclosing.
- Weak area: the “in transit” security claim is simulated by encrypting before node replication, but the local Flask server itself does not use TLS. For a one-machine prototype this is acceptable, but the README and report should state this explicitly.
- Weak area: the client/server requirement is only partly demonstrated in the current demos, because the demo scripts call shared Python services directly instead of making HTTP requests to Flask. The server exists and works, but the demos are not API-driven.

### Suggested improvements before submission

- Add one short API demo section to the report that shows `POST /login` and `GET /verify` using `curl` or Postman screenshots.
- Mention explicitly in the written report that AES-GCM provides both confidentiality and integrity for the sensitive payload.
- State clearly that the three nodes are simulated as independent ledger files on one host, which satisfies the prototype requirement but not real distributed deployment.
- If time permits, add token expiration and a small HTTP-based demo client. These are nice improvements, but they are not necessary to satisfy the assignment.
- In the report, frame the lack of TLS, lack of quorum reads, and local key storage as deliberate prototype limitations rather than oversights.

## Project Structure

```text
.
├── README.md
├── app.py
├── auth/
├── audit/
├── crypto/
├── data/
├── demo/
├── models/
├── nodes/
├── report_notes.md
├── requirements.txt
├── storage.py
├── system.py
└── config.py
```

## How To Install

1. Create and activate a virtual environment if desired.
2. Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## How To Run

### Run the Flask server

```bash
python3 app.py
```

The API will start on [http://127.0.0.1:5310](http://127.0.0.1:5310).

Suggested professor demo order:

```bash
python3 demo/create_users_demo.py
python3 demo/generate_audit_logs_demo.py
python3 demo/query_as_patient_demo.py
python3 demo/query_as_audit_company_demo.py
python3 demo/unauthorized_query_demo.py
python3 demo/tamper_demo.py
python3 demo/generate_audit_logs_demo.py
python3 demo/verify_integrity_demo.py
```

The second `generate_audit_logs_demo.py` resets the ledgers back to a clean state after the tamper demonstration.

### Run the demo scripts

```bash
python3 demo/create_users_demo.py
python3 demo/generate_audit_logs_demo.py
python3 demo/query_as_patient_demo.py
python3 demo/query_as_audit_company_demo.py
python3 demo/unauthorized_query_demo.py
python3 demo/tamper_demo.py
python3 demo/verify_integrity_demo.py
```

## Demo Scripts And Expected Output

### `python3 demo/create_users_demo.py`

Creates a fresh sample user dataset and resets all three node ledgers.

Expected output highlights:

- `patient: 10`
- `doctor: 2`
- `audit_company: 3`
- `admin: 1`
- demo passwords for each role

### `python3 demo/generate_audit_logs_demo.py`

Creates encrypted audit records and replicates them to `node_a`, `node_b`, and `node_c`.

Expected output highlights:

- `Generated 18 audit records`
- preview of decrypted logical records
- stored node record showing `ciphertext`, `tag`, `previous_hash`, and `current_hash`

### `python3 demo/query_as_patient_demo.py`

Authenticates `patient_01` and returns only records for patient `P001`.

Expected output highlights:

- `Authenticated user: patient_01`
- only records where `patient_id=P001`
- decrypted output visible only after successful authentication and authorization

### `python3 demo/query_as_audit_company_demo.py`

Authenticates `audit_company_01` and returns decrypted records across all patients.

Expected output highlights:

- `Authenticated user: audit_company_01`
- records for multiple patient IDs
- decrypted output visible for the audit-company role

### `python3 demo/unauthorized_query_demo.py`

Authenticates a doctor and attempts an unauthorized audit query.

Expected output highlights:

- `Authenticated user: doctor_01`
- `Access denied as expected`

### `python3 demo/tamper_demo.py`

Seeds clean ledgers, verifies them, manually edits ciphertext in one node ledger, and verifies again.

Expected output highlights:

- `All checks passed: True` before tampering
- `Tampered record AUDIT-0003 on node_b`
- `All checks passed: False` after tampering
- mismatch or authentication-failure messages

### `python3 demo/verify_integrity_demo.py`

Runs the verification routine against the current decentralized node state.

Expected output highlights:

- clean state: `All checks passed: True`
- tampered state: `All checks passed: False`

## Privacy Implementation

- Sensitive audit fields are encrypted with `AES-GCM`.
- The encrypted payload contains `timestamp`, `patient_id`, `user_id`, `action_type`, and `details`.
- AES-GCM provides confidentiality and integrity for the sensitive payload.
- Because encryption happens before replication, the same protected record is kept encrypted during simulated transit and at rest.
- Plaintext metadata is intentionally minimal and excludes patient identity and event content.

## Authorization Implementation

- User passwords are hashed with Werkzeug password hashing.
- Users must authenticate before performing privileged operations.
- Roles are enforced in code.
- `patient`: can query only their own records.
- `doctor`: can generate audit events but cannot query audit ledgers.
- `audit_company`: can query all patient audit records and run verification.
- `admin`: can generate audit events and query all records.

## Query Restrictions

- A patient query is allowed only when `requester.patient_id == requested_patient_id`.
- Audit companies can retrieve all patient audit records.
- Unauthorized users receive an authorization error instead of decrypted output.

## Tamper Detection

- Each record stores `previous_hash` and `current_hash`.
- `current_hash` is SHA-256 over the record metadata and encrypted payload fields.
- The verification routine checks whether each `current_hash` recomputes correctly.
- The verification routine checks whether each `previous_hash` links to the prior record.
- The verification routine checks whether AES-GCM decryption/authentication still succeeds.
- The verification routine checks whether all three node ledgers still match.
- The tamper demo manually edits ciphertext in one node ledger, and verification reports the attack.

## Decentralization Simulation

- Three independent audit nodes are simulated with separate ledger files.
- `data/nodes/node_a_ledger.json`
- `data/nodes/node_b_ledger.json`
- `data/nodes/node_c_ledger.json`
- Each new audit record is replicated to all three nodes.
- Verification compares ledgers across nodes and reports divergence.
- The code runs locally, but the structure treats the ledgers as independent organizations.

## Files That Implement Each Goal

### Privacy

- `crypto/crypto_manager.py`
- `audit/service.py`
- `demo/generate_audit_logs_demo.py`

### Identification and authorization

- `auth/service.py`
- `app.py`
- `audit/service.py`
- `demo/create_users_demo.py`
- `demo/unauthorized_query_demo.py`

### Queries

- `audit/service.py`
- `app.py`
- `demo/query_as_patient_demo.py`
- `demo/query_as_audit_company_demo.py`

### Immutability / tamper detection

- `crypto/crypto_manager.py`
- `audit/service.py`
- `nodes/service.py`
- `demo/tamper_demo.py`
- `demo/verify_integrity_demo.py`

### Decentralization

- `config.py`
- `nodes/service.py`
- `data/nodes/`
- `audit/service.py`

## API Summary

### `POST /login`

Request body:

```json
{
  "username": "audit_company_01",
  "password": "AuditPass!"
}
```

### `POST /audit/access`

Requires `Authorization: Bearer <token>`.

Request body:

```json
{
  "patient_id": "P001",
  "action_type": "query",
  "details": "doctor_01 performed query on the medication history section for P001."
}
```

### `GET /audit/patient/<patient_id>`

Requires `Authorization: Bearer <token>`.

### `GET /audit/all`

Requires `Authorization: Bearer <token>`.

### `GET /verify`

Requires `Authorization: Bearer <token>` and role `audit_company` or `admin`.

## Assumptions And Limitations

- The project stores cryptographic material locally in `data/secrets.json`; a real deployment would use an HSM or dedicated key management system.
- The three nodes are simulated on one machine rather than on separate hosts.
- The API runs over local HTTP; the prototype demonstrates transport protection conceptually by encrypting before replication, but a real deployment should also use TLS.
- The system uses full-record queries rather than searchable encrypted indexes.
- Consensus, fault tolerance, and real blockchain networking are not implemented; decentralization is simulated through independent replicated ledgers plus cross-node verification.
- Authentication tokens are signed but do not expire.
- Queries currently read from the primary replica rather than performing quorum selection across nodes.

## External Packages And Attribution

Written specifically for this project:

- authentication, role enforcement, ledger replication, tamper verification, Flask routes, demo scripts, report notes, and project structure

External packages used:

- `Flask`: lightweight web server and API routing
- `cryptography`: AES-GCM authenticated encryption
- `Werkzeug` via Flask: password hashing utilities

No proprietary code was used.

## Submission Notes

- This repository is submission-ready for the Option 2 prototype requirement.
- For the written report, use `report_notes.md` as a starting structure.
- For the demo video, the most important commands to capture are:
  - `python3 demo/create_users_demo.py`
  - `python3 demo/query_as_patient_demo.py`
  - `python3 demo/query_as_audit_company_demo.py`
  - `python3 demo/unauthorized_query_demo.py`
  - `python3 demo/tamper_demo.py`
- After `tamper_demo.py`, run `python3 demo/generate_audit_logs_demo.py` once to restore a clean ledger before any final screenshots.
