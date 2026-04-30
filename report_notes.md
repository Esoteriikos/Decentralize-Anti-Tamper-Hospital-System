# Report Notes For Semester Project

## First Page Notes

- Project title: `Designing a Secure Decentralized Audit System`
- Selected option: `Option 2`
- Partner: `None` unless you are submitting with a teammate

## Suggested Report Outline

### 1. System Workflow

- Doctor or admin accesses an EHR record.
- The audit generator builds a sensitive JSON payload containing timestamp, patient ID, user ID, action type, and details.
- The payload is encrypted with AES-GCM before leaving the audit generator.
- The system computes a SHA-256 hash over the encrypted record metadata and links it to the previous record hash.
- The logical record is replicated across three independent audit nodes.
- Patients query only their own records after authentication.
- Audit companies query all records and can run integrity verification across nodes.

### 2. System Architecture

- `auth/`: authentication and role-aware authorization
- `crypto/`: AES-GCM encryption, decryption, and SHA-256 hashing
- `audit/`: record creation, query processing, and integrity verification
- `nodes/`: decentralized ledger storage and replication across three node files
- `app.py`: Flask server stub
- `demo/`: client-side demo scripts for screenshots and video

### 3. Cryptographic Components

- AES-GCM for confidentiality and integrity of sensitive audit payloads
- SHA-256 for hash chaining and tamper detection
- password hashing with Werkzeug
- HMAC-signed bearer tokens for the Flask API

### 4. How The System Meets The Requirements

- Privacy: sensitive fields are encrypted before storage and replication
- Identification and authorization: login is required and role checks are enforced
- Queries: patients can query only their own logs; audit companies can query all
- Immutability: tampering changes hash values or breaks AES-GCM authentication
- Decentralization: three independent node ledgers store replicated copies and are compared during verification

### 5. Assumptions And Limitations

- local single-machine deployment
- local key storage
- no TLS in the local demo
- no full blockchain consensus layer
- simplified user management and fixed sample credentials

### 6. Implementation Notes

- Show screenshots from:
  - `create_users_demo.py`
  - `generate_audit_logs_demo.py`
  - `query_as_patient_demo.py`
  - `query_as_audit_company_demo.py`
  - `unauthorized_query_demo.py`
  - `tamper_demo.py`
  - `verify_integrity_demo.py`
- Include one screenshot of a stored ledger record to show encrypted fields and hashes.
- Include one screenshot of a failed integrity report after tampering.

## References To Cite

- The course PDF assignment itself
- Flask documentation
- cryptography library documentation for AES-GCM
- any academic blockchain/EHR references you choose to discuss in the paper
