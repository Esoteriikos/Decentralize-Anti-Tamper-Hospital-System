import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from demo.bootstrap import build_system, print_banner, print_query_results, seed_audit_logs


def main() -> None:
    system = build_system()
    print_banner("DEMO 2: GENERATE ENCRYPTED AUDIT LOGS")
    created_records = seed_audit_logs(system, reset_ledgers=True)
    print(f"Generated {len(created_records)} audit records and replicated each record to all 3 audit nodes.")
    print("\nDecrypted preview of the first 5 logical audit events:")
    print_query_results(created_records[:5])

    ledger = system.nodes.read_ledger("node_a")
    first_stored_record = ledger["records"][0]
    print("\nStored record on node_a (plaintext metadata + encrypted payload):")
    for key in ["record_id", "node_id", "nonce", "ciphertext", "tag", "previous_hash", "current_hash"]:
        print(f"  - {key}: {first_stored_record[key]}")


if __name__ == "__main__":
    main()
