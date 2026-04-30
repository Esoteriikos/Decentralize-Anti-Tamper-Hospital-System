import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from demo.bootstrap import build_system, ensure_users, print_banner, print_verification_report, seed_audit_logs


def main() -> None:
    system = build_system()
    print_banner("DEMO 6: MANUAL TAMPERING ATTACK")
    ensure_users(system, reset=False)
    seed_audit_logs(system, reset_ledgers=True)

    print("Integrity check before tampering:")
    clean_report = system.audit.verify_integrity()
    print_verification_report(clean_report)

    tamper_node = "node_b"
    tamper_index = 2
    ledger = system.nodes.read_ledger(tamper_node)
    original_ciphertext = ledger["records"][tamper_index]["ciphertext"]
    replacement_prefix = "A" if original_ciphertext[0] != "A" else "B"
    tampered_ciphertext = replacement_prefix + original_ciphertext[1:]
    tampered_record = system.nodes.tamper_record(tamper_node, tamper_index, "ciphertext", tampered_ciphertext)

    print(f"\nTampered record {tampered_record['record_id']} on {tamper_node}.")
    print("Attack: modified the encrypted ciphertext in one node ledger without updating the hash chain.")

    print("\nIntegrity check after tampering:")
    attacked_report = system.audit.verify_integrity()
    print_verification_report(attacked_report)


if __name__ == "__main__":
    main()
