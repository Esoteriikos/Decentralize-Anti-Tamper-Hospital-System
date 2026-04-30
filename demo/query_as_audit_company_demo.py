import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from demo.bootstrap import build_system, ensure_users, print_banner, print_query_results, seed_audit_logs


def main() -> None:
    system = build_system()
    print_banner("DEMO 4: AUTHORIZED AUDIT COMPANY QUERY")
    ensure_users(system, reset=False)
    seed_audit_logs(system, reset_ledgers=system.nodes.get_record_count() == 0)

    auditor = system.auth.authenticate("audit_company_01", "AuditPass!")
    print(f"Authenticated user: {auditor.user_id} (role={auditor.role})")
    records = system.audit.query_all_patient_records(requester=auditor)
    print(f"\nAudit company query returned {len(records)} decrypted records across all patients.")
    print("First 8 results:")
    print_query_results(records[:8])


if __name__ == "__main__":
    main()
