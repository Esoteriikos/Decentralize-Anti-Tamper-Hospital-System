import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from demo.bootstrap import build_system, ensure_users, print_banner, print_verification_report, seed_audit_logs


def main() -> None:
    system = build_system()
    print_banner("DEMO 7: VERIFY DECENTRALIZED LEDGER INTEGRITY")
    ensure_users(system, reset=False)
    if system.nodes.get_record_count() == 0:
        seed_audit_logs(system, reset_ledgers=True)

    report = system.audit.verify_integrity()
    print_verification_report(report)


if __name__ == "__main__":
    main()
