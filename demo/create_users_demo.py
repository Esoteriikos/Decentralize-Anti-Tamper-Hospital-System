import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from demo.bootstrap import build_system, ensure_users, print_banner, print_user_counts


def main() -> None:
    system = build_system()
    print_banner("DEMO 1: CREATE SAMPLE USERS")
    ensure_users(system, reset=True)
    system.nodes.reset_ledgers()
    print("Created fresh user dataset and reset all decentralized node ledgers.")
    print_user_counts(system)
    print("\nDemo credentials:")
    print("  - patients: usernames patient_01 ... patient_10 | password: PatientPass!")
    print("  - doctors: usernames doctor_01, doctor_02 | password: DoctorPass!")
    print("  - audit companies: usernames audit_company_01 ... audit_company_03 | password: AuditPass!")
    print("  - admin: username admin_01 | password: AdminPass!")


if __name__ == "__main__":
    main()
