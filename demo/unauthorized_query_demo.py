import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from demo.bootstrap import build_system, ensure_users, print_banner, seed_audit_logs
from errors import AuthorizationError


def main() -> None:
    system = build_system()
    print_banner("DEMO 5: UNAUTHORIZED QUERY IS DENIED")
    ensure_users(system, reset=False)
    seed_audit_logs(system, reset_ledgers=system.nodes.get_record_count() == 0)

    doctor = system.auth.authenticate("doctor_01", "DoctorPass!")
    print(f"Authenticated user: {doctor.user_id} (role={doctor.role})")
    print("Attempting to query patient P001 audit records as a doctor...")

    try:
        system.audit.query_patient_records(requester=doctor, patient_id="P001")
    except AuthorizationError as exc:
        print(f"Access denied as expected: {exc}")
        return

    raise SystemExit("Unauthorized query unexpectedly succeeded.")


if __name__ == "__main__":
    main()
