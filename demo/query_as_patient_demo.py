import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from demo.bootstrap import build_system, ensure_users, print_banner, print_query_results, seed_audit_logs


def main() -> None:
    system = build_system()
    print_banner("DEMO 3: AUTHORIZED PATIENT QUERY")
    ensure_users(system, reset=False)
    seed_audit_logs(system, reset_ledgers=system.nodes.get_record_count() == 0)

    patient = system.auth.authenticate("patient_01", "PatientPass!")
    print(f"Authenticated user: {patient.user_id} (role={patient.role}, patient_id={patient.patient_id})")
    records = system.audit.query_patient_records(requester=patient, patient_id=patient.patient_id)
    print(f"\nPatient query returned {len(records)} decrypted records for {patient.patient_id}:")
    print_query_results(records)


if __name__ == "__main__":
    main()
