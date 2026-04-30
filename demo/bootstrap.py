from datetime import datetime, timedelta

from config import ALLOWED_ACTIONS, NODE_IDS
from system import AuditSystem


def build_system() -> AuditSystem:
    return AuditSystem()


def print_banner(title: str) -> None:
    border = "=" * 88
    print(f"\n{border}\n{title}\n{border}")


def print_user_counts(system: AuditSystem) -> None:
    users = system.auth.list_users()
    counts: dict[str, int] = {}
    for user in users:
        counts[user.role] = counts.get(user.role, 0) + 1
    print("User counts by role:")
    for role in ["patient", "doctor", "audit_company", "admin"]:
        print(f"  - {role}: {counts.get(role, 0)}")


def ensure_users(system: AuditSystem, reset: bool = False) -> None:
    system.auth.create_sample_users(reset=reset)


def seed_audit_logs(system: AuditSystem, reset_ledgers: bool = False) -> list[dict]:
    ensure_users(system, reset=False)
    if reset_ledgers:
        system.nodes.reset_ledgers()
    elif system.nodes.get_record_count() > 0:
        return system.audit.query_all_patient_records(system.auth.get_user_by_id("admin_01"))

    patients = [user for user in system.auth.list_users() if user.role == "patient"]
    doctors = [
        system.auth.get_user_by_id("doctor_01"),
        system.auth.get_user_by_id("doctor_02"),
    ]
    sections = [
        "medication history",
        "lab results",
        "allergy list",
        "discharge summary",
        "radiology report",
        "insurance attachment",
    ]
    base_time = datetime(2026, 4, 29, 18, 0, 0)
    created_records = []

    for index in range(18):
        patient = patients[index % len(patients)]
        doctor = doctors[index % len(doctors)]
        action_type = ALLOWED_ACTIONS[index % len(ALLOWED_ACTIONS)]
        section = sections[index % len(sections)]
        timestamp = (base_time + timedelta(minutes=11 * index)).isoformat(timespec="seconds") + "Z"
        details = f"{doctor.user_id} performed {action_type} on the {section} section for {patient.patient_id}."
        created_records.append(
            system.audit.create_audit_record(
                actor=doctor,
                patient_id=patient.patient_id,
                action_type=action_type,
                details=details,
                timestamp=timestamp,
            )
        )

    return created_records


def print_query_results(records: list[dict]) -> None:
    for record in records:
        print(
            f"  - {record['record_id']} | {record['timestamp']} | patient={record['patient_id']} "
            f"| actor={record['user_id']} | action={record['action_type']}"
        )
        print(f"    details: {record['details']}")


def print_verification_report(report: dict) -> None:
    print(f"All checks passed: {report['all_checks_passed']}")
    print(f"Network consistent across {len(NODE_IDS)} nodes: {report['network_consistent']}")
    for node_id, node_report in report["per_node"].items():
        print(f"\nNode: {node_id}")
        print(f"  - record_count: {node_report['record_count']}")
        print(f"  - valid_hashes: {node_report['valid_hashes']}")
        print(f"  - valid_chain: {node_report['valid_chain']}")
        print(f"  - decryptable_records: {node_report['decryptable_records']}")
        if node_report["issues"]:
            print("  - issues:")
            for issue in node_report["issues"]:
                print(f"      * {issue}")
    if report["network_mismatches"]:
        print("\nNetwork mismatches:")
        for issue in report["network_mismatches"]:
            print(f"  - {issue}")

