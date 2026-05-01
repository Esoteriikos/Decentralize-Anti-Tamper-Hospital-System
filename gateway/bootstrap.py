"""Demo seeding logic.

Creates the deterministic set of users the assignment asks for:
10 patients, 2 doctors, 3 audit companies, 1 admin.  The function is
called from the API endpoint POST /api/admin/bootstrap and from the
demo CLI scripts.
"""

from __future__ import annotations

from typing import Iterable, Optional

from auth.user_store import UserStore


SAMPLE_PATIENT_PASSWORD = "PatientPass!"
SAMPLE_DOCTOR_PASSWORD = "DoctorPass!"
SAMPLE_AUDIT_PASSWORD = "AuditPass!"
SAMPLE_ADMIN_PASSWORD = "AdminPass!"


def create_sample_users(
    user_store: UserStore,
    reset: bool = False,
    node_clients: Optional[Iterable] = None,
) -> dict:
    """Seed the deterministic demo roster.

    When ``reset=True`` we also wipe each node's chain (if ``node_clients`` is
    provided) because the previous chain's wrapped data keys reference RSA
    public keys that are about to be destroyed -- otherwise readers would see
    a wave of ``InvalidTag`` errors on every record created before the reset.
    """

    if user_store.list_users() and not reset:
        return {"created": False, "reason": "users already exist"}

    if reset:
        user_store.delete_all()
        for client in node_clients or ():
            try:
                client.reset()
            except Exception:  # noqa: BLE001 - reset is best-effort
                pass

    created: list[str] = []

    for index in range(1, 11):
        pid = f"P{index:03d}"
        username = f"patient_{index:02d}"
        user_store.register_user(
            user_id=username,
            username=username,
            role="patient",
            password=SAMPLE_PATIENT_PASSWORD,
            patient_id=pid,
        )
        created.append(username)

    for index in range(1, 3):
        username = f"doctor_{index:02d}"
        user_store.register_user(
            user_id=username,
            username=username,
            role="doctor",
            password=SAMPLE_DOCTOR_PASSWORD,
        )
        created.append(username)

    for index in range(1, 4):
        username = f"audit_company_{index:02d}"
        user_store.register_user(
            user_id=username,
            username=username,
            role="audit_company",
            password=SAMPLE_AUDIT_PASSWORD,
        )
        created.append(username)

    user_store.register_user(
        user_id="admin_01",
        username="admin_01",
        role="admin",
        password=SAMPLE_ADMIN_PASSWORD,
    )
    created.append("admin_01")

    return {
        "created": True,
        "count": len(created),
        "users": created,
        "default_passwords": {
            "patient": SAMPLE_PATIENT_PASSWORD,
            "doctor": SAMPLE_DOCTOR_PASSWORD,
            "audit_company": SAMPLE_AUDIT_PASSWORD,
            "admin": SAMPLE_ADMIN_PASSWORD,
        },
    }
