"""Demo 01 - doctor creates audit records.

Logs in as doctor_01 and posts six audit records spread across three
patients.  Each call goes through the gateway, which envelope-encrypts
the payload, signs it, and broadcasts to the three audit nodes.
"""

import requests

from demo import GATEWAY_URL, auth, banner, expect_status, login


SCENARIOS = [
    ("P001", "create", "Initial chart created at admission"),
    ("P001", "change", "Updated allergy list"),
    ("P002", "query", "Reviewed last lab results"),
    ("P002", "print", "Printed discharge summary"),
    ("P003", "copy", "Forwarded record to specialist"),
    ("P003", "delete", "Removed duplicate entry"),
]


def main() -> None:
    banner("Demo 01 - doctor creates audit records")
    creds = login("doctor_01", "DoctorPass!")
    token = creds["token"]

    for patient_id, action, details in SCENARIOS:
        response = requests.post(
            f"{GATEWAY_URL}/api/audit/access",
            headers=auth(token),
            json={"patient_id": patient_id, "action_type": action, "details": details},
            timeout=10,
        )
        expect_status(response, 201, f"audit/access {patient_id} {action}")
        body = response.json()
        print(
            f"  -> {body['record_id']} height={body['height']} "
            f"endorsements={len(body['endorsements'])} (errors={list(body['broadcast_errors'].keys())})"
        )


if __name__ == "__main__":
    main()
