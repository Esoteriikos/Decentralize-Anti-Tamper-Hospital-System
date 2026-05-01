"""Demo 05 - doctor tries to query audit logs (must fail).

Doctors can write audit events but cannot read past audit logs - the
envelope encryption only wraps the per-record AES key for the patient
plus the audit companies plus the admin.  This demo proves the policy
layer rejects the doctor's read attempt before it ever reaches storage.
"""

import requests

from demo import GATEWAY_URL, auth, banner, expect_failure, login


def main() -> None:
    banner("Demo 05 - doctor_01 attempts to query audit logs (should be denied)")
    creds = login("doctor_01", "DoctorPass!")
    token = creds["token"]

    response = requests.get(f"{GATEWAY_URL}/api/audit/all", headers=auth(token), timeout=5)
    expect_failure(response, "audit/all as doctor_01", allowed=(403,))

    response = requests.get(f"{GATEWAY_URL}/api/audit/patient/P001", headers=auth(token), timeout=5)
    expect_failure(response, "audit/patient/P001 as doctor_01", allowed=(403,))


if __name__ == "__main__":
    main()
