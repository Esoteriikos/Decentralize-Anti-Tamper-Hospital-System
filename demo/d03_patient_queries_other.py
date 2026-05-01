"""Demo 03 - patient tries to query another patient (must fail)."""

import requests

from demo import GATEWAY_URL, auth, banner, expect_failure, login


def main() -> None:
    banner("Demo 03 - patient_01 attempts to read patient_02 (should be denied)")
    creds = login("patient_01", "PatientPass!")
    token = creds["token"]

    response = requests.get(f"{GATEWAY_URL}/api/audit/patient/P002", headers=auth(token), timeout=5)
    expect_failure(response, "audit/patient/P002 as patient_01", allowed=(403,))


if __name__ == "__main__":
    main()
