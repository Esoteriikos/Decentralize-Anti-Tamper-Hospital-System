"""Demo 02 - patient queries their own audit log."""

import requests

from demo import GATEWAY_URL, auth, banner, expect_status, login, pretty_print_json


def main() -> None:
    banner("Demo 02 - patient_01 queries their own audit log")
    creds = login("patient_01", "PatientPass!")
    token = creds["token"]
    pid = creds["user"]["patient_id"]

    response = requests.get(f"{GATEWAY_URL}/api/audit/patient/{pid}", headers=auth(token), timeout=5)
    expect_status(response, 200, f"audit/patient/{pid}")
    body = response.json()
    print(f"\nReturned {body['count']} record(s) for {pid}:")
    pretty_print_json(body["records"])


if __name__ == "__main__":
    main()
