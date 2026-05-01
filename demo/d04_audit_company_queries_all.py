"""Demo 04 - audit company queries all patient records."""

import requests

from demo import GATEWAY_URL, auth, banner, expect_status, login, pretty_print_json


def main() -> None:
    banner("Demo 04 - audit_company_01 queries all audit records")
    creds = login("audit_company_01", "AuditPass!")
    token = creds["token"]

    response = requests.get(f"{GATEWAY_URL}/api/audit/all", headers=auth(token), timeout=5)
    expect_status(response, 200, "audit/all")
    body = response.json()
    print(f"\nReturned {body['count']} record(s) across all patients.")
    for r in body["records"]:
        print(
            f"  {r['record_id']} | patient={r['patient_id']} | action={r['action_type']} | "
            f"by {r['user_id']} @ {r['timestamp']}"
        )


if __name__ == "__main__":
    main()
