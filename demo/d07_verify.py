"""Demo 07 - run integrity verification and observe the tamper detection."""

import requests

from demo import GATEWAY_URL, auth, banner, login, pretty_print_json


def main() -> None:
    banner("Demo 07 - audit_company_01 runs /api/verify across all three nodes")
    creds = login("audit_company_01", "AuditPass!")
    token = creds["token"]

    response = requests.get(f"{GATEWAY_URL}/api/verify", headers=auth(token), timeout=10)
    print(f"[verify] status={response.status_code}")
    body = response.json()
    print(f"\nall_checks_passed = {body.get('all_checks_passed')}")
    print(f"network_consistent = {body.get('network_consistent')}")
    print(f"majority_nodes     = {body.get('majority_nodes')}")
    print()
    for node_id, report in body.get("per_node", {}).items():
        if report.get("online") is False:
            print(f"  {node_id}: OFFLINE ({report.get('error')})")
            continue
        flag = "✓" if report.get("valid") else "✗"
        print(
            f"  {flag} {node_id}: blocks={report.get('block_count')}, "
            f"chain={report.get('valid_chain')}, hashes={report.get('valid_hashes')}, "
            f"sigs={report.get('valid_actor_signatures')}"
        )
        for issue in report.get("issues", []):
            print(f"      ! {issue}")
    if body.get("divergences"):
        print("\nCross-node divergences:")
        pretty_print_json(body["divergences"])


if __name__ == "__main__":
    main()
