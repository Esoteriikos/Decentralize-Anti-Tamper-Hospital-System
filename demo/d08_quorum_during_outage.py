"""Demo 08 - prove the system tolerates one node going down.

Calls /api/nodes/health to show which nodes are up, then asks the
doctor to create another audit record.  As long as 2 of 3 nodes are
reachable the gateway can still reach quorum and the write succeeds.

To run this demo: stop the node_c terminal (Ctrl+C in its window), or
in docker compose: `docker compose stop node_c`, then run this script.
"""

import requests

from demo import GATEWAY_URL, auth, banner, expect_status, login


def main() -> None:
    banner("Demo 08 - quorum still works with 1 node down")

    health = requests.get(f"{GATEWAY_URL}/api/nodes/health", timeout=5).json()
    online = [s["node_id"] for s in health if s["online"]]
    offline = [s["node_id"] for s in health if not s["online"]]
    print(f"[health] online={online}, offline={offline}")

    if len(online) < 2:
        print(f"[health] Need at least 2 online nodes for quorum; have {len(online)}.")
        return

    creds = login("doctor_02", "DoctorPass!")
    token = creds["token"]
    response = requests.post(
        f"{GATEWAY_URL}/api/audit/access",
        headers=auth(token),
        json={"patient_id": "P004", "action_type": "query", "details": "quorum demo write"},
        timeout=10,
    )
    expect_status(response, 201, "audit/access during partial outage")
    body = response.json()
    print(
        f"\n[quorum] Wrote {body['record_id']} with {len(body['endorsements'])} endorsements; "
        f"missed nodes: {list(body['broadcast_errors'].keys())}."
    )


if __name__ == "__main__":
    main()
