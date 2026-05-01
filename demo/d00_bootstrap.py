"""Demo 00 - bootstrap sample users.

Calls POST /api/admin/bootstrap which is open while users.json is empty.
Run this first on a fresh checkout (or after deleting data/).
"""

import requests

from demo import GATEWAY_URL, banner, pretty_print_json


def main() -> None:
    banner("Demo 00 - bootstrap sample users")
    response = requests.post(f"{GATEWAY_URL}/api/admin/bootstrap", json={"reset": False}, timeout=10)
    print(f"[bootstrap] status={response.status_code}")
    pretty_print_json(response.json())


if __name__ == "__main__":
    main()
