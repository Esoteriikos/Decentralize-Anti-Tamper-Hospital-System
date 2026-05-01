"""Shared helpers for the demo scripts."""

from __future__ import annotations

import os
import sys
from typing import Optional

import requests

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:5310")


def banner(title: str) -> None:
    bar = "=" * 60
    print()
    print(bar)
    print(f"  {title}")
    print(bar)


def login(username: str, password: str) -> dict:
    response = requests.post(
        f"{GATEWAY_URL}/api/login",
        json={"username": username, "password": password},
        timeout=5,
    )
    if response.status_code != 200:
        print(f"[login] FAILED status={response.status_code} body={response.text}")
        sys.exit(1)
    data = response.json()
    print(f"[login] OK as {data['user']['username']} (role={data['user']['role']})")
    return data


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def pretty_print_json(payload, indent: int = 2) -> None:
    import json

    print(json.dumps(payload, indent=indent, sort_keys=True))


def expect_status(response: requests.Response, expected: int, label: str) -> None:
    if response.status_code != expected:
        print(f"[{label}] UNEXPECTED status={response.status_code}")
        print(response.text)
        sys.exit(1)
    print(f"[{label}] OK (status={expected})")


def expect_failure(response: requests.Response, label: str, allowed: tuple[int, ...] = (401, 403)) -> None:
    if response.status_code in allowed:
        print(f"[{label}] correctly rejected (status={response.status_code})")
        return
    print(f"[{label}] EXPECTED rejection but got status={response.status_code}: {response.text}")
    sys.exit(1)
