"""Centralised role policy.

Every authorisation decision in the gateway routes through one of the
predicates in this module so the rules can be reviewed in a single
place.  The matrix mirrors the table in TODO.md / PLAN.md.
"""

from __future__ import annotations

from functools import wraps
from typing import Callable

from errors import AuthorizationError


def can_create_record(role: str) -> bool:
    return role in {"doctor", "admin"}


def can_query_patient(role: str, requester_patient_id: str | None, target_patient_id: str) -> bool:
    if role in {"audit_company", "admin"}:
        return True
    if role == "patient":
        return requester_patient_id == target_patient_id
    return False


def can_query_all(role: str) -> bool:
    return role in {"audit_company", "admin"}


def can_verify_integrity(role: str) -> bool:
    return role in {"audit_company", "admin"}


def can_manage_users(role: str) -> bool:
    return role == "admin"


def role_required(*allowed_roles: str) -> Callable:
    """Decorator factory used by the gateway routes."""

    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapper(requester, *args, **kwargs):
            if requester.role not in allowed_roles:
                raise AuthorizationError(
                    f"Role '{requester.role}' is not permitted; need one of {sorted(allowed_roles)}."
                )
            return view(requester, *args, **kwargs)

        return wrapper

    return decorator
