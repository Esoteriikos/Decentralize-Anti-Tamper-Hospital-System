from functools import wraps

from flask import Flask, jsonify, request

from errors import AuthenticationError, AuthorizationError, IntegrityError, ValidationError
from system import AuditSystem


app = Flask(__name__)
system = AuditSystem()


def require_auth(handler):
    @wraps(handler)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise AuthenticationError("Missing Bearer token.")
        token = auth_header.removeprefix("Bearer ").strip()
        requester = system.auth.verify_token(token)
        return handler(requester, *args, **kwargs)

    return wrapper


@app.errorhandler(AuthenticationError)
@app.errorhandler(AuthorizationError)
@app.errorhandler(IntegrityError)
@app.errorhandler(ValidationError)
def handle_known_errors(exc):
    code_map = {
        AuthenticationError: 401,
        AuthorizationError: 403,
        IntegrityError: 409,
        ValidationError: 400,
    }
    return jsonify({"error": type(exc).__name__, "message": str(exc)}), code_map[type(exc)]


@app.errorhandler(Exception)
def handle_unknown_errors(exc):
    return jsonify({"error": "InternalServerError", "message": str(exc)}), 500


@app.get("/")
def index():
    return jsonify(
        {
            "project": "Designing a Secure Decentralized Audit System",
            "selected_option": "Option 2",
            "available_routes": [
                "POST /login",
                "POST /audit/access",
                "GET /audit/patient/<patient_id>",
                "GET /audit/all",
                "GET /verify",
            ],
        }
    )


@app.post("/login")
def login():
    payload = request.get_json(force=True)
    user = system.auth.authenticate(payload["username"], payload["password"])
    token = system.auth.issue_token(user)
    return jsonify(
        {
            "message": "Login successful.",
            "token": token,
            "user": {
                "user_id": user.user_id,
                "role": user.role,
                "patient_id": user.patient_id,
            },
        }
    )


@app.post("/audit/access")
@require_auth
def create_audit_record(requester):
    payload = request.get_json(force=True)
    created_record = system.audit.create_audit_record(
        actor=requester,
        patient_id=payload["patient_id"],
        action_type=payload["action_type"],
        details=payload["details"],
        timestamp=payload.get("timestamp"),
    )
    return jsonify({"message": "Audit record generated and replicated to all nodes.", "record": created_record})


@app.get("/audit/patient/<patient_id>")
@require_auth
def query_patient(requester, patient_id):
    records = system.audit.query_patient_records(requester=requester, patient_id=patient_id)
    return jsonify({"patient_id": patient_id, "count": len(records), "records": records})


@app.get("/audit/all")
@require_auth
def query_all(requester):
    records = system.audit.query_all_patient_records(requester=requester)
    return jsonify({"count": len(records), "records": records})


@app.get("/verify")
@require_auth
def verify_integrity(requester):
    if requester.role not in {"audit_company", "admin"}:
        raise AuthorizationError("Only audit companies or admins may run integrity verification.")
    return jsonify(system.audit.verify_integrity())


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5310)
