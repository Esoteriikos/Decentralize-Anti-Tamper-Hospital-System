"""Gateway Flask application.

Combines:

- a JSON REST API used by demo scripts and the web UI's JavaScript
  (mounted at /api/...)
- a small server-rendered web UI built with Jinja templates and
  Bootstrap 5 (mounted at /, /web/...)

Both surfaces share the same JwtService so a user that logs in via the
web form gets the same JWT a CLI script would receive.

Architectural reminder: this server holds **no** audit data.  All
records live on the three node servers.  Killing the gateway loses
nothing besides in-memory state.
"""

from __future__ import annotations

import os
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException

from auth import (
    JwtService,
    UserStore,
    can_create_record,
    can_manage_users,
    can_query_all,
    can_query_patient,
    can_verify_integrity,
)
from audit_log import (
    login_summary,
    record_login_event,
    record_query,
    recent_login_events,
    recent_queries,
)
from config import (
    ALLOW_PATIENT_SIGNUP,
    GATEWAY_HOST,
    GATEWAY_PORT,
    NODE_URLS,
    ROLES,
    ensure_dirs,
)
from db import init_db
from errors import (
    AuditSystemError,
    AuthenticationError,
    AuthorizationError,
    ConsensusError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from .audit_service import AuditService
from .bootstrap import create_sample_users


def create_app() -> Flask:
    ensure_dirs()
    init_db()
    template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "templates")
    static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "static")
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir, static_url_path="/static")
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True
    app.jinja_env.globals["ALLOW_PATIENT_SIGNUP"] = ALLOW_PATIENT_SIGNUP

    user_store = UserStore()
    jwt_service = JwtService()
    audit_service = AuditService(user_store)

    app.config["USER_STORE"] = user_store
    app.config["JWT"] = jwt_service
    app.config["AUDIT"] = audit_service

    # ---------------- error handling ----------------

    @app.errorhandler(AuditSystemError)
    def handle_known(exc):
        code = 400
        if isinstance(exc, AuthenticationError):
            code = 401
        elif isinstance(exc, AuthorizationError):
            code = 403
        elif isinstance(exc, NotFoundError):
            code = 404
        elif isinstance(exc, IntegrityError):
            code = 409
        elif isinstance(exc, ConsensusError):
            code = 503
        elif isinstance(exc, ValidationError):
            code = 400
        if request.path.startswith("/api/"):
            return jsonify({"error": type(exc).__name__, "message": str(exc)}), code
        flash(f"{type(exc).__name__}: {exc}", "danger")
        if "user" not in session:
            target = url_for("web_login")
        elif request.path == url_for("web_dashboard"):
            # avoid redirect loop if dashboard itself errors out
            target = url_for("web_logout")
        else:
            target = url_for("web_dashboard")
        return redirect(target), 302

    @app.errorhandler(Exception)
    def handle_unknown(exc):
        # Don't swallow HTTPException (404/405/etc) -- let Flask render its
        # default response so we don't spam users with "Server error: 404" toasts.
        if isinstance(exc, HTTPException):
            return exc
        import traceback
        traceback.print_exc()
        if request.path.startswith("/api/"):
            return jsonify({"error": "InternalServerError", "message": str(exc)}), 500
        flash(f"Server error: {exc}", "danger")
        return redirect(url_for("web_login"))

    # ---------------- helpers ----------------

    def _bearer_user():
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise AuthenticationError("Missing Bearer token.")
        token = auth_header.removeprefix("Bearer ").strip()
        payload = jwt_service.verify(token)
        return user_store.get(payload["sub"])

    def api_auth(view):
        @wraps(view)
        def wrapper(*a, **kw):
            return view(_bearer_user(), *a, **kw)

        return wrapper

    def web_session_user():
        info = session.get("user")
        if not info:
            return None
        try:
            jwt_service.verify(info["token"])
        except AuthenticationError:
            session.pop("user", None)
            return None
        try:
            return user_store.get(info["user_id"])
        except NotFoundError:
            session.pop("user", None)
            return None

    def web_required(view):
        @wraps(view)
        def wrapper(*a, **kw):
            user = web_session_user()
            if user is None:
                flash("Please sign in.", "info")
                return redirect(url_for("web_login"))
            g.current_user = user
            return view(*a, **kw)

        return wrapper

    # ---------------- API ----------------

    @app.get("/api")
    def api_root():
        return jsonify(
            {
                "service": "Decentralized Audit Gateway",
                "option": "Option 2",
                "nodes": NODE_URLS,
                "endpoints": [
                    "POST /api/login",
                    "POST /api/logout",
                    "POST /api/admin/bootstrap",
                    "POST /api/audit/access",
                    "GET  /api/audit/patient/<patient_id>",
                    "GET  /api/audit/all",
                    "GET  /api/verify",
                    "GET  /api/nodes/health",
                ],
            }
        )

    @app.post("/api/login")
    def api_login():
        body = request.get_json(force=True) or {}
        username = body.get("username", "")
        password = body.get("password", "")
        try:
            user = user_store.authenticate(username, password)
        except AuthenticationError:
            user_store.record_failed_login(username)
            record_login_event(
                user_id=None,
                username_attempted=username,
                outcome="bad_password",
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
            )
            raise
        user_store.reset_failed_logins(user.user_id)
        record_login_event(
            user_id=user.user_id,
            username_attempted=username,
            outcome="success",
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
        token = jwt_service.issue(user)
        return jsonify(
            {
                "token": token["token"],
                "expires_at": token["expires_at"],
                "user": {
                    "user_id": user.user_id,
                    "username": user.username,
                    "role": user.role,
                    "patient_id": user.patient_id,
                },
            }
        )

    @app.post("/api/logout")
    @api_auth
    def api_logout(_):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()
        payload = jwt_service.verify(token)
        jwt_service.revoke(payload["jti"], user_id=payload.get("sub"), expires_at=payload.get("exp"))
        return jsonify({"revoked": payload["jti"]})

    @app.post("/api/admin/bootstrap")
    def api_bootstrap():
        existing = user_store.list_users()
        if existing:
            try:
                requester = _bearer_user()
            except AuthenticationError:
                raise AuthorizationError("Bootstrap is locked because users already exist; admin token required.")
            if not can_manage_users(requester.role):
                raise AuthorizationError("Only admin can re-bootstrap an existing deployment.")
        reset = bool((request.get_json(silent=True) or {}).get("reset"))
        result = create_sample_users(
            user_store,
            reset=reset,
            node_clients=list(audit_service.clients.values()) if reset else None,
        )
        return jsonify(result)

    @app.post("/api/audit/access")
    @api_auth
    def api_create_audit(requester):
        if not can_create_record(requester.role):
            raise AuthorizationError("Only doctors or admins may create audit records.")
        body = request.get_json(force=True) or {}
        result = audit_service.create_audit_record(
            actor=requester,
            patient_id=body["patient_id"],
            action_type=body["action_type"],
            details=body.get("details", ""),
        )
        return jsonify(result), 201

    @app.get("/api/audit/patient/<patient_id>")
    @api_auth
    def api_query_patient(requester, patient_id):
        if not can_query_patient(requester.role, requester.patient_id, patient_id):
            raise AuthorizationError("You are not allowed to read this patient's records.")
        records = audit_service.query_records_for_reader(requester, patient_id)
        record_query(
            actor_user_id=requester.user_id,
            actor_role=requester.role,
            endpoint=request.path,
            method=request.method,
            patient_filter=patient_id,
            result_count=len(records),
            status_code=200,
            ip=request.remote_addr,
        )
        return jsonify({"patient_id": patient_id, "count": len(records), "records": records})

    @app.get("/api/audit/all")
    @api_auth
    def api_query_all(requester):
        if not can_query_all(requester.role):
            raise AuthorizationError("Only audit companies or admins may query all records.")
        records = audit_service.query_records_for_reader(requester, patient_id=None)
        record_query(
            actor_user_id=requester.user_id,
            actor_role=requester.role,
            endpoint=request.path,
            method=request.method,
            patient_filter=None,
            result_count=len(records),
            status_code=200,
            ip=request.remote_addr,
        )
        return jsonify({"count": len(records), "records": records})

    @app.get("/api/verify")
    @api_auth
    def api_verify(requester):
        if not can_verify_integrity(requester.role):
            raise AuthorizationError("Only audit companies or admins may run integrity verification.")
        return jsonify(audit_service.verify_integrity())

    @app.get("/api/nodes/health")
    def api_nodes_health():
        statuses = audit_service.node_statuses()
        return jsonify(
            [
                {
                    "node_id": s.node_id,
                    "url": s.url,
                    "online": s.online,
                    "head": s.head,
                    "public_key": s.public_key,
                    "error": s.error,
                }
                for s in statuses
            ]
        )

    # ---------------- Web UI ----------------

    @app.get("/")
    def web_login():
        if web_session_user() is not None:
            return redirect(url_for("web_dashboard"))
        return render_template("login.html")

    @app.post("/web/login")
    def web_login_submit():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        try:
            user = user_store.authenticate(username, password)
        except AuthenticationError as exc:
            user_store.record_failed_login(username)
            record_login_event(
                user_id=None,
                username_attempted=username,
                outcome="bad_password",
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
            )
            flash(str(exc), "danger")
            return redirect(url_for("web_login"))
        user_store.reset_failed_logins(user.user_id)
        record_login_event(
            user_id=user.user_id,
            username_attempted=username,
            outcome="success",
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
        token = jwt_service.issue(user)
        session["user"] = {
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role,
            "patient_id": user.patient_id,
            "token": token["token"],
        }
        flash(f"Welcome, {user.username} ({user.role}).", "success")
        return redirect(url_for("web_dashboard"))

    @app.get("/web/logout")
    def web_logout():
        info = session.pop("user", None)
        if info:
            try:
                payload = jwt_service.verify(info["token"])
                jwt_service.revoke(payload["jti"], user_id=payload.get("sub"), expires_at=payload.get("exp"))
            except AuthenticationError:
                pass
        flash("Signed out.", "info")
        return redirect(url_for("web_login"))

    @app.post("/web/bootstrap")
    def web_bootstrap():
        existing = user_store.list_users()
        if existing:
            user = web_session_user()
            if user is None or not can_manage_users(user.role):
                flash("Bootstrap requires an admin session when users already exist.", "warning")
                return redirect(url_for("web_login"))
        reset = bool(request.form.get("reset"))
        result = create_sample_users(
            user_store,
            reset=reset,
            node_clients=list(audit_service.clients.values()) if reset else None,
        )
        flash(f"Sample users created: {result.get('count', 0)}.", "success")
        return redirect(url_for("web_login"))

    @app.get("/web/dashboard")
    @web_required
    def web_dashboard():
        user = g.current_user
        context = {
            "user": user,
            "roles": ROLES,
        }
        if user.role == "patient":
            records = audit_service.query_records_for_reader(user, user.patient_id)
            # Patients should never see hashes / nodes / wrapped-key plumbing.
            # We project records down to a plain-language access list.
            simplified = [
                {
                    "timestamp": r.get("timestamp"),
                    "action_type": r.get("action_type"),
                    "details": r.get("details"),
                    "user_id": r.get("user_id"),
                    "undecryptable": r.get("undecryptable", False),
                }
                for r in records
            ]
            record_query(
                actor_user_id=user.user_id,
                actor_role=user.role,
                endpoint=request.path,
                method="GET",
                patient_filter=user.patient_id,
                result_count=len(records),
                status_code=200,
                ip=request.remote_addr,
            )
            context["records"] = simplified
            return render_template("dashboard_patient.html", **context)
        if user.role == "doctor":
            patients = [u for u in user_store.list_users() if u.role == "patient"]
            recent_writes = audit_service.read_endorsement_log(filter_signer=user.user_id, limit=10)
            context["patients"] = patients
            context["recent_writes"] = recent_writes
            return render_template("dashboard_doctor.html", **context)
        if user.role in {"audit_company", "admin"}:
            target_pid = request.args.get("patient_id") or None
            q = (request.args.get("q") or "").strip().lower()
            action_filter = (request.args.get("action") or "").strip()
            records = audit_service.query_records_for_reader(user, target_pid)
            if q:
                records = [
                    r for r in records
                    if q in (r.get("details") or "").lower()
                    or q in (r.get("user_id") or "").lower()
                    or q in (r.get("patient_id") or "").lower()
                ]
            if action_filter:
                records = [r for r in records if r.get("action_type") == action_filter]
            patients = [u for u in user_store.list_users() if u.role == "patient"]
            node_statuses = audit_service.node_statuses()
            record_query(
                actor_user_id=user.user_id,
                actor_role=user.role,
                endpoint=request.path,
                method="GET",
                patient_filter=target_pid,
                result_count=len(records),
                status_code=200,
                ip=request.remote_addr,
            )
            context.update(
                {
                    "records": records,
                    "filter_patient_id": target_pid or "",
                    "filter_q": q,
                    "filter_action": action_filter,
                    "patients": patients,
                    "node_statuses": node_statuses,
                    "is_admin": user.role == "admin",
                    "recent_queries": recent_queries(limit=20),
                }
            )
            return render_template("dashboard_audit.html", **context)
        flash("Unknown role.", "danger")
        return redirect(url_for("web_logout"))

    @app.post("/web/audit/create")
    @web_required
    def web_create_audit():
        user = g.current_user
        if not can_create_record(user.role):
            flash("Only doctors or admins may create audit records.", "danger")
            return redirect(url_for("web_dashboard"))
        patient_id = request.form.get("patient_id", "").strip()
        action_type = request.form.get("action_type", "").strip()
        details = request.form.get("details", "").strip()
        try:
            result = audit_service.create_audit_record(
                actor=user, patient_id=patient_id, action_type=action_type, details=details
            )
            flash(
                f"Created {result['record_id']} at height {result['height']} with {len(result['endorsements'])} endorsements.",
                "success",
            )
        except AuditSystemError as exc:
            flash(f"{type(exc).__name__}: {exc}", "danger")
        return redirect(url_for("web_dashboard"))

    @app.get("/web/verify")
    @web_required
    def web_verify():
        user = g.current_user
        if not can_verify_integrity(user.role):
            flash("Only audit companies or admins may run integrity verification.", "danger")
            return redirect(url_for("web_dashboard"))
        report = audit_service.verify_integrity()
        node_statuses = audit_service.node_statuses()
        return render_template(
            "verify.html", user=user, report=report, node_statuses=node_statuses
        )

    # ---------------- new API endpoints ----------------

    @app.get("/api/me/writes")
    @api_auth
    def api_me_writes(requester):
        if not can_create_record(requester.role):
            raise AuthorizationError("Only writers have a broadcast log.")
        entries = audit_service.read_endorsement_log(filter_signer=requester.user_id, limit=50)
        return jsonify({"signer": requester.user_id, "count": len(entries), "entries": entries})

    @app.get("/api/audit/record/<record_id>")
    @api_auth
    def api_record_detail(requester, record_id):
        detail = audit_service.get_record_detail(record_id, requester)
        if requester.role == "patient":
            payload_pid = (detail.get("plaintext") or {}).get("patient_id")
            if payload_pid and payload_pid != requester.patient_id:
                raise AuthorizationError("You may not read records for other patients.")
            if detail["decrypt_status"] != "ok":
                raise AuthorizationError("This record is not addressed to you.")
        elif requester.role == "doctor":
            # Doctors only see metadata - never plaintext.
            detail["plaintext"] = None
        return jsonify(detail)

    @app.get("/api/nodes/<node_id>/blocks")
    @api_auth
    def api_node_blocks(requester, node_id):
        if not (can_query_all(requester.role) or can_verify_integrity(requester.role)):
            raise AuthorizationError("Only audit companies or admins may inspect node ledgers.")
        per_node = audit_service.list_blocks_per_node()
        if node_id not in per_node:
            raise NotFoundError(f"Unknown node: {node_id}")
        return jsonify({"node_id": node_id, **per_node[node_id]})

    @app.get("/api/admin/users")
    @api_auth
    def api_admin_users(requester):
        if not can_manage_users(requester.role):
            raise AuthorizationError("Only admins may list users.")
        return jsonify(
            {
                "count": len(user_store.list_users()),
                "users": [
                    {
                        "user_id": u.user_id,
                        "username": u.username,
                        "role": u.role,
                        "patient_id": u.patient_id,
                        "locked": u.locked,
                        "failed_logins": u.failed_logins,
                    }
                    for u in user_store.list_users()
                ],
            }
        )

    @app.post("/api/admin/tamper")
    @api_auth
    def api_admin_tamper(requester):
        if not can_manage_users(requester.role):
            raise AuthorizationError("Only admins may simulate tampering.")
        body = request.get_json(force=True) or {}
        result = audit_service.tamper_node_block(
            node_id=body.get("node_id", ""),
            height=int(body.get("height", 0)),
            field=body.get("field", "ciphertext"),
        )
        return jsonify(result)

    # ---------------- new web routes ----------------

    @app.get("/web/record/<record_id>")
    @web_required
    def web_record_detail(record_id):
        user = g.current_user
        try:
            detail = audit_service.get_record_detail(record_id, user)
        except AuditSystemError as exc:
            flash(f"{type(exc).__name__}: {exc}", "danger")
            return redirect(url_for("web_dashboard"))
        if user.role == "doctor":
            detail["plaintext"] = None
        return render_template("record_detail.html", user=user, detail=detail)

    @app.get("/web/nodes")
    @web_required
    def web_nodes():
        user = g.current_user
        if not (can_query_all(user.role) or can_verify_integrity(user.role)):
            flash("Only audit companies or admins may inspect node ledgers.", "warning")
            return redirect(url_for("web_dashboard"))
        per_node = audit_service.list_blocks_per_node()
        node_statuses = audit_service.node_statuses()
        # Build a per-height map for divergence highlighting.
        height_index: dict[int, dict[str, str]] = {}
        for node_id, info in per_node.items():
            for block in info.get("blocks", []):
                h = block.get("height")
                height_index.setdefault(h, {})[node_id] = block.get("current_hash", "")
        diverged_heights = {
            h for h, hashes in height_index.items() if len(set(hashes.values())) > 1
        }
        return render_template(
            "nodes.html",
            user=user,
            per_node=per_node,
            node_statuses=node_statuses,
            diverged_heights=diverged_heights,
        )

    @app.get("/web/admin")
    @web_required
    def web_admin():
        user = g.current_user
        if not can_manage_users(user.role):
            flash("Admin only.", "warning")
            return redirect(url_for("web_dashboard"))
        users = user_store.list_users()
        node_statuses = audit_service.node_statuses()
        per_node = audit_service.list_blocks_per_node()
        return render_template(
            "admin.html",
            user=user,
            users=users,
            node_statuses=node_statuses,
            per_node=per_node,
            recent_logins=recent_login_events(limit=25),
            login_stats=login_summary(days=7),
            recent_queries=recent_queries(limit=25),
        )

    @app.post("/web/admin/tamper")
    @web_required
    def web_admin_tamper():
        user = g.current_user
        if not can_manage_users(user.role):
            flash("Admin only.", "danger")
            return redirect(url_for("web_dashboard"))
        node_id = request.form.get("node_id", "").strip()
        height = request.form.get("height", "1").strip()
        field = request.form.get("field", "ciphertext").strip()
        try:
            audit_service.tamper_node_block(node_id=node_id, height=int(height), field=field)
            flash(
                f"Tampered with {node_id} block height {height} field '{field}'. "
                f"Run integrity check to see detection.",
                "warning",
            )
        except AuditSystemError as exc:
            flash(f"{type(exc).__name__}: {exc}", "danger")
        except Exception as exc:  # noqa: BLE001
            flash(f"Tamper failed: {exc}", "danger")
        return redirect(url_for("web_verify"))

    # ---------- public patient self-signup ----------

    @app.get("/signup")
    def web_signup():
        if not ALLOW_PATIENT_SIGNUP:
            abort(404)
        # Suggest a free patient_id (P011, P012, ... or higher).
        existing_pids = {u.patient_id for u in user_store.list_users() if u.patient_id}
        suggestion = None
        for i in range(1, 1000):
            cand = f"P{i:03d}"
            if cand not in existing_pids:
                suggestion = cand
                break
        return render_template("signup.html", suggested_patient_id=suggestion)

    @app.post("/signup/submit")
    def web_signup_submit():
        if not ALLOW_PATIENT_SIGNUP:
            abort(404)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        patient_id = request.form.get("patient_id", "").strip().upper()
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("web_signup"))
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("web_signup"))
        try:
            user = user_store.create_patient_self_signup(username=username, password=password, patient_id=patient_id)
        except ValidationError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("web_signup"))
        flash(f"Account created for {user.username} ({user.patient_id}).  Please sign in.", "success")
        return redirect(url_for("web_login"))

    # ---------- doctor: per-patient drilldown (writes only) ----------

    @app.get("/web/doctor/patient/<patient_id>")
    @web_required
    def web_doctor_patient(patient_id):
        user = g.current_user
        if user.role not in {"doctor", "admin"}:
            flash("Doctors only.", "warning")
            return redirect(url_for("web_dashboard"))
        target = next(
            (u for u in user_store.list_users() if u.role == "patient" and u.patient_id == patient_id),
            None,
        )
        if target is None:
            flash(f"Unknown patient: {patient_id}", "warning")
            return redirect(url_for("web_dashboard"))
        # Doctors can see their *own writes* on this patient (metadata only).
        my_writes = [
            w for w in audit_service.read_endorsement_log(filter_signer=user.user_id)
            if (w.get("sig_header") or {}).get("record", {}).get("patient_id_hash")
               == __import__("crypto.primitives", fromlist=["sha256_hex"]).sha256_hex(patient_id.encode("utf-8"))
        ]
        return render_template(
            "doctor_patient.html",
            user=user,
            patient=target,
            my_writes=my_writes[:50],
        )

    # ---------- admin user CRUD ----------

    @app.post("/web/admin/user/create")
    @web_required
    def web_admin_user_create():
        user = g.current_user
        if not can_manage_users(user.role):
            flash("Admin only.", "danger")
            return redirect(url_for("web_dashboard"))
        username = request.form.get("username", "").strip()
        role = request.form.get("role", "").strip()
        password = request.form.get("password", "")
        patient_id = (request.form.get("patient_id", "").strip() or None)
        try:
            new_user = user_store.register_user(
                user_id=username,
                username=username,
                role=role,
                password=password,
                patient_id=patient_id,
            )
            flash(f"Created {new_user.username} ({new_user.role}).", "success")
        except ValidationError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("web_admin"))

    @app.post("/web/admin/user/<user_id>/lock")
    @web_required
    def web_admin_user_lock(user_id):
        u = g.current_user
        if not can_manage_users(u.role):
            flash("Admin only.", "danger")
            return redirect(url_for("web_dashboard"))
        action = request.form.get("action", "lock")
        try:
            user_store.set_locked(user_id, locked=(action == "lock"))
            flash(f"{user_id} {'locked' if action == 'lock' else 'unlocked'}.", "success")
        except NotFoundError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("web_admin"))

    @app.post("/web/admin/user/<user_id>/delete")
    @web_required
    def web_admin_user_delete(user_id):
        u = g.current_user
        if not can_manage_users(u.role):
            flash("Admin only.", "danger")
            return redirect(url_for("web_dashboard"))
        if user_id == u.user_id:
            flash("You can't delete your own account while signed in.", "warning")
            return redirect(url_for("web_admin"))
        try:
            user_store.delete_user(user_id)
            flash(f"{user_id} deleted.", "success")
        except NotFoundError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("web_admin"))

    @app.post("/web/admin/chain/reset")
    @web_required
    def web_admin_chain_reset():
        u = g.current_user
        if not can_manage_users(u.role):
            flash("Admin only.", "danger")
            return redirect(url_for("web_dashboard"))
        for client in audit_service.clients.values():
            try:
                client.reset()
            except Exception as exc:  # noqa: BLE001
                flash(f"{client.node_id}: reset failed ({exc})", "warning")
        flash("Audit chains reset on all reachable nodes.", "success")
        return redirect(url_for("web_admin"))

    return app


def main() -> None:  # pragma: no cover
    app = create_app()
    print(f"[gateway] listening on http://{GATEWAY_HOST}:{GATEWAY_PORT}")
    app.run(host=GATEWAY_HOST, port=GATEWAY_PORT, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":  # pragma: no cover
    main()
