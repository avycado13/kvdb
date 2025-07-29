import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from flask import Blueprint, current_app, jsonify, render_template, request
from flask_pydantic import validate  # type: ignore

from app.helpers import (
    create_scoped_token,
    filepath,
    is_valid_id,
    list_all_ids,
    load_data,
    log_action,
    rate_limited,
    save_data,
    sign_id,
    verify_scoped_token,
)
from app.models import BulkSetRequest, CreateRequest, Record, SetValueRequest


bp = Blueprint("main", __name__)

RATE_LIMIT: Dict[str, List[str]] = {}  # naive in-memory rate limiter


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/create", methods=["POST"])
@validate()
def create(body: CreateRequest):
    if rate_limited(request.remote_addr, RATE_LIMIT):
        return {"error": "Too many requests"}, 429

    id = os.urandom(16).hex()
    password = body.password
    expires_in = int(body.expires)
    if expires_in < 0:
        return {"error": "Expiration time must be non-negative"}, 400

    token_scopes = (
        body.scopes.split(",") if body.scopes else ["read", "write", "delete", "clear"]
    )

    record = Record(
        data={},
        password=sign_id(password) if password else None,
        expires_at=(datetime.now(timezone.utc) + timedelta(seconds=expires_in))
        if expires_in
        else None,
        audit_log=[],
    )
    save_data(id, record)
    token = create_scoped_token(id, token_scopes, expires_in)
    return jsonify({"id": id, "token": token}), 201


@bp.route("/<id>")
def get(id):
    if rate_limited(request.remote_addr, RATE_LIMIT, id):
        return {"error": "Too many requests"}, 429
    if not is_valid_id(id):
        return {"error": "Invalid ID format"}, 400

    token = request.args.get("token")
    if not verify_scoped_token(token, "read"):
        return {"error": "Invalid token"}, 403

    try:
        data = load_data(id)
    except FileNotFoundError:
        return {"error": "ID not found"}, 404

    if data.get("expires_at") and datetime.now(timezone.utc) > datetime.fromisoformat(
        data["expires_at"]
    ):
        os.remove(filepath(id))
        return {"error": "Data expired"}, 410

    # Clean up expired keys
    expired_keys = []
    for key, entry in data.get("data", {}).items():
        if entry.get("expires_at") and datetime.now(
            timezone.utc
        ) > datetime.fromisoformat(entry["expires_at"]):
            expired_keys.append(key)

    for key in expired_keys:
        del data["data"][key]
        log_action(data, "delete_expired", key, request.remote_addr)

    log_action(data, "read_all", ip=request.remote_addr)
    save_data(id, data)

    response_data = {k: v["value"] for k, v in data.get("data", {}).items()}
    if request.accept_mimetypes.accept_html:
        return jsonify(response_data)
    return {"data": response_data}, 200


@bp.route("/set/<id>", methods=["POST"])
@validate()
def set_value(id: str, body: SetValueRequest):
    if rate_limited(request.remote_addr, RATE_LIMIT, id):
        return {"error": "Too many requests"}, 429
    if not is_valid_id(id):
        return {"error": "Invalid ID format"}, 400

    token = request.args.get("token", "")
    if not verify_scoped_token(token, "write"):
        return {"error": "Write permission denied"}, 403

    try:
        data = load_data(id)
    except FileNotFoundError:
        return {"error": "ID not found"}, 404

    key = body.key
    value = body.value
    key_password = body.password
    one_time = body.one_time
    expires_at = body.expires_at

    # Ensure `expires_at` is processed correctly
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    elif isinstance(expires_at, datetime):
        pass  # Already a datetime, no action needed
    else:
        raise TypeError("expires_at must be a string or datetime")

    if expires_at:
        try:
            pass
            if expires_at < datetime.now(timezone.utc):
                return {"error": "Expiration time must be in the future"}, 400
        except ValueError:
            return {"error": "Invalid expiration time format"}, 400

    if not key:
        return {"error": "Missing key"}, 400

    hashed_pw = (
        hmac.new(current_app.config["SECRET_KEY"], key_password.encode(), "sha256").hexdigest()
        if key_password
        else None
    )

    data["data"][key] = {
        "value": value,
        "password": hashed_pw,
        "one_time": one_time,
        "expires_at": expires_at,
    }
    # Correct `log_action` calls to avoid argument conflicts
    log_action(data=data, action="set", key=key, ip=request.remote_addr, token=token)
    record = Record(**data)
    save_data(id, record)
    return {"message": "Value set successfully"}, 200


@bp.route("/get/<id>/<key>")
def get_key(id, key):
    if rate_limited(request.remote_addr, RATE_LIMIT, id):
        return {"error": "Too many requests"}, 429
    if not is_valid_id(id):
        return {"error": "Invalid ID format"}, 400

    token = request.args.get("token")
    password = request.args.get("password")

    if not verify_scoped_token(token, "read"):
        return {"error": "Invalid read token"}, 403

    try:
        data = load_data(id)
        entry = data["data"].get(key)
        if not entry:
            return {"error": "Key not found"}, 404

        if entry.get("password"):
            if not password:
                return {"error": "Password required"}, 401
            hashed_input = hmac.new(
                current_app.config["SECRET_KEY"], password.encode(), "sha256"
            ).hexdigest()
            if not hmac.compare_digest(hashed_input, entry["password"]):
                return {"error": "Incorrect password"}, 403

        if entry.get("expires_at") and datetime.now(
            timezone.utc
        ) > datetime.fromisoformat(entry["expires_at"]):
            del data["data"][key]
            log_action(data, "delete_expired", key, request.remote_addr, token=token)

        value = entry["value"]
        if entry.get("one_time"):
            del data["data"][key]
        log_action(data, "read", key, request.remote_addr, token=token)
        save_data(id, data)
        return {"key": key, "value": value}, 200
    except FileNotFoundError:
        return {"error": "ID not found"}, 404


@bp.route("/delete/<id>", methods=["POST"])
def delete_id(id):
    if rate_limited(request.remote_addr, RATE_LIMIT, id):
        return {"error": "Too many requests"}, 429
    if not is_valid_id(id):
        return {"error": "Invalid ID format"}, 400
    token = request.args.get("token")

    if not verify_scoped_token(token, "clear"):
        return {"error": "Delete permission denied"}, 403
    try:
        os.remove(filepath(id))
        return {"message": "ID deleted successfully"}, 200
    except FileNotFoundError:
        return {"error": "ID not found"}, 404


@bp.route("/delete/<id>/<key>", methods=["POST"])
def delete_key(id, key):
    if rate_limited(request.remote_addr, RATE_LIMIT, id):
        return {"error": "Too many requests"}, 429
    if not is_valid_id(id):
        return {"error": "Invalid ID format"}, 400
    token = request.args.get("token")

    if not verify_scoped_token(token, "delete"):
        return {"error": "Delete permission denied"}, 403
    try:
        data = load_data(id)
        if key in data["data"]:
            del data["data"][key]
            log_action(data, "delete", key, request.remote_addr, token=token)
            record = Record(**data)
            save_data(id, record)
            return {"message": "Key deleted successfully"}, 200
        else:
            return {"error": "Key not found"}, 404
    except FileNotFoundError:
        return {"error": "ID not found"}, 404


@bp.route("/list/<id>")
def list_keys(id):
    if rate_limited(request.remote_addr, RATE_LIMIT, id):
        return {"error": "Too many requests"}, 429
    if not is_valid_id(id):
        return {"error": "Invalid ID format"}, 400
    token = request.args.get("token")
    if not verify_scoped_token(token, "read"):
        return {"error": "Invalid read token"}, 403
    try:
        data = load_data(id)
        return {"keys": list(data["data"].keys())}, 200
    except FileNotFoundError:
        return {"error": "ID not found"}, 404


@bp.route("/bulkset/<id>", methods=["POST"])
@validate()
def bulk_set(id: str, body: BulkSetRequest):
    if rate_limited(request.remote_addr, RATE_LIMIT, id):
        return {"error": "Too many requests"}, 429
    if not is_valid_id(id):
        return {"error": "Invalid ID format"}, 400
    token = request.args.get("token", "")
    if not verify_scoped_token(token, "write"):
        return {"error": "Invalid write token"}, 403

    try:
        data = load_data(id)
        for key, value in body.root.items():
            data["data"][key] = {"value": value, "one_time": False, "password": None}
            # Fix `log_action` in bulk_set
            log_action(
                data=data,
                action="bulk_set",
                key=key,
                ip=request.remote_addr,
                token=token,
            )
        record = Record(**data)
        save_data(id, record)
        return {"message": "Bulk set successful"}, 200
    except Exception as e:
        return {"error": str(e)}, 400


@bp.route("/admin/list-all")
def list_all():
    if rate_limited(request.remote_addr, RATE_LIMIT):
        return {"error": "Too many requests"}, 429
    if request.args.get("admin_key") != current_app.config["ADMIN_KEY"]:
        return {"error": "Unauthorized"}, 403

    all_ids = list_all_ids()
    return {"ids": all_ids}, 200


@bp.route("/admin/nuke", methods=["POST"])
def clear_data():
    if rate_limited(request.remote_addr, RATE_LIMIT):
        return {"error": "Too many requests"}, 429
    if request.args.get("admin_key") != current_app.config["ADMIN_KEY"]:
        return {"error": "Unauthorized"}, 403

    try:
        for filename in os.listdir(current_app.config["DATA_DIR"]):
            os.remove(os.path.join(current_app.config["DATA_DIR"], filename))
        return {"message": "All data Nuked successfully"}, 200
    except Exception as e:
        return {"error": str(e)}, 500


@bp.route("/clear_expired", methods=["POST"])
def clear_expired():
    if rate_limited(request.remote_addr, RATE_LIMIT):
        return {"error": "Too many requests"}, 429
    if request.args.get("admin_key") != current_app.config["ADMIN_KEY"]:
        return {"error": "Unauthorized"}, 403
    try:
        for filename in os.listdir(current_app.config["DATA_DIR"]):
            id = filename.split(".")[0]
            data = load_data(id)
            if data.get("expires_at") and datetime.now(
                timezone.utc
            ) > datetime.fromisoformat(data["expires_at"]):
                os.remove(filepath(id))
            log_action(data, "clear_expired", ip=request.remote_addr, token="admin")
        return {"message": "Expired data cleared successfully"}, 200
    except Exception as e:
        return {"error": str(e)}, 500


@bp.route("/admin")
def admin_panel():
    if rate_limited(request.remote_addr, RATE_LIMIT):
        return {"error": "Too many requests"}, 429
    return render_template("admin.html")


# Suppress `flask_pydantic` missing stubs error
