from flask import jsonify, request, render_template_string, Flask
import hmac
import os
from typing import Dict, List

from datetime import datetime, timedelta, timezone
from app.helpers import (
    is_valid_id,
    sign_id,
    verify_signature,
    load_data,
    save_data,
    rate_limited,
    log_action,
    list_all_ids,
    filepath,
)

app = Flask(__name__)

DATA_DIR = "data"

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["ADMIN_KEY"] = os.environ.get("ADMIN_KEY", "default_admin")
app.config["DATA_DIR"] = os.environ.get("DATA_DIR", DATA_DIR)

os.makedirs(app.config["DATA_DIR"], exist_ok=True)

RATE_LIMIT: Dict[str, List[str]] = {}  # naive in-memory rate limiter


@app.route("/")
def index():
    return "Hello, World!"


@app.route("/create", methods=["POST"])
def create():
    if rate_limited(request.remote_addr, RATE_LIMIT):
        return {"error": "Too many requests"}, 429
        
    id = os.urandom(16).hex()
    password = request.form.get("password")
    expires_in = int(request.form.get("expires", 0))

    record = {
        "data": {},
        "password": hmac.new(
            app.config["SECRET_KEY"], password.encode(), "sha256"
        ).hexdigest()
        if password
        else None,
        "expires_at": (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()
        if expires_in
        else None,
        "audit_log": [],
    }
    save_data(id, record)
    signature = sign_id(id)
    return jsonify({"id": id, "signature": signature}), 201


@app.route("/<id>")
def get(id):
    if not is_valid_id(id):
        return {"error": "Invalid ID format"}, 400
    if rate_limited(request.remote_addr, RATE_LIMIT, id):
        return {"error": "Too many requests"}, 429

    signature = request.args.get("sig")
    if not verify_signature(id, signature):
        return {"error": "Invalid signature"}, 403

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
        return render_template_string(
            """
            <h1>Stored Data</h1>
            <ul>{% for k,v in data.items() %}<li><b>{{k}}:</b> {{v}}</li>{% endfor %}</ul>
        """,
            data=response_data,
        )
    return {"data": response_data}, 200


@app.route("/set/<id>", methods=["POST"])
def set_value(id):
    if not is_valid_id(id):
        return {"error": "Invalid ID format"}, 400
    if rate_limited(request.remote_addr, RATE_LIMIT, id):
        return {"error": "Too many requests"}, 429

    signature = request.args.get("sig")
    if not verify_signature(id, signature):
        return {"error": "Invalid signature"}, 403

    try:
        data = load_data(id)
    except FileNotFoundError:
        return {"error": "ID not found"}, 404

    key = request.form.get("key")
    value = request.form.get("value")
    key_password = request.form.get("password")
    one_time = request.form.get("one_time") == "true"
    expires_at = request.form.get("expires_at")

    if expires_at:
        try:
            expires_at = datetime.fromisoformat(expires_at)
            if expires_at < datetime.now(timezone.utc):
                return {"error": "Expiration time must be in the future"}, 400
        except ValueError:
            return {"error": "Invalid expiration time format"}, 400

    if not key:
        return {"error": "Missing key"}, 400

    hashed_pw = (
        hmac.new(app.config["SECRET_KEY"], key_password.encode(), "sha256").hexdigest()
        if key_password
        else None
    )

    data["data"][key] = {
        "value": value,
        "password": hashed_pw,
        "one_time": one_time,
        "expires_at": expires_at,
    }
    log_action(data, "set", key, request.remote_addr)
    save_data(id, data)
    return {"message": "Value set successfully"}, 200


@app.route("/get/<id>/<key>")
def get_key(id, key):
    signature = request.args.get("sig")
    password = request.args.get("password")

    if not verify_signature(id, signature):
        return {"error": "Invalid signature"}, 403

    try:
        data = load_data(id)
        entry = data["data"].get(key)
        if not entry:
            return {"error": "Key not found"}, 404

        if entry.get("password"):
            if not password:
                return {"error": "Password required"}, 401
            hashed_input = hmac.new(
                app.config["SECRET_KEY"], password.encode(), "sha256"
            ).hexdigest()
            if not hmac.compare_digest(hashed_input, entry["password"]):
                return {"error": "Incorrect password"}, 403

        if entry.get("expires_at") and datetime.now(
            timezone.utc
        ) > datetime.fromisoformat(entry["expires_at"]):
            del data["data"][key]
            log_action(data, "delete_expired", key, request.remote_addr)

        value = entry["value"]
        if entry.get("one_time"):
            del data["data"][key]
        log_action(data, "read", key, request.remote_addr)
        save_data(id, data)
        return {"key": key, "value": value}, 200
    except FileNotFoundError:
        return {"error": "ID not found"}, 404


@app.route("/delete/<id>", methods=["POST"])
def delete_id(id):
    signature = request.args.get("sig")
    if not verify_signature(id, signature):
        return {"error": "Invalid signature"}, 403
    try:
        os.remove(filepath(id))
        return {"message": "ID deleted successfully"}, 200
    except FileNotFoundError:
        return {"error": "ID not found"}, 404


@app.route("/delete/<id>/<key>", methods=["POST"])
def delete_key(id, key):
    signature = request.args.get("sig")
    if not verify_signature(id, signature):
        return {"error": "Invalid signature"}, 403
    try:
        data = load_data(id)
        if key in data["data"]:
            del data["data"][key]
            log_action(data, "delete", key, request.remote_addr)
            save_data(id, data)
            return {"message": "Key deleted successfully"}, 200
        else:
            return {"error": "Key not found"}, 404
    except FileNotFoundError:
        return {"error": "ID not found"}, 404


@app.route("/list/<id>")
def list_keys(id):
    signature = request.args.get("sig")
    if not verify_signature(id, signature):
        return {"error": "Invalid signature"}, 403
    try:
        data = load_data(id)
        return {"keys": list(data["data"].keys())}, 200
    except FileNotFoundError:
        return {"error": "ID not found"}, 404


@app.route("/bulkset/<id>", methods=["POST"])
def bulk_set(id):
    signature = request.args.get("sig")
    if not verify_signature(id, signature):
        return {"error": "Invalid signature"}, 403

    try:
        incoming = request.get_json()
        data = load_data(id)
        for key, value in incoming.items():
            data["data"][key] = {"value": value, "one_time": False, "password": None}
            log_action(data, "bulk_set", key, request.remote_addr)
        save_data(id, data)
        return {"message": "Bulk set successful"}, 200
    except Exception as e:
        return {"error": str(e)}, 400


@app.route("/admin/list-all")
def list_all():
    if request.args.get("admin_key") != app.config["ADMIN_KEY"]:
        return {"error": "Unauthorized"}, 403

    all_ids = list_all_ids()
    return {"ids": all_ids}, 200


@app.route("/admin/nuke", methods=["POST"])
def clear_data():
    if request.args.get("admin_key") != app.config["ADMIN_KEY"]:
        return {"error": "Unauthorized"}, 403

    try:
        for filename in os.listdir(app.config["DATA_DIR"]):
            os.remove(os.path.join(app.config["DATA_DIR"], filename))
        return {"message": "All data Nuked successfully"}, 200
    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/clear_expired", methods=["POST"])
def clear_expired():
    try:
        for filename in os.listdir(app.config["DATA_DIR"]):
            id = filename.split('.')[0]
            data = load_data(id)
            if data.get("expires_at") and datetime.now(timezone.utc) > datetime.fromisoformat(data["expires_at"]):
                os.remove(filepath(id))
        return {"message": "Expired data cleared successfully"}, 200
    except Exception as e:
        return {"error": str(e)}, 500
    
@app.route("/gen_public_link/<id>")
def gen_public_link(id):
    signature = request.args.get("sig")
    key = request.form.get("key")
    if not verify_signature(id, signature):
        return {"error": "Invalid signature"}, 403
    try:
        data = load_data(id)
        if key not in data["data"]:
            return {"error": "Key not found"}, 404

        entry = data["data"][key]
        if entry.get("expires_at") and datetime.now(timezone.utc) > datetime.fromisoformat(entry["expires_at"]):
            return {"error": "Key expired"}, 410

        public_link = f"{request.url_root}get/{id}/{key}?sig={signature}"
        return {"public_link": public_link}, 200
    except FileNotFoundError:
        return {"error": "ID not found"}, 404
