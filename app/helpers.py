# app/helpers.py
"""
Helper functions for KVDB application.
This module provides utility functions for file handling, ID validation,
signature generation, rate limiting, and data management.
"""
from typing import Optional
from flask import current_app
import base64
import hmac
import os
import re
import json
from datetime import datetime, timedelta, timezone


def filepath(id):
    assert is_valid_id(id)
    shard_path = os.path.join(current_app.config["DATA_DIR"], id[:2], id[2:4])
    os.makedirs(shard_path, exist_ok=True)
    return os.path.join(shard_path, f"{id[4:]}.json")


def list_all_ids():
    all_ids = []
    for root, _, files in os.walk(current_app.config["DATA_DIR"]):
        for file in files:
            if file.endswith(".json"):
                rel_path = os.path.relpath(
                    os.path.join(root, file), current_app.config["DATA_DIR"]
                )
                parts = rel_path.split(os.sep)
                if len(parts) == 3:
                    id = parts[0] + parts[1] + file[:-5]
                    if is_valid_id(id):
                        all_ids.append(id)
    return all_ids


def is_valid_id(id):
    return re.fullmatch(r"[a-f0-9]{32}", id) is not None


def sign_id(id: str, scope: str | list[str] = "") -> str:
    scope_str = canonical_scope(scope)
    msg = f"{id}:{scope_str}".encode()
    return hmac.new(current_app.config["SECRET_KEY"], msg, "sha256").hexdigest()

def create_scoped_token(id: str, scopes: str | list[str], expires_in: int = 3600) -> str:
    payload = {
        "id": id,
        "scopes": canonical_scope(scopes),
        "exp": int((datetime.now(timezone.utc) + timedelta(seconds=expires_in)).timestamp())
    }
    payload_json = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_json).rstrip(b"=")
    sig = hmac.new(current_app.config["SECRET_KEY"], payload_b64, "sha256").hexdigest()
    return f"{payload_b64.decode()}.{sig}"
    
def canonical_scope(scope: str | list[str]) -> str:
    if isinstance(scope, str):
        scopes = [s.strip() for s in scope.split(",")]
    else:
        scopes = scope
    return ",".join(sorted(set(scopes)))

def verify_signature(id: str, signature: str, required_scope: str, provided_scope: str) -> bool:
    scope_str = canonical_scope(provided_scope)
    expected_sig = sign_id(id, scope_str)
    if not hmac.compare_digest(expected_sig, signature or ""):
        return False
    return required_scope in scope_str.split(",")

def verify_scoped_token(token: str, required_scope: str) -> dict | None:
    try:
        payload_b64, sig = token.split(".")
        payload_json = base64.urlsafe_b64decode(payload_b64 + "==").decode()
        expected_sig = hmac.new(current_app.config["SECRET_KEY"], payload_b64.encode(), "sha256").hexdigest()

        if not hmac.compare_digest(expected_sig, sig):
            return None
        
        payload = json.loads(payload_json)
        if int(datetime.now(timezone.utc).timestamp()) > payload["exp"]:
            return None
        
        scopes = payload["scopes"].split(",")
        if required_scope not in scopes:
            return None
        
        return payload  # contains id, scopes, exp
    except Exception:
        return None

def load_data(id: str) -> dict:
    with open(filepath(id), "r") as f:
        return json.load(f)


def save_data(id: str, data: dict):
    with open(filepath(id), "w") as f:
        json.dump(data, f, indent=2)


def rate_limited(ip: str, rate_limit: dict, id: Optional[str] = None) -> bool:
    """Rate limit by IP and optionally by ID."""
    now = datetime.now(timezone.utc)
    
    # Create composite key for ID + IP rate limiting
    if id:
        key = f"{id}:{ip}"
    else:
        key = ip
    
    timestamps = rate_limit.get(key, [])
    # Filter out timestamps older than 60 seconds
    timestamps = [t for t in timestamps if (now - datetime.fromisoformat(t)).total_seconds() < 60]
    timestamps.append(now.isoformat())
    rate_limit[key] = timestamps
    
    return len(timestamps) > 20


def compute_log_hash(entry, secret_key):
    msg = json.dumps(entry, sort_keys=True).encode()
    return hmac.new(secret_key, msg, "sha256").hexdigest()


def log_action(data, action, key=None, ip=None):
    if "audit_log" not in data:
        data["audit_log"] = []

    prev_hash = data["audit_log"][-1]["hash"] if data["audit_log"] else None
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "key": key,
        "ip": ip,
        "prev_hash": prev_hash,
    }

    # Sign this entire entry
    entry["hash"] = compute_log_hash(entry, current_app.config["SECRET_KEY"])
    data["audit_log"].append(entry)
