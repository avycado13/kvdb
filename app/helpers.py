from flask import current_app
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


def sign_id(id):
    return hmac.new(current_app.config["SECRET_KEY"], id.encode(), "sha256").hexdigest()


def verify_signature(id, signature):
    return hmac.compare_digest(sign_id(id), signature or "")


def load_data(id):
    with open(filepath(id), "r") as f:
        return json.load(f)


def save_data(id, data):
    with open(filepath(id), "w") as f:
        json.dump(data, f, indent=2)


def rate_limited(ip, rate_limit, id=None):
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
