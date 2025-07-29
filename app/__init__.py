# app/__init__.py
"""
Main application module for KVDB.
This module initializes the Flask app, sets up routes, and handles
data management, including creating, reading, updating, and deleting
records in the key-value database.
"""

import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from flask import Flask, jsonify, render_template, request
from flask_pydantic import validate  # type: ignore

from app.helpers import (create_scoped_token, filepath, is_valid_id,
                         list_all_ids, load_data, log_action, rate_limited,
                         save_data, sign_id, verify_scoped_token)
from app.models import BulkSetRequest, CreateRequest, Record, SetValueRequest

app = Flask(__name__)

DATA_DIR = "data"

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["ADMIN_KEY"] = os.environ.get("ADMIN_KEY", "default_admin")
app.config["DATA_DIR"] = os.environ.get("DATA_DIR", DATA_DIR)

os.makedirs(app.config["DATA_DIR"], exist_ok=True)

RATE_LIMIT: Dict[str, List[str]] = {}  # naive in-memory rate limiter

from app.routes import bp

app.register_blueprint(bp)
