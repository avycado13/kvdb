# app/__init__.py
"""
Main application module for KVDB.
This module initializes the Flask app, sets up routes, and handles
data management, including creating, reading, updating, and deleting
records in the key-value database.
"""

import logging
import os
import sys
from typing import Dict, List
from app.loggers import NtfyHandler
from flask import Flask

app = Flask(__name__)

DATA_DIR = "data"

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["ADMIN_KEY"] = os.environ.get("ADMIN_KEY", "default_admin")
app.config["DATA_DIR"] = os.environ.get("DATA_DIR", DATA_DIR)
app.config["NTFY_TOPIC"] = os.environ.get("NTFY_TOPIC","")
ntfy_handler = NtfyHandler(
    topic=app.config["NTFY_TOPIC"],
    priority="high",
    tags=["warning", "computer"]
)
ntfy_handler.setLevel(logging.WARNING)
ntfy_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
app.logger.addHandler(ntfy_handler)
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.INFO)
stdout_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

app.logger.addHandler(stdout_handler)


os.makedirs(app.config["DATA_DIR"], exist_ok=True)

RATE_LIMIT: Dict[str, List[str]] = {}  # naive in-memory rate limiter

from app.routes import bp

app.register_blueprint(bp)
