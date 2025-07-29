# app/models.py
# This file contains the Pydantic models used in the application.
# It defines the structure of requests and records, including validation rules. 
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, RootModel


class CreateRequest(BaseModel):
    password: str | None = None
    expires: int | float = Field(default_factory=lambda: 31536000)
    scopes: str = ""


class SetValueRequest(BaseModel):
    key: str
    value: str
    password: str | None = None
    one_time: bool = False
    expires_at: datetime | str | None = None


class BulkSetRequest(RootModel[dict[str, str]]):
    pass


class Record(BaseModel):
    data: dict[str, Any] = {}
    password: Optional[str] = None
    expires_at: Optional[datetime] = None  # now it's parsed and validated
    audit_log: list["AuditEntry"] = []


class AuditEntry(BaseModel):
    timestamp: datetime  # ISO string — or use `datetime` for validation
    action: str
    key: Optional[str] = None
    ip: Optional[str] = None
    prev_hash: Optional[str] = None
    token: str
    hash: str
