from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel


class RunResponse(BaseModel):
    job_id: str


class StatusResponse(BaseModel):
    job_id: str
    status: str
    error: Optional[str] = None
    report: Optional[Dict[str, Any]] = None

