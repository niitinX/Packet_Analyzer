from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel


class RunResponse(BaseModel):
    job_id: str


class SampleResponse(BaseModel):
    sample_id: str
    packet_count: int


class StatusResponse(BaseModel):
    job_id: str
    status: str
    error: Optional[str] = None
    report: Optional[Dict[str, Any]] = None
    progress: Optional[Dict[str, Any]] = None

