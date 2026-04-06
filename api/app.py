from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from api.schemas import RunResponse, StatusResponse
from api.utils import ensure_job_dir, parse_rules, save_report
from generate_test_pcap import write_test_pcap
from packet_analyzer.dpi_mt import run_mt
from packet_analyzer.dpi_simple import run_simple

BASE_DIR = Path(__file__).resolve().parents[1]
JOBS_DIR = BASE_DIR / "api" / "jobs"

app = FastAPI(title="DPI Engine API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_jobs: Dict[str, Dict[str, Any]] = {}
_jobs_lock = threading.Lock()


def _set_job(job_id: str, data: Dict[str, Any]) -> None:
    with _jobs_lock:
        _jobs[job_id] = data


def _get_job(job_id: str) -> Optional[Dict[str, Any]]:
    with _jobs_lock:
        return _jobs.get(job_id)


def _run_job(
    *,
    job_id: str,
    input_path: Path,
    output_path: Path,
    mode: str,
    lbs: int,
    fps: int,
    rules_json: str,
) -> None:
    try:
        rules = parse_rules(rules_json)
        if mode == "mt":
            report = run_mt(
                str(input_path),
                str(output_path),
                rules,
                lbs,
                fps,
                throttle_ms=0,
                stats_interval=0.0,
                perf=True,
                quiet=True,
            )
        else:
            report = run_simple(
                str(input_path),
                str(output_path),
                rules,
                throttle_ms=0,
                stats_interval=0.0,
                perf=True,
                quiet=True,
            )

        report_path = input_path.parent / "report.json"
        save_report(report, report_path)
        _set_job(job_id, {"status": "done", "report": report, "output": str(output_path)})
    except Exception as exc:  # noqa: BLE001
        _set_job(job_id, {"status": "error", "error": str(exc)})


@app.post("/api/run", response_model=RunResponse)
async def run_dpi(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    mode: str = Form("simple"),
    lbs: int = Form(2),
    fps: int = Form(2),
    rules: str = Form(""),
) -> RunResponse:
    if mode not in {"simple", "mt"}:
        raise HTTPException(status_code=400, detail="Invalid mode")

    job_id = uuid.uuid4().hex
    job_dir = ensure_job_dir(JOBS_DIR, job_id)
    input_path = job_dir / "input.pcap"
    output_path = job_dir / "output.pcap"

    content = await file.read()
    input_path.write_bytes(content)

    _set_job(job_id, {"status": "running"})

    background_tasks.add_task(
        _run_job,
        job_id=job_id,
        input_path=input_path,
        output_path=output_path,
        mode="mt" if mode == "mt" else "simple",
        lbs=lbs,
        fps=fps,
        rules_json=rules,
    )

    return RunResponse(job_id=job_id)


@app.post("/api/run-sample", response_model=RunResponse)
def run_sample(
    background_tasks: BackgroundTasks,
    mode: str = Form("simple"),
    lbs: int = Form(2),
    fps: int = Form(2),
    rules: str = Form(""),
    randomize: bool = Form(True),
) -> RunResponse:
    if mode not in {"simple", "mt"}:
        raise HTTPException(status_code=400, detail="Invalid mode")

    job_id = uuid.uuid4().hex
    job_dir = ensure_job_dir(JOBS_DIR, job_id)
    input_path = job_dir / "input.pcap"
    output_path = job_dir / "output.pcap"

    seed = int(job_id[:8], 16)
    write_test_pcap(str(input_path), verbose=False, randomize=randomize, seed=seed)

    _set_job(job_id, {"status": "running"})
    background_tasks.add_task(
        _run_job,
        job_id=job_id,
        input_path=input_path,
        output_path=output_path,
        mode="mt" if mode == "mt" else "simple",
        lbs=lbs,
        fps=fps,
        rules_json=rules,
    )

    return RunResponse(job_id=job_id)


@app.get("/api/status/{job_id}", response_model=StatusResponse)
def get_status(job_id: str) -> StatusResponse:
    job = _get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return StatusResponse(job_id=job_id, **job)


@app.get("/api/download/{job_id}")
def download(job_id: str) -> FileResponse:
    job = _get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.get("status") != "done":
        raise HTTPException(status_code=400, detail="Job not finished")
    output_path = job.get("output")
    if not output_path:
        raise HTTPException(status_code=404, detail="Output not found")
    return FileResponse(output_path, filename="output.pcap")
