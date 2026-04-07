from __future__ import annotations

import shutil
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from api.schemas import RunResponse, SampleResponse, StatusResponse
from api.utils import ensure_job_dir, parse_rules, save_report
from generate_test_pcap import write_test_pcap
from packet_analyzer.dpi_mt import run_mt
from packet_analyzer.dpi_simple import run_simple

BASE_DIR = Path(__file__).resolve().parents[1]
JOBS_DIR = BASE_DIR / "api" / "jobs"
SAMPLES_DIR = JOBS_DIR / "samples"

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


def _update_job(job_id: str, data: Dict[str, Any]) -> None:
    with _jobs_lock:
        existing = _jobs.get(job_id, {})
        existing.update(data)
        _jobs[job_id] = existing


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
    throttle_ms: int,
) -> None:
    try:
        def on_progress(snapshot) -> None:
            _update_job(
                job_id,
                {
                    "status": "running",
                    "progress": {
                        "total_packets": snapshot.total_packets,
                        "total_bytes": snapshot.total_bytes,
                        "tcp_packets": snapshot.tcp_packets,
                        "udp_packets": snapshot.udp_packets,
                        "forwarded": snapshot.forwarded,
                        "dropped": snapshot.dropped,
                    },
                },
            )

        rules = parse_rules(rules_json)
        if mode == "mt":
            report = run_mt(
                str(input_path),
                str(output_path),
                rules,
                lbs,
                fps,
                throttle_ms=throttle_ms,
                stats_interval=0.5,
                perf=True,
                quiet=True,
                progress_callback=on_progress,
            )
        else:
            report = run_simple(
                str(input_path),
                str(output_path),
                rules,
                throttle_ms=throttle_ms,
                stats_interval=0.5,
                perf=True,
                quiet=True,
                progress_callback=on_progress,
            )

        report_path = input_path.parent / "report.json"
        save_report(report, report_path)
        _set_job(job_id, {"status": "done", "report": report, "output": str(output_path)})
    except Exception as exc:  # noqa: BLE001
        _set_job(job_id, {"status": "error", "error": str(exc)})


@app.post("/api/run", response_model=RunResponse)
async def run_dpi(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(None),
    sample_id: str = Form(""),
    mode: str = Form("simple"),
    lbs: int = Form(2),
    fps: int = Form(2),
    throttle_ms: int = Form(0),
    rules: str = Form(""),
) -> RunResponse:
    if mode not in {"simple", "mt"}:
        raise HTTPException(status_code=400, detail="Invalid mode")

    if file is None and not sample_id:
        raise HTTPException(status_code=400, detail="Missing file or sample_id")

    job_id = uuid.uuid4().hex
    job_dir = ensure_job_dir(JOBS_DIR, job_id)
    input_path = job_dir / "input.pcap"
    output_path = job_dir / "output.pcap"

    if file is not None:
        content = await file.read()
        input_path.write_bytes(content)
    else:
        sample_path = SAMPLES_DIR / sample_id / "input.pcap"
        if not sample_path.exists():
            raise HTTPException(status_code=404, detail="Sample not found")
        shutil.copyfile(sample_path, input_path)

    _set_job(job_id, {"status": "running"})

    background_tasks.add_task(
        _run_job,
        job_id=job_id,
        input_path=input_path,
        output_path=output_path,
        mode="mt" if mode == "mt" else "simple",
        lbs=lbs,
        fps=fps,
        throttle_ms=max(0, throttle_ms),
        rules_json=rules,
    )

    return RunResponse(job_id=job_id)


@app.post("/api/sample", response_model=SampleResponse)
def generate_sample(
    randomize: bool = Form(True),
    size_factor: int = Form(3),
) -> SampleResponse:
    sample_id = uuid.uuid4().hex
    sample_dir = ensure_job_dir(SAMPLES_DIR, sample_id)
    input_path = sample_dir / "input.pcap"

    seed = int(sample_id[:8], 16)
    packet_count = write_test_pcap(
        str(input_path),
        verbose=False,
        randomize=randomize,
        seed=seed,
        size_factor=max(1, size_factor),
    )

    return SampleResponse(sample_id=sample_id, packet_count=packet_count)


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
