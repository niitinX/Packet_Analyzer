from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from packet_analyzer.rules import RuleManager


def ensure_job_dir(base: Path, job_id: str) -> Path:
    job_dir = base / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    return job_dir


def parse_rules(rules_raw: str) -> RuleManager:
    if not rules_raw:
        return RuleManager()
    data = json.loads(rules_raw)
    return RuleManager.from_dict(data)


def save_report(report: Dict[str, object], path: Path) -> None:
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
