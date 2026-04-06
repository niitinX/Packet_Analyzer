from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Optional, Set

from .dpi_types import AppType


class RuleManager:
    def __init__(self) -> None:
        self.blocked_ips: Set[int] = set()
        self.blocked_apps: Set[AppType] = set()
        self.blocked_domains: Set[str] = set()

    def add_block_ip(self, ip_str: str) -> None:
        ip = int(ipaddress.IPv4Address(ip_str))
        self.blocked_ips.add(ip)

    def add_block_app(self, app: AppType) -> None:
        self.blocked_apps.add(app)

    def add_block_domain(self, domain: str) -> None:
        self.blocked_domains.add(domain.lower())

    def is_blocked(self, src_ip: int, app: AppType, sni: Optional[str]) -> bool:
        if src_ip in self.blocked_ips:
            return True
        if app in self.blocked_apps:
            return True
        if sni:
            sni_lower = sni.lower()
            for dom in self.blocked_domains:
                if dom in sni_lower:
                    return True
        return False

    def to_dict(self) -> dict:
        return {
            "blocked_ips": [str(ipaddress.IPv4Address(ip)) for ip in self.blocked_ips],
            "blocked_apps": [app.value for app in self.blocked_apps],
            "blocked_domains": sorted(self.blocked_domains),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RuleManager":
        rules = cls()
        for ip_str in data.get("blocked_ips", []):
            rules.add_block_ip(ip_str)
        for app_name in data.get("blocked_apps", []):
            try:
                rules.add_block_app(AppType(app_name))
            except ValueError:
                continue
        for domain in data.get("blocked_domains", []):
            rules.add_block_domain(domain)
        return rules

    def save(self, path: str) -> None:
        payload = self.to_dict()
        Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str) -> "RuleManager":
        content = Path(path).read_text(encoding="utf-8")
        data = json.loads(content)
        return cls.from_dict(data)
