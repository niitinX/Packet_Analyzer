from __future__ import annotations

import ipaddress
from typing import Iterable, Optional, Set

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
