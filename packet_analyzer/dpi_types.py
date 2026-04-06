from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AppType(str, Enum):
    UNKNOWN = "unknown"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    GOOGLE = "google"
    YOUTUBE = "youtube"
    FACEBOOK = "facebook"
    GITHUB = "github"
    TIKTOK = "tiktok"
    PORNHUB = "pornhub"


@dataclass(frozen=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int


@dataclass
class Flow:
    sni: Optional[str] = None
    app_type: AppType = AppType.UNKNOWN
    blocked: bool = False


def sni_to_app_type(sni: str) -> AppType:
    s = sni.lower()
    if "youtube" in s:
        return AppType.YOUTUBE
    if "facebook" in s:
        return AppType.FACEBOOK
    if "google" in s:
        return AppType.GOOGLE
    if "github" in s:
        return AppType.GITHUB
    if "tiktok" in s:
        return AppType.TIKTOK
    return AppType.HTTPS
