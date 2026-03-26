from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple
import socket
import hashlib


class AppType(Enum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    GOOGLE = 10
    FACEBOOK = 11
    YOUTUBE = 12
    TWITTER = 13
    INSTAGRAM = 14
    NETFLIX = 15
    AMAZON = 16
    MICROSOFT = 17
    APPLE = 18
    WHATSAPP = 19
    TELEGRAM = 20
    TIKTOK = 21
    SPOTIFY = 22
    ZOOM = 23
    DISCORD = 24
    GITHUB = 25
    CLOUDFLARE = 26


APP_NAMES = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.TLS: "TLS",
    AppType.QUIC: "QUIC",
    AppType.GOOGLE: "Google",
    AppType.FACEBOOK: "Facebook",
    AppType.YOUTUBE: "YouTube",
    AppType.TWITTER: "Twitter/X",
    AppType.INSTAGRAM: "Instagram",
    AppType.NETFLIX: "Netflix",
    AppType.AMAZON: "Amazon",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
    AppType.WHATSAPP: "WhatsApp",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.ZOOM: "Zoom",
    AppType.DISCORD: "Discord",
    AppType.GITHUB: "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN
    
    lower_sni = sni.lower()
    
    if any(x in lower_sni for x in ["youtube", "ytimg", "youtu.be", "yt3.ggpht"]):
        return AppType.YOUTUBE
    
    if any(x in lower_sni for x in ["google", "gstatic", "googleapis", "ggpht", "gvt1"]):
        return AppType.GOOGLE
    
    if any(x in lower_sni for x in ["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"]):
        return AppType.FACEBOOK
    
    if any(x in lower_sni for x in ["instagram", "cdninstagram"]):
        return AppType.INSTAGRAM
    
    if any(x in lower_sni for x in ["whatsapp", "wa.me"]):
        return AppType.WHATSAPP
    
    if any(x in lower_sni for x in ["twitter", "twimg", "x.com", "t.co"]):
        return AppType.TWITTER
    
    if any(x in lower_sni for x in ["netflix", "nflxvideo", "nflximg"]):
        return AppType.NETFLIX
    
    if any(x in lower_sni for x in ["amazon", "amazonaws", "cloudfront", "aws"]):
        return AppType.AMAZON
    
    if any(x in lower_sni for x in ["microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"]):
        return AppType.MICROSOFT
    
    if any(x in lower_sni for x in ["apple", "icloud", "mzstatic", "itunes"]):
        return AppType.APPLE
    
    if any(x in lower_sni for x in ["telegram", "t.me"]):
        return AppType.TELEGRAM
    
    if any(x in lower_sni for x in ["tiktok", "tiktokcdn", "musical.ly", "bytedance"]):
        return AppType.TIKTOK
    
    if any(x in lower_sni for x in ["spotify", "scdn.co"]):
        return AppType.SPOTIFY
    
    if "zoom" in lower_sni:
        return AppType.ZOOM
    
    if any(x in lower_sni for x in ["discord", "discordapp"]):
        return AppType.DISCORD
    
    if any(x in lower_sni for x in ["github", "githubusercontent"]):
        return AppType.GITHUB
    
    if any(x in lower_sni for x in ["cloudflare", "cf-"]):
        return AppType.CLOUDFLARE
    
    return AppType.HTTPS


@dataclass
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    
    def hash(self) -> int:
        data = f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}:{self.protocol}"
        return int(hashlib.md5(data.encode()).hexdigest()[:8], 16)
    
    def __hash__(self):
        return self.hash()
    
    def __eq__(self, other):
        return (self.src_ip == other.src_ip and
                self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port and
                self.protocol == other.protocol)
    
    def __str__(self):
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({proto})"


@dataclass
class Flow:
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes_count: int = 0
    blocked: bool = False
    classified: bool = False


@dataclass 
class Packet:
    id: int
    ts_sec: int
    ts_usec: int
    tuple: FiveTuple
    raw_data: bytes
    payload: bytes = b""
    tcp_flags: int = 0


@dataclass
class Stats:
    total_packets: int = 0
    total_bytes: int = 0
    forwarded: int = 0
    dropped: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    app_counts: Dict[AppType, int] = field(default_factory=dict)
    detected_snis: Dict[str, AppType] = field(default_factory=dict)
    
    def record_app(self, app_type: AppType, sni: str = ""):
        self.app_counts[app_type] = self.app_counts.get(app_type, 0) + 1
        if sni:
            self.detected_snis[sni] = app_type
