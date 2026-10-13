"""
config.py — Configuration loading and defaults for DriftSentry.

Priority (highest wins): CLI flags > YAML config file > built-in defaults.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None

# ---------------------------------------------------------------------------
# Top-1000 / Top-100 port lists (derived from nmap frequency data)
# We bundle a static list so the tool works without nmap installed.
# If /usr/share/nmap/nmap-services is present we *could* load it dynamically,
# but a bundled list keeps the tool dependency-free.
# ---------------------------------------------------------------------------

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 9090, 9200,
    # Additional frequently seen ports rounded to 100 total
    20, 69, 79, 81, 88, 102, 113, 119, 137, 138, 161, 162, 179, 194, 389,
    427, 465, 500, 515, 543, 548, 554, 587, 631, 636, 646, 873, 990, 992,
    1080, 1194, 1433, 1434, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    2121, 2222, 2375, 2376, 3000, 3001, 3128, 3268, 3269, 3306, 4333,
    4444, 4899, 5000, 5001, 5432, 5631, 5666, 5800, 5985, 6000, 6379,
    6660, 6661, 6662, 6663, 7000, 7070, 8000, 8008, 8009, 8010, 8020,
    8081, 8181, 8888, 9001, 9043, 9060, 9080, 9090, 9100, 9443,
    10000, 10080, 27017,
]

METASPLOITABLE_PORTS = [
    21, 22, 23, 25, 53, 80, 111, 139, 445, 512, 513, 514, 1099, 1524,
    2049, 2121, 3306, 3632, 5432, 5900, 6000, 6667, 6697, 8009, 8180, 8787
]

def load_nmap_top_ports(count: int = 1000) -> Optional[list[int]]:
    """Dynamically load top N TCP ports from Kali Linux's nmap-services file if present."""
    nmap_file = Path("/usr/share/nmap/nmap-services")
    if not nmap_file.exists():
        return None
    try:
        entries = []
        with open(nmap_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 3 and "/tcp" in parts[1]:
                    port_num = int(parts[1].split("/")[0])
                    freq = float(parts[2])
                    entries.append((freq, port_num))
        entries.sort(key=lambda x: x[0], reverse=True)
        return [p[1] for p in entries[:count]]
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Dataclass for runtime config
# ---------------------------------------------------------------------------

@dataclass
class Config:
    # Scan target(s)
    target: str = ""
    ports: str = "top1000"
    protocol: str = "tcp-connect"

    # Performance
    concurrency: int = 300
    timeout_ms: int = 800
    rate_limit_pps: Optional[int] = None

    # Alerting
    webhook_url: Optional[str] = None
    syslog: bool = False
    json_stdout: bool = False
    always_notify: bool = False

    # Storage
    db_path: Path = field(default_factory=lambda: Path("driftsentry.db"))
    retention_days: Optional[int] = 90

    # Authorization
    authorized: bool = False

    # Debounce
    debounce_count: int = 1  # alert after N consecutive scans showing the same change


def load_config(config_file: Optional[str] = None, **overrides) -> Config:
    """Load a Config from an optional YAML file, then apply CLI overrides."""
    cfg = Config()

    if config_file and Path(config_file).exists():
        if yaml is None:
            raise ImportError("PyYAML is required to load YAML config files. Install with: pip install PyYAML")
        with open(config_file) as f:
            data = yaml.safe_load(f) or {}

        if "target" in data:
            cfg.target = str(data["target"])
        if "ports" in data:
            cfg.ports = str(data["ports"])
        if "protocol" in data:
            cfg.protocol = str(data["protocol"])
        if "concurrency" in data:
            cfg.concurrency = int(data["concurrency"])
        if "timeout_ms" in data:
            cfg.timeout_ms = int(data["timeout_ms"])
        if "rate_limit_pps" in data:
            cfg.rate_limit_pps = int(data["rate_limit_pps"])
        if "retention_days" in data:
            cfg.retention_days = int(data["retention_days"])
        if "db_path" in data:
            cfg.db_path = Path(data["db_path"])

        alerts = data.get("alerts", {})
        if "webhook" in alerts:
            cfg.webhook_url = str(alerts["webhook"])
        if "syslog" in alerts:
            cfg.syslog = bool(alerts["syslog"])
        if "json_stdout" in alerts:
            cfg.json_stdout = bool(alerts["json_stdout"])

    # Apply CLI overrides (non-None values only)
    for key, value in overrides.items():
        if value is not None and hasattr(cfg, key):
            setattr(cfg, key, value)

    return cfg


# ---------------------------------------------------------------------------
# Port spec parsing
# ---------------------------------------------------------------------------

def parse_ports(spec: str) -> list[int]:
    """Parse a port spec string into a sorted list of port numbers.

    Supported formats:
      top100         → top 100 most common ports (uses Kali nmap-services if present)
      top1000        → top 1000 ports (uses Kali nmap-services if present)
      metasploit     → all common Metasploitable lab service ports
      all            → 1–65535
      80             → single port
      1-1024         → range
      22,80,443      → comma list
      1-1024,8080    → mixed
    """
    spec = spec.strip().lower()
    if spec == "top100":
        kali = load_nmap_top_ports(100)
        if kali:
            return sorted(set(kali))
        return sorted(set(TOP_100_PORTS))

    if spec == "top1000":
        kali = load_nmap_top_ports(1000)
        if kali:
            return sorted(set(kali))
        fallback = set(range(1, 1025)) | set(TOP_100_PORTS) | set(METASPLOITABLE_PORTS)
        return sorted(fallback)

    if spec in ("metasploit", "metasploitable", "lab"):
        return sorted(set(METASPLOITABLE_PORTS))

    if spec == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_str, hi_str = part.split("-", 1)
            lo, hi = int(lo_str), int(hi_str)
            if lo > hi:
                raise ValueError(f"Invalid port range '{part}': lower bound {lo} exceeds upper bound {hi}")
            if lo < 1 or hi > 65535:
                raise ValueError(f"Port range '{part}' out of valid range (1-65535)")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} out of valid range (1-65535)")
            ports.add(p)

    return sorted(ports)


# ---------------------------------------------------------------------------
# Target spec parsing
# ---------------------------------------------------------------------------

def parse_targets(spec: str) -> list[str]:
    """Expand a target spec into a flat list of IP address strings.

    Supported:
      Single IP:    "192.168.1.1"
      Hostname:     "example.com"   (returned as-is; DNS resolved at scan time)
      CIDR:         "10.0.0.0/24"
      File path:    "@/path/to/targets.txt"  (one target per line)
    """
    spec = spec.strip()
    if not spec:
        return []

    # File of targets
    if spec.startswith("@"):
        path = Path(spec[1:])
        if not path.exists():
            raise FileNotFoundError(f"Target file not found: {path}")
        lines = [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")]
        targets: list[str] = []
        for line in lines:
            targets.extend(parse_targets(line))
        return targets

    # CIDR block
    try:
        network = ipaddress.ip_network(spec, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        pass

    # Single IP or hostname
    return [spec]
