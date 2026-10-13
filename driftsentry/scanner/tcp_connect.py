"""
scanner/tcp_connect.py — Unprivileged TCP-connect scanner with banner grabbing.

Uses asyncio.open_connection so no root/CAP_NET_RAW is required.
Each probe returns a ProbeResult dataclass.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    ip: str
    port: int
    protocol: str = "tcp"
    state: str = "closed"       # open | closed | filtered
    banner: Optional[str] = None
    service_guess: Optional[str] = None
    response_time_ms: Optional[int] = None


# ---------------------------------------------------------------------------
# Service/banner hints (protocol-aware probes)
# ---------------------------------------------------------------------------

# Map of port → bytes to send as a probe.  None means just read whatever is
# sent immediately (many services send a banner on connect).
_PROBES: dict[int, Optional[bytes]] = {
    21:   None,                            # FTP — sends banner
    22:   None,                            # SSH — sends banner
    23:   None,                            # Telnet
    25:   None,                            # SMTP
    80:   b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    443:  b"HEAD / HTTP/1.0\r\n\r\n",     # will fail TLS, but catches non-TLS
    110:  None,                            # POP3
    143:  None,                            # IMAP
}

# Cheap service guessing from well-known ports
_SERVICE_MAP: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}


def guess_service(port: int, banner: Optional[str]) -> Optional[str]:
    if port in _SERVICE_MAP:
        return _SERVICE_MAP[port]
    if banner:
        bl = banner.lower()
        if "ssh" in bl:
            return "ssh"
        if "ftp" in bl:
            return "ftp"
        if "smtp" in bl or "220" in bl:
            return "smtp"
        if "http" in bl:
            return "http"
    return None


# ---------------------------------------------------------------------------
# Single probe coroutine
# ---------------------------------------------------------------------------

async def probe_port(
    ip: str,
    port: int,
    timeout_s: float = 0.8,
    grab_banner: bool = True,
) -> ProbeResult:
    """Attempt a TCP connect to (ip, port). Returns a ProbeResult."""
    t0 = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout_s
        )
    except asyncio.TimeoutError:
        return ProbeResult(ip=ip, port=port, state="filtered")
    except (ConnectionRefusedError, OSError):
        elapsed = int((time.monotonic() - t0) * 1000)
        return ProbeResult(ip=ip, port=port, state="closed", response_time_ms=elapsed)

    elapsed_connect = int((time.monotonic() - t0) * 1000)
    banner: Optional[str] = None

    if grab_banner:
        try:
            probe_bytes = _PROBES.get(port, None)
            if probe_bytes:
                writer.write(probe_bytes)
                await asyncio.wait_for(writer.drain(), timeout=1.0)
            raw = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            if raw:
                # Decode leniently; strip nulls and control chars
                banner = raw.decode("utf-8", errors="replace").strip()
                banner = "".join(ch for ch in banner if ch.isprintable() or ch in "\n\r\t")
                banner = banner[:512]  # cap length
        except Exception:
            pass  # No banner is fine

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    return ProbeResult(
        ip=ip,
        port=port,
        state="open",
        banner=banner,
        service_guess=guess_service(port, banner),
        response_time_ms=elapsed_connect,
    )
