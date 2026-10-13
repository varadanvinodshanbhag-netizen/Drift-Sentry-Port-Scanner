"""
scanner/tcp_syn.py — Opt-in TCP SYN scanner using Scapy.

Requires CAP_NET_RAW (or root on Linux).  On Kali Linux grant with:
    sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))

This scanner is intentionally NOT in the default code path.  It is only
activated when --protocol tcp-syn is explicitly requested.

How SYN scanning works:
  1. Send a raw TCP SYN packet to the target port.
  2. Wait for:
     - SYN-ACK (flags=0x12) → port is OPEN.  Send RST to close cleanly.
     - RST     (flags=0x14) → port is CLOSED.
     - Timeout              → FILTERED (firewall dropped the packet).
  3. Never completes the 3-way handshake → quieter than TCP-connect.

Because Scapy's sr1() is synchronous we run it in a thread-pool executor
to avoid blocking the asyncio event loop.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("driftsentry.syn_scanner")


@dataclass
class SYNProbeResult:
    ip: str
    port: int
    protocol: str = "tcp"
    state: str = "filtered"     # open | closed | filtered
    banner: Optional[str] = None
    service_guess: Optional[str] = None
    response_time_ms: Optional[int] = None


def _check_scapy() -> bool:
    """Return True if Scapy is importable."""
    try:
        import scapy.all  # noqa: F401
        return True
    except ImportError:
        return False


def _syn_probe_sync(ip: str, port: int, timeout_s: float) -> SYNProbeResult:
    """Synchronous SYN probe — runs in a thread-pool executor."""
    import time
    t0 = time.monotonic()

    try:
        from scapy.all import IP, TCP, sr1, conf
        conf.verb = 0  # suppress Scapy output

        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=timeout_s, verbose=0)
        elapsed = int((time.monotonic() - t0) * 1000)

        if response is None:
            return SYNProbeResult(ip=ip, port=port, state="filtered",
                                  response_time_ms=elapsed)

        tcp_layer = response.getlayer(TCP)
        if tcp_layer is None:
            return SYNProbeResult(ip=ip, port=port, state="filtered",
                                  response_time_ms=elapsed)

        flags = tcp_layer.flags

        if flags == 0x12:  # SYN-ACK → open; send RST to avoid half-open flood
            rst = IP(dst=ip) / TCP(dport=port, flags="R",
                                   seq=tcp_layer.ack)
            sr1(rst, timeout=0.5, verbose=0)
            return SYNProbeResult(ip=ip, port=port, state="open",
                                  response_time_ms=elapsed)

        if flags & 0x04:   # RST bit set → closed
            return SYNProbeResult(ip=ip, port=port, state="closed",
                                  response_time_ms=elapsed)

        return SYNProbeResult(ip=ip, port=port, state="filtered",
                              response_time_ms=elapsed)

    except PermissionError:
        log.error(
            "SYN scan requires CAP_NET_RAW.  Run:\n"
            "  sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))\n"
            "Or re-run the scan as root."
        )
        return SYNProbeResult(ip=ip, port=port, state="filtered")
    except Exception as exc:
        log.debug(f"SYN probe error {ip}:{port}: {exc}")
        return SYNProbeResult(ip=ip, port=port, state="filtered")


async def probe_syn(
    ip: str,
    port: int,
    timeout_s: float = 1.0,
) -> SYNProbeResult:
    """Async wrapper: run the synchronous Scapy probe in a thread pool."""
    if not _check_scapy():
        log.error("Scapy not installed.  Install with: pip install scapy")
        return SYNProbeResult(ip=ip, port=port, state="filtered")

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, _syn_probe_sync, ip, port, timeout_s)
    return result
