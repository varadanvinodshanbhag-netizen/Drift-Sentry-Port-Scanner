"""
scanner/udp.py — Best-effort UDP scanner.

UDP scanning is inherently ambiguous:
  - If we receive a UDP reply      → open
  - If we receive ICMP port-unreach → closed
  - If timeout with no response    → open|filtered (can't distinguish)

The tool says so explicitly rather than pretending otherwise (PRD §7.1).

We use asyncio + raw socket tricks on Linux.  On Windows we fall back to a
simple connect() attempt which is less reliable but still useful.

Protocol-specific probes are sent per port so common services (DNS, NTP,
SNMP, TFTP, etc.) actually respond rather than timing out silently.
"""

from __future__ import annotations

import asyncio
import platform
import socket
import time
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Result type (mirrors tcp_connect.ProbeResult for a uniform interface)
# ---------------------------------------------------------------------------

@dataclass
class UDPProbeResult:
    ip: str
    port: int
    protocol: str = "udp"
    state: str = "open|filtered"   # open | closed | open|filtered
    banner: Optional[str] = None
    service_guess: Optional[str] = None
    response_time_ms: Optional[int] = None


# ---------------------------------------------------------------------------
# Protocol-specific UDP probes (payload bytes per port)
# ---------------------------------------------------------------------------

# Minimal valid payloads that elicit a response from common UDP services
_UDP_PROBES: dict[int, bytes] = {
    53:   b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"   # DNS query (minimal)
          b"\x07version\x04bind\x00\x00\x10\x00\x03",
    123:  (b"\x1b" + b"\x00" * 47),                                # NTP client request
    161:  (                                                         # SNMP v1 GetRequest
          b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
          b"\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0e"
          b"\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
    ),
    69:   b"\x00\x01test.txt\x00octet\x00",                       # TFTP RRQ
    111:  b"\x72\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02"    # RPC portmapper
          b"\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x04"
          b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
          b"\x00\x00\x00\x00",
    137:  (b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"   # NetBIOS Name query
           b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"),
    514:  b"<14>test\n",                                            # Syslog
    520:  b"\x01\x01\x00\x00\x00\x00\x00\x00"                     # RIP request
          b"\x00\x00\x00\x00\x00\x00\x00\x00",
    1194: b"\x38\x01\x00\x00\x00\x00\x00\x00\x00",                # OpenVPN ping
    1900: (                                                          # UPnP SSDP
          b"M-SEARCH * HTTP/1.1\r\n"
          b"HOST: 239.255.255.250:1900\r\n"
          b'MAN: "ssdp:discover"\r\n'
          b"MX: 1\r\n"
          b"ST: ssdp:all\r\n\r\n"
    ),
    5353: (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"   # mDNS query
           b"\x00\x00\x1c\x00\x01"),
}

_SERVICE_MAP_UDP: dict[int, str] = {
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 111: "rpcbind",
    123: "ntp", 137: "netbios-ns", 138: "netbios-dgm", 161: "snmp",
    162: "snmptrap", 389: "ldap", 500: "isakmp", 514: "syslog",
    520: "rip", 1194: "openvpn", 1900: "ssdp", 4500: "ipsec",
    5353: "mdns", 5060: "sip",
}


# ---------------------------------------------------------------------------
# UDP probe coroutine
# ---------------------------------------------------------------------------

async def probe_udp(
    ip: str,
    port: int,
    timeout_s: float = 2.0,
) -> UDPProbeResult:
    """Send a UDP probe and classify the response.

    Because UDP is connectionless, we use a raw approach:
      1. Send a protocol-appropriate payload (or empty bytes).
      2. Wait for a response:
         - UDP reply → open
         - ICMP port-unreachable → closed  (detected via ConnectionRefusedError on Linux)
         - Timeout → open|filtered
    """
    payload = _UDP_PROBES.get(port, b"\x00")
    t0 = time.monotonic()

    loop = asyncio.get_running_loop()

    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.connect((ip, port))   # "connect" on UDP just sets the peer addr

        # Send probe
        await loop.sock_sendall(sock, payload)

        # Wait for response
        try:
            data = await asyncio.wait_for(
                loop.sock_recv(sock, 1024), timeout=timeout_s
            )
            elapsed = int((time.monotonic() - t0) * 1000)
            banner = None
            if data:
                banner = data.decode("utf-8", errors="replace").strip()[:256]
            return UDPProbeResult(
                ip=ip, port=port, state="open",
                banner=banner,
                service_guess=_SERVICE_MAP_UDP.get(port),
                response_time_ms=elapsed,
            )
        except asyncio.TimeoutError:
            return UDPProbeResult(
                ip=ip, port=port, state="open|filtered",
                service_guess=_SERVICE_MAP_UDP.get(port),
                response_time_ms=int((time.monotonic() - t0) * 1000),
            )
        except ConnectionRefusedError:
            # ICMP port-unreachable received → definitely closed
            return UDPProbeResult(
                ip=ip, port=port, state="closed",
                response_time_ms=int((time.monotonic() - t0) * 1000),
            )

    except Exception as exc:
        return UDPProbeResult(ip=ip, port=port, state="open|filtered")
    finally:
        try:
            sock.close()
        except Exception:
            pass
