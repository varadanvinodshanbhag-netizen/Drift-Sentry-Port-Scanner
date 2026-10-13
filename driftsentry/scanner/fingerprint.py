"""
scanner/fingerprint.py — Service fingerprinting from banners.

After a banner is grabbed, this module tries to extract a structured
service/version string from the raw bytes.  It is used by both the
TCP-connect and (future) SYN scanners to enrich probe results.

Design:
  - No external dependencies — pure regex + pattern matching.
  - Returns a ServiceInfo dataclass with name, version, and product fields.
  - Falls back to a port-number guess if no pattern matches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceInfo:
    name: str                       # e.g. "ssh", "http", "ftp"
    product: Optional[str] = None   # e.g. "OpenSSH", "nginx", "vsftpd"
    version: Optional[str] = None   # e.g. "8.9p1", "1.25.3"
    extra: Optional[str] = None     # e.g. "Ubuntu 22.04"

    def __str__(self) -> str:
        parts = [self.name]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        if self.extra:
            parts.append(f"({self.extra})")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Fingerprint patterns — (regex, name, product_group, version_group)
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[re.Pattern, str, Optional[int], Optional[int]]] = [
    # SSH:  SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
    (re.compile(r"SSH-[\d.]+-(\S+?)(?:[_ ]([\d.]+[^\s]*))?", re.I), "ssh", 1, 2),

    # HTTP Server headers
    (re.compile(r"Server:\s*(\S+?)(?:/([\d.]+))?", re.I), "http", 1, 2),

    # FTP: 220 vsftpd 3.0.5  |  220 FTP Server ready
    (re.compile(r"^220[- ].*?(\w+FTP\w*|vsftpd|ProFTPD|FileZilla)[/\s]*([\d.]+)?", re.I), "ftp", 1, 2),

    # SMTP: 220 mail.example.com ESMTP Postfix (Ubuntu)
    (re.compile(r"^220[- ].*?ESMTP\s+(\w+)", re.I), "smtp", 1, None),

    # POP3: +OK Dovecot ready
    (re.compile(r"^\+OK\s+(\w+)", re.I), "pop3", 1, None),

    # IMAP: * OK [CAPABILITY ...] Dovecot ready
    (re.compile(r"^\* OK\s+\[.*?\]\s+(\w+)", re.I), "imap", 1, None),

    # MySQL: binary protocol — first 4 bytes are packet header, then version string
    (re.compile(r"[\x00-\x08].{3}([\d]+\.[\d]+\.[\d]+[^\x00]*)", re.S), "mysql", 1, None),

    # Redis: -ERR or +PONG
    (re.compile(r"^(\+PONG|-ERR)", re.I), "redis", None, None),

    # MongoDB: binary handshake containing version string
    (re.compile(r"MongoDB\s+([\d.]+)", re.I), "mongodb", None, 1),

    # RDP / Windows RDP cookie
    (re.compile(r"Cookie: mstshash=", re.I), "rdp", None, None),

    # Telnet IAC negotiation
    (re.compile(r"^\xff[\xfd\xfb\xfc\xfe]", re.S), "telnet", None, None),

    # Generic HTTP response
    (re.compile(r"^HTTP/([\d.]+)\s+(\d+)", re.I), "http", None, 1),

    # TLS/SSL ClientHello or alert (often means HTTPS on wrong port)
    (re.compile(r"^\x15\x03", re.S), "tls-alert", None, None),
]


# Port → known service name (fallback when no banner pattern matches)
_PORT_SERVICE: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 500: "isakmp", 514: "syslog", 515: "lpd",
    587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1194: "openvpn", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2375: "docker",
    2376: "docker-tls", 3000: "http-dev", 3306: "mysql", 3389: "rdp",
    4444: "metasploit", 5432: "postgresql", 5900: "vnc",
    5985: "winrm", 6379: "redis", 6443: "k8s-api",
    8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 9300: "elasticsearch", 27017: "mongodb",
}


def fingerprint(port: int, banner: Optional[str]) -> ServiceInfo:
    """Extract structured service info from a banner string.

    Args:
        port:   The target port number.
        banner: Raw banner string (may be None).

    Returns:
        ServiceInfo with at minimum a .name field.
    """
    if banner:
        for pattern, name, prod_grp, ver_grp in _PATTERNS:
            m = pattern.search(banner)
            if m:
                product: Optional[str] = None
                version: Optional[str] = None
                try:
                    if prod_grp and m.lastindex and m.lastindex >= prod_grp:
                        product = m.group(prod_grp)
                except IndexError:
                    pass
                try:
                    if ver_grp and m.lastindex and m.lastindex >= ver_grp:
                        version = m.group(ver_grp)
                except IndexError:
                    pass
                return ServiceInfo(name=name, product=product, version=version)

    # No banner pattern matched — fall back to port map
    svc = _PORT_SERVICE.get(port, f"unknown-{port}")
    return ServiceInfo(name=svc)
