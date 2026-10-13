"""
driftsentry/scanner/nmap.py — Integrated Nmap scanner engine.

Executes native Nmap with service/version detection (-sV -Pn), parses the XML output,
and integrates the discovered ports, banners, and versions directly into DriftSentry's
persistent SQLite database and diff engine.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import xml.etree.ElementTree as ET
from typing import Optional

from driftsentry.config import Config, parse_ports, parse_targets
from driftsentry.scanner.tcp_connect import ProbeResult
from driftsentry.store import db

log = logging.getLogger("driftsentry.nmap")


def parse_nmap_xml(xml_content: str) -> list[ProbeResult]:
    """Parse Nmap XML output (-oX -) into a list of DriftSentry ProbeResults."""
    results: list[ProbeResult] = []
    if not xml_content or not xml_content.strip():
        return results

    try:
        root = ET.fromstring(xml_content.strip())
    except ET.ParseError as e:
        log.warning(f"Failed to parse Nmap XML output: {e}")
        return results

    for host in root.findall("host"):
        # Check host status
        status_elem = host.find("status")
        if status_elem is not None and status_elem.get("state") == "down":
            continue

        # Extract IP address
        ip: Optional[str] = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if not ip:
            continue

        # Extract latency
        response_time_ms: Optional[int] = None
        times_elem = host.find("times")
        if times_elem is not None and times_elem.get("srtt"):
            try:
                # srtt is in microseconds
                response_time_ms = max(1, int(int(times_elem.get("srtt")) / 1000))
            except ValueError:
                pass

        # Extract ports
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            try:
                port_id = int(port_elem.get("portid", "0"))
            except ValueError:
                continue

            proto = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            state = state_elem.get("state", "closed") if state_elem is not None else "closed"

            service_elem = port_elem.find("service")
            service_name: Optional[str] = None
            product: Optional[str] = None
            version: Optional[str] = None
            extrainfo: Optional[str] = None

            if service_elem is not None:
                service_name = service_elem.get("name")
                product = service_elem.get("product")
                version = service_elem.get("version")
                extrainfo = service_elem.get("extrainfo")

            # Format service guess and banner
            guess_parts = []
            if service_name:
                guess_parts.append(service_name)
            if product:
                guess_parts.append(product)
            if version:
                guess_parts.append(version)

            service_guess = " ".join(guess_parts).strip() or service_name

            banner_parts = []
            if product:
                banner_parts.append(product)
            if version:
                banner_parts.append(version)
            if extrainfo:
                banner_parts.append(f"({extrainfo})")

            banner = " ".join(banner_parts).strip() or service_guess

            results.append(
                ProbeResult(
                    ip=ip,
                    port=port_id,
                    protocol=proto,
                    state=state,
                    banner=banner if banner else None,
                    service_guess=service_guess if service_guess else None,
                    response_time_ms=response_time_ms,
                )
            )

    return results


def format_nmap_ports(ports: list[int]) -> str:
    """Format port list for Nmap -p argument (ranges where possible or comma list)."""
    if not ports:
        return "1-1000"
    if len(ports) > 1000:
        # Group into a comma-separated list or chunks
        return ",".join(str(p) for p in ports)
    return ",".join(str(p) for p in ports)


async def run_nmap_scan(
    conn,
    scan_id: int,
    config: Config,
) -> list[ProbeResult]:
    """Execute native Nmap scan on targets, parse XML, and save to SQLite."""
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise FileNotFoundError(
            "Nmap binary not found on PATH. On Kali Linux, install it via: sudo apt install nmap"
        )

    targets = parse_targets(config.target)
    ports = parse_ports(config.ports)

    port_arg = format_nmap_ports(ports)
    # Use -sV for service/version detection, -Pn to skip host discovery ping
    cmd = [
        nmap_path,
        "-sV",
        "-Pn",
        "-T4",
        "-p", port_arg,
        *targets,
        "-oX", "-",
    ]

    log.info(f"Executing integrated Nmap: {' '.join(cmd[:8])}... ({len(targets)} targets, {len(ports)} ports)")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        err_msg = stderr.decode("utf-8", errors="replace").strip()
        log.warning(f"Nmap exited with code {proc.returncode}: {err_msg}")

    xml_text = stdout.decode("utf-8", errors="replace")
    results = parse_nmap_xml(xml_text)

    # Upsert hosts and results into database
    host_id_map: dict[str, int] = {}
    for res in results:
        if res.ip not in host_id_map:
            host_id_map[res.ip] = db.upsert_host(conn, res.ip)

        hid = host_id_map[res.ip]
        db.save_result(
            conn,
            scan_id=scan_id,
            host_id=hid,
            port=res.port,
            protocol=res.protocol,
            state=res.state,
            banner=res.banner,
            service_guess=res.service_guess,
            response_time_ms=res.response_time_ms,
        )

    conn.commit()
    log.info(f"Nmap scan complete: {len(results)} port results recorded.")
    return results
