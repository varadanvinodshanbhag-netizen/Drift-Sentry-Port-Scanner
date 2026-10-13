"""
scanner/engine.py — Multi-protocol async scan orchestrator.

Routes each probe to the correct scanner based on config.protocol:
  tcp-connect  → scanner.tcp_connect.probe_port   (default, no root)
  tcp-syn      → scanner.tcp_syn.probe_syn         (CAP_NET_RAW required)
  udp          → scanner.udp.probe_udp
  tcp+udp      → tcp-connect + udp combined

After probing, results are fingerprinted by scanner.fingerprint.fingerprint()
and persisted to SQLite incrementally (one commit per probe result) so that
a mid-scan SIGINT never loses progress.

Concurrency is bounded by a semaphore (config.concurrency).
Rate limiting uses a token-bucket via asyncio.sleep between dispatches.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Optional, Union

from driftsentry.config import Config, parse_ports, parse_targets
from driftsentry.scanner.fingerprint import fingerprint, ServiceInfo
from driftsentry.scanner.tcp_connect import ProbeResult, probe_port
from driftsentry.scanner.udp import UDPProbeResult, probe_udp
from driftsentry.store import db

log = logging.getLogger("driftsentry.engine")

AnyProbeResult = Union[ProbeResult, UDPProbeResult]


async def run_scan(
    conn,
    scan_id: int,
    config: Config,
) -> list[AnyProbeResult]:
    """Execute the full scan for all targets × ports × protocol(s).

    Returns a flat list of all probe results (may include both TCP and UDP
    results when protocol='tcp+udp').
    """
    targets = parse_targets(config.target)
    ports = parse_ports(config.ports)
    timeout_s = config.timeout_ms / 1000.0
    concurrency = config.concurrency
    rate_limit = config.rate_limit_pps

    # Determine which protocols to scan
    protocols: list[str] = []
    proto_cfg = (config.protocol or "tcp-connect").lower()
    if proto_cfg == "nmap":
        from driftsentry.scanner.nmap import run_nmap_scan
        return await run_nmap_scan(conn, scan_id, config)

    if proto_cfg in ("tcp-connect", "tcp+udp"):
        protocols.append("tcp-connect")
    if proto_cfg in ("tcp-syn",):
        protocols.append("tcp-syn")
    if proto_cfg in ("udp", "tcp+udp"):
        protocols.append("udp")
    if not protocols:
        protocols = ["tcp-connect"]

    total = len(targets) * len(ports) * len(protocols)
    log.info(
        f"Scanning {len(targets)} host(s) × {len(ports)} port(s) "
        f"× {len(protocols)} protocol(s) = {total} probes "
        f"(concurrency={concurrency}, timeout={config.timeout_ms}ms, "
        f"protocol={proto_cfg})"
    )

    if "tcp-syn" in protocols:
        log.info("SYN scan mode requested — requires CAP_NET_RAW / root on Linux.")

    sem = asyncio.Semaphore(concurrency)
    results: list[AnyProbeResult] = []
    min_interval = (1.0 / rate_limit) if rate_limit else 0.0
    last_dispatch = 0.0

    # ── Resolve hosts once, upsert DB rows ───────────────────────────────────
    host_map: dict[str, tuple[str, int]] = {}  # original → (resolved_ip, host_id)
    for ip_or_host in targets:
        resolved_ip = ip_or_host
        hostname: Optional[str] = None
        try:
            loop = asyncio.get_running_loop()
            info = await loop.getaddrinfo(
                ip_or_host, None, type=socket.SOCK_STREAM
            )
            resolved_ip = info[0][4][0]
            if resolved_ip != ip_or_host:
                hostname = ip_or_host
        except Exception:
            pass  # Unresolvable — use as-is
        host_id = db.upsert_host(conn, resolved_ip, hostname)
        host_map[ip_or_host] = (resolved_ip, host_id)

    # ── Build and dispatch probe coroutines ───────────────────────────────────
    tasks: list[asyncio.Task] = []
    commit_counter = 0

    for ip_or_host, (resolved_ip, host_id) in host_map.items():
        for proto in protocols:
            for port in ports:

                # Rate limiting
                if min_interval > 0:
                    now = time.monotonic()
                    gap = min_interval - (now - last_dispatch)
                    if gap > 0:
                        await asyncio.sleep(gap)
                    last_dispatch = time.monotonic()

                async def _probe(ip=resolved_ip, p=port, pr=proto, hid=host_id):
                    async with sem:
                        if pr == "tcp-connect":
                            return await probe_port(ip, p, timeout_s=timeout_s)
                        elif pr == "tcp-syn":
                            from driftsentry.scanner.tcp_syn import probe_syn
                            return await probe_syn(ip, p, timeout_s=timeout_s)
                        elif pr == "udp":
                            return await probe_udp(ip, p, timeout_s=max(timeout_s, 1.5))
                        else:
                            return await probe_port(ip, p, timeout_s=timeout_s)

                task = asyncio.create_task(_probe())

                def _on_done(t: asyncio.Task, hid=host_id) -> None:
                    nonlocal commit_counter
                    if t.exception():
                        log.debug(f"Probe error: {t.exception()}")
                        return
                    res: AnyProbeResult = t.result()

                    # Fingerprint the banner
                    svc: ServiceInfo = fingerprint(res.port, res.banner)

                    db.save_result(
                        conn,
                        scan_id=scan_id,
                        host_id=hid,
                        port=res.port,
                        protocol=res.protocol,
                        state=res.state,
                        banner=res.banner,
                        service_guess=str(svc),
                        response_time_ms=res.response_time_ms,
                    )
                    results.append(res)
                    commit_counter += 1
                    if commit_counter % 250 == 0:
                        conn.commit()

                task.add_done_callback(_on_done)
                tasks.append(task)

    await asyncio.gather(*tasks, return_exceptions=True)
    conn.commit()

    open_count = sum(1 for r in results if r.state == "open")
    ambiguous = sum(1 for r in results if r.state == "open|filtered")
    log.info(
        f"Scan complete: {len(results)} results — "
        f"{open_count} open, {ambiguous} open|filtered."
    )
    return results
