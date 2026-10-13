"""
alerting/sinks.py — Output sinks for drift events.

v0.1 (MVP):
  - StdoutSink   (human-readable with rich, or plain text fallback)
  - JsonSink     (machine-readable JSON to stdout)
  - WebhookSink  (HTTP POST, Slack/Discord/SIEM compatible)

v0.2:
  - SyslogSink   (local syslog via logging.handlers.SysLogHandler)

Each sink is a callable: sink(events, scan_meta) → None.
New sinks can be added without touching the diff engine or CLI.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Optional, Callable

from driftsentry.diff.engine import DriftEvent

log = logging.getLogger("driftsentry.alerting")

SinkFn = Callable[[list[DriftEvent], dict], None]


# ---------------------------------------------------------------------------
# Severity colour map for rich
# ---------------------------------------------------------------------------
_SEVERITY_COLOR = {
    "info":     "cyan",
    "warning":  "yellow",
    "critical": "bold red",
}


# ---------------------------------------------------------------------------
# Stdout — human-readable
# ---------------------------------------------------------------------------

def make_stdout_sink(use_rich: bool = True) -> SinkFn:
    """Returns a sink that prints a colour-coded summary to stdout."""

    def _sink(events: list[DriftEvent], meta: dict) -> None:
        if not events:
            _print_no_drift(meta, use_rich)
            return

        if use_rich:
            _rich_output(events, meta)
        else:
            _plain_output(events, meta)

    return _sink


def _print_no_drift(meta: dict, use_rich: bool) -> None:
    msg = (f"✓  No drift detected  "
           f"(scan #{meta.get('scan_id')} vs #{meta.get('prior_scan_id', 'n/a')})")
    if use_rich:
        try:
            from rich.console import Console
            Console().print(f"[green]{msg}[/green]")
            return
        except ImportError:
            pass
    print(msg)


def _rich_output(events: list[DriftEvent], meta: dict) -> None:
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        console.print(
            f"\n[bold]DriftSentry — scan #{meta.get('scan_id')} "
            f"vs #{meta.get('prior_scan_id', 'n/a')}[/bold]"
        )

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity", width=10)
        table.add_column("Type", width=15)
        table.add_column("Host", width=20)
        table.add_column("Port", width=8)
        table.add_column("Detail")

        for ev in events:
            color = _SEVERITY_COLOR.get(ev.severity, "white")
            detail_str = json.dumps(ev.detail, ensure_ascii=False)
            table.add_row(
                f"[{color}]{ev.severity}[/{color}]",
                ev.event_type,
                ev.host_ip,
                str(ev.port) if ev.port else "—",
                detail_str[:80],
            )

        console.print(table)

    except ImportError:
        _plain_output(events, meta)


def _plain_output(events: list[DriftEvent], meta: dict) -> None:
    print(f"\n=== DriftSentry: scan #{meta.get('scan_id')} "
          f"vs #{meta.get('prior_scan_id', 'n/a')} ===")
    for ev in events:
        print(f"[{ev.severity.upper()}] {ev.human_summary()}")


# ---------------------------------------------------------------------------
# JSON sink
# ---------------------------------------------------------------------------

def make_json_sink() -> SinkFn:
    """Returns a sink that prints one JSON object per event to stdout."""

    def _sink(events: list[DriftEvent], meta: dict) -> None:
        for ev in events:
            payload = {
                "tool": "driftsentry",
                "scan_id": meta.get("scan_id"),
                "prior_scan_id": meta.get("prior_scan_id"),
                "timestamp": meta.get("timestamp"),
                "host": ev.host_ip,
                "event_type": ev.event_type,
                "port": ev.port,
                "severity": ev.severity,
                "detail": ev.detail,
            }
            print(json.dumps(payload))

    return _sink


# ---------------------------------------------------------------------------
# Webhook sink
# ---------------------------------------------------------------------------

def make_webhook_sink(url: str, timeout_s: int = 10) -> SinkFn:
    """Returns a sink that POSTs each event as JSON to *url*."""

    def _sink(events: list[DriftEvent], meta: dict) -> None:
        try:
            import requests
        except ImportError:
            log.error("'requests' not installed — cannot send webhook. "
                      "Run: pip install requests")
            return

        for ev in events:
            payload = {
                "tool": "driftsentry",
                "scan_id": meta.get("scan_id"),
                "prior_scan_id": meta.get("prior_scan_id"),
                "timestamp": meta.get("timestamp"),
                "host": ev.host_ip,
                "event_type": ev.event_type,
                "port": ev.port,
                "protocol": ev.detail.get("proto", "tcp"),
                "service_guess": ev.detail.get("service_guess"),
                "banner": ev.detail.get("banner"),
                "severity": ev.severity,
            }
            try:
                resp = requests.post(url, json=payload, timeout=timeout_s)
                resp.raise_for_status()
                log.debug(f"Webhook OK ({resp.status_code}) for {ev.event_type} @ {ev.host_ip}:{ev.port}")
            except Exception as exc:
                log.warning(f"Webhook failed for event {ev.event_type}: {exc}")

    return _sink


# ---------------------------------------------------------------------------
# Syslog sink (v0.2)
# ---------------------------------------------------------------------------

def make_syslog_sink(
    address: str | tuple = "/dev/log",
    facility: int = None,
) -> SinkFn:
    """Returns a sink that emits each drift event to local syslog.

    On Linux this writes to /dev/log (the standard syslog socket).
    On Windows syslog is not available — the sink logs a warning and no-ops.

    Args:
        address: syslog socket path (str) or (host, port) tuple for remote syslog.
        facility: logging facility constant (e.g. logging.handlers.SysLogHandler.LOG_DAEMON).
                  Defaults to LOG_USER.
    """
    import platform
    import logging.handlers

    if platform.system() == "Windows":
        log.warning(
            "Syslog sink is not available on Windows — "
            "use stdout or webhook sinks instead."
        )
        return lambda events, meta: None  # no-op on Windows

    if facility is None:
        facility = logging.handlers.SysLogHandler.LOG_USER

    try:
        handler = logging.handlers.SysLogHandler(address=address, facility=facility)
    except Exception as exc:
        log.warning(f"Could not open syslog at {address}: {exc}. Syslog sink disabled.")
        return lambda events, meta: None

    syslog = logging.getLogger("driftsentry.syslog")
    syslog.addHandler(handler)
    syslog.setLevel(logging.DEBUG)
    syslog.propagate = False  # don't double-print to stderr

    _LEVEL_MAP = {
        "info":     logging.INFO,
        "warning":  logging.WARNING,
        "critical": logging.CRITICAL,
    }

    def _sink(events: list[DriftEvent], meta: dict) -> None:
        for ev in events:
            level = _LEVEL_MAP.get(ev.severity, logging.INFO)
            syslog.log(
                level,
                f"driftsentry scan={meta.get('scan_id')} "
                f"event={ev.event_type} host={ev.host_ip} "
                f"port={ev.port} severity={ev.severity}",
            )

    return _sink


# ---------------------------------------------------------------------------
# Debounce filter (v0.2)
# ---------------------------------------------------------------------------

def debounce_events(
    events: list[DriftEvent],
    conn,
    scan_id: int,
    target_spec: str,
    n: int,
) -> list[DriftEvent]:
    """Filter *events* to only those confirmed across N consecutive scans.

    How it works: for each candidate event, look back through the N-1 prior
    scans and check whether the same (host, port, event_type) exists in the
    drift_events table for each of them.  Only pass through events that
    appear in all N scans (including the current one).

    With n=1 (default) every event passes through immediately — no debounce.
    With n=2 an event must appear in 2 consecutive scans before alerting.
    """
    if n <= 1 or not events:
        return events  # fast path: no debounce

    # Get the N-1 prior scan IDs for this target (before current)
    prior_scans = conn.execute(
        """SELECT scan_id FROM scans
           WHERE target_spec = ? AND scan_id < ?
           ORDER BY scan_id DESC LIMIT ?""",
        (target_spec, scan_id, n - 1),
    ).fetchall()

    if len(prior_scans) < n - 1:
        # Not enough history yet — pass all events through on first N scans
        return events

    prior_ids = [r["scan_id"] for r in prior_scans]

    passed: list[DriftEvent] = []
    for ev in events:
        confirmed = True
        for pid in prior_ids:
            row = conn.execute(
                """SELECT 1 FROM drift_events
                   WHERE scan_id = ? AND host_id = ? AND port IS ? AND event_type = ?
                   LIMIT 1""",
                (pid, ev.host_id, ev.port, ev.event_type),
            ).fetchone()
            if not row:
                confirmed = False
                break

        if confirmed:
            passed.append(ev)
        else:
            log.debug(
                f"Debounced (need {n} consecutive): "
                f"{ev.event_type} {ev.host_ip}:{ev.port}"
            )

    log.info(f"Debounce ({n}x): {len(events)} events → {len(passed)} after filtering.")
    return passed


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def dispatch(events: list[DriftEvent], meta: dict, sinks: list[SinkFn]) -> None:
    """Send *events* to all registered sinks."""
    for sink in sinks:
        try:
            sink(events, meta)
        except Exception as exc:
            log.error(f"Sink {sink} raised: {exc}")
