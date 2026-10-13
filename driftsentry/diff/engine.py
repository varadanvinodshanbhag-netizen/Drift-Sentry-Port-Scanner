"""
diff/engine.py — Drift detection engine.

Compares two scan result sets (current vs. prior) and emits a list of
DriftEvent objects.  This is a pure function from two lists of rows
to a list of events — easy to unit-test without a database.

Event types (from PRD §7.3):
  new_port      — port is open now but was not open before
  closed_port   — port was open before but is closed/gone now
  banner_change — port is open in both but the banner differs
  host_up       — host has results now but had none before
  host_down     — host had results before but has none now
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from typing import Optional

log = logging.getLogger("driftsentry.diff")


# ---------------------------------------------------------------------------
# Severity rules
# ---------------------------------------------------------------------------

_SEVERITY: dict[str, str] = {
    "new_port":     "warning",
    "closed_port":  "info",
    "banner_change": "warning",
    "host_up":      "info",
    "host_down":    "warning",
}


# ---------------------------------------------------------------------------
# DriftEvent
# ---------------------------------------------------------------------------

@dataclass
class DriftEvent:
    scan_id: int
    prior_scan_id: Optional[int]
    host_ip: str
    host_id: int
    port: Optional[int]
    event_type: str
    severity: str
    detail: dict          # structured before/after info

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def human_summary(self) -> str:
        proto = self.detail.get("proto", "tcp")
        match self.event_type:
            case "new_port":
                banner = self.detail.get("banner") or ""
                svc = self.detail.get("service_guess") or ""
                extra = f" ({svc})" if svc else ""
                extra += f' banner="{banner}"' if banner else ""
                return f"[NEW PORT]    {self.host_ip}:{self.port}/{proto}{extra}"
            case "closed_port":
                return f"[CLOSED PORT] {self.host_ip}:{self.port}/{proto}"
            case "banner_change":
                before = self.detail.get("before", "")
                after = self.detail.get("after", "")
                return (f"[BANNER CHG]  {self.host_ip}:{self.port}/{proto} "
                        f'"{before}" → "{after}"')
            case "host_up":
                return f"[HOST UP]     {self.host_ip}"
            case "host_down":
                return f"[HOST DOWN]   {self.host_ip}"
            case _:
                return f"[{self.event_type.upper()}] {self.host_ip}:{self.port}"


# ---------------------------------------------------------------------------
# Core diff function
# ---------------------------------------------------------------------------

def compute_drift(
    current_rows,   # list of sqlite3.Row from get_results_for_scan(current)
    prior_rows,     # list of sqlite3.Row from get_results_for_scan(prior)
    scan_id: int,
    prior_scan_id: Optional[int],
) -> list[DriftEvent]:
    """Compare current vs prior scan rows and return drift events.

    Both row lists must have columns: ip_address, port, protocol, state, banner, host_id
    """
    events: list[DriftEvent] = []

    # Index: (ip, port, protocol) → row
    def index(rows) -> dict[tuple, object]:
        return {(r["ip_address"], r["port"], r["protocol"]): r for r in rows}

    current_idx = index(current_rows)
    prior_idx = index(prior_rows)

    # Collect per-host presence info
    current_hosts = {r["ip_address"]: r["host_id"] for r in current_rows}
    prior_hosts = {r["ip_address"]: r["host_id"] for r in prior_rows}

    # ── host_up / host_down ──────────────────────────────────────────────────
    for ip, host_id in current_hosts.items():
        if ip not in prior_hosts:
            events.append(DriftEvent(
                scan_id=scan_id, prior_scan_id=prior_scan_id,
                host_ip=ip, host_id=host_id,
                port=None, event_type="host_up",
                severity=_SEVERITY["host_up"],
                detail={"ip": ip},
            ))

    for ip, host_id in prior_hosts.items():
        if ip not in current_hosts:
            events.append(DriftEvent(
                scan_id=scan_id, prior_scan_id=prior_scan_id,
                host_ip=ip, host_id=host_id,
                port=None, event_type="host_down",
                severity=_SEVERITY["host_down"],
                detail={"ip": ip},
            ))

    # ── new_port ─────────────────────────────────────────────────────────────
    for key, row in current_idx.items():
        ip, port, proto = key
        if row["state"] != "open":
            continue  # only care about open ports
        prior_row = prior_idx.get(key)
        host_id = row["host_id"]

        if prior_row is None or prior_row["state"] != "open":
            # Port is newly open
            events.append(DriftEvent(
                scan_id=scan_id, prior_scan_id=prior_scan_id,
                host_ip=ip, host_id=host_id,
                port=port, event_type="new_port",
                severity=_SEVERITY["new_port"],
                detail={
                    "proto": proto,
                    "banner": row["banner"],
                    "service_guess": row["service_guess"],
                },
            ))
        else:
            # Port was open before — check for banner change
            cur_banner = (row["banner"] or "").strip()
            prior_banner = (prior_row["banner"] or "").strip()
            if cur_banner != prior_banner:
                events.append(DriftEvent(
                    scan_id=scan_id, prior_scan_id=prior_scan_id,
                    host_ip=ip, host_id=host_id,
                    port=port, event_type="banner_change",
                    severity=_SEVERITY["banner_change"],
                    detail={"proto": proto, "before": prior_banner, "after": cur_banner},
                ))

    # ── closed_port ──────────────────────────────────────────────────────────
    for key, prior_row in prior_idx.items():
        ip, port, proto = key
        if prior_row["state"] != "open":
            continue  # was not open before, nothing to report as closed
        cur_row = current_idx.get(key)
        host_id = prior_row["host_id"]

        if cur_row is None or cur_row["state"] != "open":
            events.append(DriftEvent(
                scan_id=scan_id, prior_scan_id=prior_scan_id,
                host_ip=ip, host_id=host_id,
                port=port, event_type="closed_port",
                severity=_SEVERITY["closed_port"],
                detail={"proto": proto, "prior_banner": prior_row["banner"]},
            ))

    log.info(f"Diff complete: {len(events)} drift event(s) detected.")
    return events
