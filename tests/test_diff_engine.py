"""
tests/test_diff_engine.py — Unit tests for the diff engine.

These tests pass mocked sqlite3.Row-like dicts (using a simple Proxy class)
to compute_drift() and assert the correct events are produced.
No database or network needed.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from driftsentry.diff.engine import compute_drift, DriftEvent


# ---------------------------------------------------------------------------
# Helpers — simulate sqlite3.Row with a dict
# ---------------------------------------------------------------------------

class FakeRow(dict):
    """Dict subclass that also supports attribute-style access like sqlite3.Row."""
    def __getitem__(self, key):
        return super().__getitem__(key)


def make_row(ip: str, port: int, state: str = "open", proto: str = "tcp",
             banner: str = None, host_id: int = 1, service_guess: str = None) -> FakeRow:
    return FakeRow({
        "ip_address": ip,
        "port": port,
        "protocol": proto,
        "state": state,
        "banner": banner,
        "service_guess": service_guess,
        "host_id": host_id,
        "hostname": None,
    })


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_no_events_when_identical():
    rows = [make_row("10.0.0.1", 80), make_row("10.0.0.1", 443)]
    events = compute_drift(rows, rows, scan_id=2, prior_scan_id=1)
    assert events == []


def test_new_port_detected():
    prior = [make_row("10.0.0.1", 80)]
    current = [make_row("10.0.0.1", 80), make_row("10.0.0.1", 8080)]
    events = compute_drift(current, prior, scan_id=2, prior_scan_id=1)
    assert len(events) == 1
    assert events[0].event_type == "new_port"
    assert events[0].port == 8080
    assert events[0].host_ip == "10.0.0.1"
    assert events[0].severity == "warning"


def test_closed_port_detected():
    prior = [make_row("10.0.0.1", 80), make_row("10.0.0.1", 22)]
    current = [make_row("10.0.0.1", 80)]
    events = compute_drift(current, prior, scan_id=2, prior_scan_id=1)
    assert len(events) == 1
    assert events[0].event_type == "closed_port"
    assert events[0].port == 22


def test_banner_change_detected():
    prior = [make_row("10.0.0.1", 80, banner="Apache/2.4.51")]
    current = [make_row("10.0.0.1", 80, banner="nginx/1.25.3")]
    events = compute_drift(current, prior, scan_id=2, prior_scan_id=1)
    assert len(events) == 1
    assert events[0].event_type == "banner_change"
    assert events[0].detail["before"] == "Apache/2.4.51"
    assert events[0].detail["after"] == "nginx/1.25.3"


def test_no_banner_change_when_same():
    prior = [make_row("10.0.0.1", 80, banner="nginx/1.25.3")]
    current = [make_row("10.0.0.1", 80, banner="nginx/1.25.3")]
    events = compute_drift(current, prior, scan_id=2, prior_scan_id=1)
    assert events == []


def test_host_up_detected():
    prior = []
    current = [make_row("10.0.0.5", 22)]
    events = compute_drift(current, prior, scan_id=2, prior_scan_id=1)
    host_up = [e for e in events if e.event_type == "host_up"]
    assert len(host_up) == 1
    assert host_up[0].host_ip == "10.0.0.5"


def test_host_down_detected():
    prior = [make_row("10.0.0.5", 22, host_id=5)]
    current = []
    events = compute_drift(current, prior, scan_id=2, prior_scan_id=1)
    host_down = [e for e in events if e.event_type == "host_down"]
    assert len(host_down) == 1
    assert host_down[0].host_ip == "10.0.0.5"


def test_first_scan_no_prior():
    """With no prior scan, every open port is a 'new_port'."""
    current = [make_row("10.0.0.1", 22), make_row("10.0.0.1", 80)]
    events = compute_drift(current, [], scan_id=1, prior_scan_id=None)
    new_ports = [e for e in events if e.event_type == "new_port"]
    assert len(new_ports) == 2


def test_closed_state_not_reported_as_new():
    """Ports in 'closed' state in the current scan should NOT trigger new_port."""
    current = [make_row("10.0.0.1", 9999, state="closed")]
    events = compute_drift(current, [], scan_id=2, prior_scan_id=1)
    new_ports = [e for e in events if e.event_type == "new_port"]
    assert new_ports == []


def test_multiple_hosts():
    prior = [
        make_row("10.0.0.1", 80, host_id=1),
        make_row("10.0.0.2", 22, host_id=2),
    ]
    current = [
        make_row("10.0.0.1", 80, host_id=1),
        make_row("10.0.0.1", 443, host_id=1),   # new port on host 1
        # 10.0.0.2 is gone                        # host_down + closed_port
    ]
    events = compute_drift(current, prior, scan_id=3, prior_scan_id=2)
    types = [e.event_type for e in events]
    assert "new_port" in types
    assert "closed_port" in types or "host_down" in types


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
