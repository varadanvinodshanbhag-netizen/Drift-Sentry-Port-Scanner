"""
tests/test_cli_edge_cases.py — Edge cases, error handling, and robust input validation.
"""

import argparse
import pytest
import sqlite3
from pathlib import Path
from unittest.mock import patch

from driftsentry.config import parse_ports, parse_targets, Config
from driftsentry.diff.engine import compute_drift
from driftsentry.store import db
from driftsentry.cli import cmd_diff, cmd_scan
from driftsentry.report.generator import export_scan_report
import driftsentry.scanner.nmap as nmap_mod


def test_parse_ports_valid_ranges_and_presets():
    """Verify standard port presets and range expansions."""
    p_top100 = parse_ports("top100")
    assert len(p_top100) > 0
    assert 80 in p_top100
    assert 443 in p_top100

    p_range = parse_ports("80, 8080-8082")
    assert p_range == [80, 8080, 8081, 8082]

    p_meta = parse_ports("metasploitable")
    assert 21 in p_meta
    assert 22 in p_meta


def test_parse_ports_invalid_bounds_and_format():
    """Verify parse_ports enforces 1-65535 and checks inverted ranges."""
    with pytest.raises(ValueError, match="out of valid range"):
        parse_ports("70000")

    with pytest.raises(ValueError, match="out of valid range"):
        parse_ports("0")

    with pytest.raises(ValueError, match="lower bound 100 exceeds upper bound 50"):
        parse_ports("100-50")

    with pytest.raises(ValueError):
        parse_ports("abc")


def test_parse_targets_edge_cases(tmp_path):
    """Test target parsing edge cases including CIDR, missing files, and empty specs."""
    assert parse_targets("") == []
    assert parse_targets("   ") == []

    # CIDR /30 gives 2 usable hosts
    cidr_targets = parse_targets("192.168.1.0/30")
    assert cidr_targets == ["192.168.1.1", "192.168.1.2"]

    # File based target spec
    tf = tmp_path / "targets.txt"
    tf.write_text("10.0.0.1\n# Comment\n\n10.0.0.2\n")
    loaded = parse_targets(f"@{tf}")
    assert loaded == ["10.0.0.1", "10.0.0.2"]

    # Missing target file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        parse_targets("@nonexistent_targets_file.txt")


def test_compute_drift_empty_scans():
    """Verify drift computation between two empty scans yields zero events."""
    events = compute_drift([], [], scan_id=1, prior_scan_id=None)
    assert events == []


def test_cmd_diff_nonexistent_scans(tmp_path):
    """Verify cmd_diff fails gracefully with code 1 if either scan does not exist."""
    db_file = tmp_path / "test.db"
    conn = db.init_db(db_file)
    conn.close()

    args = argparse.Namespace(
        db=str(db_file),
        from_id=101,
        to_id=102,
        json_out=False,
    )
    code = cmd_diff(args)
    assert code == 1


def test_nmap_scan_missing_binary(monkeypatch):
    """Verify run_nmap_scan raises FileNotFoundError with install instruction when nmap is absent."""
    monkeypatch.setattr(nmap_mod.shutil, "which", lambda cmd: None)

    cfg = Config(target="127.0.0.1", ports="80", protocol="nmap")
    with pytest.raises(FileNotFoundError, match="Nmap binary not found on PATH"):
        import asyncio
        asyncio.run(nmap_mod.run_nmap_scan(None, 1, cfg))


def test_db_baseline_nonexistent_tag(tmp_path):
    """Verify querying non-existent baseline tag returns None without error."""
    db_file = tmp_path / "test.db"
    conn = db.init_db(db_file)
    try:
        baseline_id = db.get_baseline_scan_id(conn, "missing_tag", "127.0.0.1")
        assert baseline_id is None
    finally:
        conn.close()


def test_cmd_scan_unauthorized_exit():
    """Verify cmd_scan enforces authorization requirement and exits with code 1 when omitted."""
    args = argparse.Namespace(
        config=None,
        target="127.0.0.1",
        ports="80",
        protocol="tcp-connect",
        concurrency=10,
        timeout_ms=500,
        rate_limit_pps=None,
        db=":memory:",
        webhook_url=None,
        syslog=False,
        json_stdout=False,
        always_notify=False,
        authorized=False,
        compare_to=None,
        baseline=None,
        debounce=1,
        verbose=False,
    )
    exit_code = cmd_scan(args)
    assert exit_code == 1


def test_export_scan_report_nonexistent_scan(tmp_path):
    """Verify report generation raises ValueError when scan ID does not exist."""
    db_file = tmp_path / "test.db"
    conn = db.init_db(db_file)
    try:
        with pytest.raises(ValueError, match="not found in database"):
            export_scan_report(conn, scan_id=9999, output_dir=tmp_path)
    finally:
        conn.close()


def test_db_get_latest_scan_id(tmp_path):
    """Verify get_latest_scan_id correctly returns the latest scan with and without target filter."""
    db_file = tmp_path / "test.db"
    conn = db.init_db(db_file)
    try:
        assert db.get_latest_scan_id(conn) is None

        s1 = db.start_scan(conn, "192.168.1.1", "80", "tcp-connect")
        db.finish_scan(conn, s1)

        s2 = db.start_scan(conn, "10.0.0.1", "443", "tcp-connect")
        db.finish_scan(conn, s2)

        assert db.get_latest_scan_id(conn) == s2
        assert db.get_latest_scan_id(conn, "192.168.1.1") == s1
        assert db.get_latest_scan_id(conn, "10.0.0.1") == s2
        assert db.get_latest_scan_id(conn, "nonexistent") == s2  # falls back to global latest
    finally:
        conn.close()


def test_console_report_execution(tmp_path, monkeypatch):
    """Verify interactive console handles report, report html, and driftsentry report commands."""
    import io
    from driftsentry.cli import run_interactive_console

    db_file = tmp_path / "driftsentry.db"
    conn = db.init_db(db_file)
    s1 = db.start_scan(conn, "127.0.0.1", "80", "tcp-connect")
    db.finish_scan(conn, s1)
    conn.close()

    # Change working directory to tmp_path where driftsentry.db lives
    monkeypatch.chdir(tmp_path)

    # Feed commands: report, report html, report 1, driftsentry report, exit
    commands = io.StringIO("report\nreport html\nreport 1 md\ndriftsentry report\nexit\n")
    monkeypatch.setattr("builtins.input", lambda prompt="": commands.readline().strip())

    run_interactive_console()

    # Reports directory must contain generated files
    rep_dir = tmp_path / "reports"
    assert rep_dir.exists()
    assert (rep_dir / f"driftsentry_scan_{s1}_127.0.0.1.html").exists()
    assert (rep_dir / f"driftsentry_scan_{s1}_127.0.0.1.md").exists()
    assert (rep_dir / f"driftsentry_scan_{s1}_127.0.0.1.csv").exists()

