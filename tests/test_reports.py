"""
tests/test_reports.py — Unit tests for the DriftSentry 3-report system (HTML, Markdown, CSV).
"""

import csv
import io
from pathlib import Path
import pytest

from driftsentry.report.generator import (
    generate_html_report,
    generate_markdown_report,
    generate_csv_report,
    export_scan_report,
)
from driftsentry.store import db


@pytest.fixture
def sample_scan_data():
    return {
        "scan_id": 1,
        "started_at": "2026-10-08T12:00:00Z",
        "finished_at": "2026-10-08T12:01:00Z",
        "target_spec": "192.168.1.100",
        "port_spec": "top100",
        "protocol": "nmap",
        "baseline_tag": "golden-baseline",
    }


@pytest.fixture
def sample_results():
    return [
        {
            "ip_address": "192.168.1.100",
            "hostname": "test-box",
            "port": 21,
            "protocol": "tcp",
            "state": "open",
            "service_guess": "ftp vsftpd 2.3.4",
            "banner": "vsftpd 2.3.4",
            "response_time_ms": 12,
        },
        {
            "ip_address": "192.168.1.100",
            "hostname": "test-box",
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service_guess": "ssh OpenSSH 4.7p1",
            "banner": "OpenSSH 4.7p1 Debian",
            "response_time_ms": 5,
        },
        {
            "ip_address": "192.168.1.100",
            "hostname": "test-box",
            "port": 80,
            "protocol": "tcp",
            "state": "closed",
            "service_guess": "http",
            "banner": None,
            "response_time_ms": 2,
        },
    ]


@pytest.fixture
def sample_drift_events():
    return [
        {
            "event_id": 1,
            "scan_id": 1,
            "prior_scan_id": 0,
            "host_id": 1,
            "ip_address": "192.168.1.100",
            "port": 21,
            "event_type": "new_port",
            "severity": "critical",
            "detail": '{"banner": "vsftpd 2.3.4", "service": "ftp"}',
        }
    ]


def test_generate_markdown_report(sample_scan_data, sample_results, sample_drift_events):
    content = generate_markdown_report(sample_scan_data, sample_results, sample_drift_events)
    assert "# DriftSentry Security Audit Report" in content
    assert "192.168.1.100" in content
    assert "vsftpd 2.3.4" in content
    assert "OpenSSH 4.7p1" in content
    assert "new_port" in content
    assert "CRITICAL" in content


def test_generate_html_report(sample_scan_data, sample_results, sample_drift_events):
    html = generate_html_report(sample_scan_data, sample_results, sample_drift_events)
    assert "<!DOCTYPE html>" in html
    assert "<html lang=\"en\">" in html
    assert "192.168.1.100" in html
    assert "vsftpd 2.3.4" in html
    assert "OpenSSH" in html
    assert "CRITICAL" in html
    assert "table" in html


def test_generate_csv_report(sample_scan_data, sample_results, sample_drift_events):
    csv_text = generate_csv_report(sample_scan_data, sample_results, sample_drift_events)
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 3
    assert rows[0]["port"] == "21"
    assert rows[0]["state"] == "open"
    assert "vsftpd" in rows[0]["banner"]
    assert rows[0]["drift_event"] == "new_port"


def test_export_scan_report(tmp_path, sample_results):
    db_file = tmp_path / "test.db"
    conn = db.init_db(db_file)
    sid = db.start_scan(conn, "192.168.1.100", "top100", "nmap")
    hid = db.upsert_host(conn, "192.168.1.100", "test-box")
    for r in sample_results:
        db.save_result(
            conn, sid, hid, r["port"], r["protocol"], r["state"],
            r["banner"], r["service_guess"], r["response_time_ms"]
        )
    db.save_drift_event(conn, sid, None, hid, 21, "new_port", '{"banner": "vsftpd"}', "critical")
    db.finish_scan(conn, sid)

    # Export html
    out_dir = tmp_path / "reports"
    paths = export_scan_report(conn, sid, report_format="all", output_dir=out_dir)
    conn.close()

    assert len(paths) == 3
    assert any(p.suffix == ".html" for p in paths)
    assert any(p.suffix == ".md" for p in paths)
    assert any(p.suffix == ".csv" for p in paths)
    for p in paths:
        assert p.exists()
        assert p.stat().st_size > 0
