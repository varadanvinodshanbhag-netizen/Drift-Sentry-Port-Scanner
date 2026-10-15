"""
driftsentry/report/generator.py — 3-Report Generation Engine.

Produces:
  1. HTML Security Audit Report — Standalone dashboard with executive metrics,
     accessible responsive tables, and print-to-PDF ready CSS.
  2. Markdown Technical Report — Clean GitHub/GitLab-Flavored Markdown for documentation.
  3. CSV Data Export — Spreadsheet-ready data for Excel, analysts, and SIEM ingestion.
"""

from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from typing import Any, Optional, Union
import sqlite3

from driftsentry.store import db


def _dict_from_row(row: Union[sqlite3.Row, dict, Any]) -> dict:
    if isinstance(row, dict):
        return row
    if hasattr(row, "keys"):
        return {k: row[k] for k in row.keys()}
    return dict(row)


def generate_markdown_report(
    scan_data: dict,
    results: list[dict],
    drift_events: list[dict],
    output_path: Optional[Path | str] = None,
) -> str:
    """Generate a GitHub-Flavored Markdown security audit report."""
    scan = _dict_from_row(scan_data)
    res_list = [_dict_from_row(r) for r in results]
    events_list = [_dict_from_row(e) for e in drift_events]

    open_ports = [r for r in res_list if r.get("state") == "open"]
    crit_events = [e for e in events_list if e.get("severity") == "critical"]
    warn_events = [e for e in events_list if e.get("severity") == "warning"]

    lines = [
        "# DriftSentry Security Audit Report",
        "",
        "> Automated port reconnaissance and temporal attack-surface drift assessment.",
        "",
        "## 1. Executive Summary",
        "",
        f"- **Target Spec:** `{scan.get('target_spec', 'Unknown')}`",
        f"- **Scan ID:** `#{scan.get('scan_id', 'N/A')}`" + (f" (Baseline: `{scan.get('baseline_tag')}`)" if scan.get('baseline_tag') else ""),
        f"- **Protocol Engine:** `{scan.get('protocol', 'tcp-connect')}`",
        f"- **Port Specification:** `{scan.get('port_spec', 'top100')}`",
        f"- **Started At (UTC):** `{scan.get('started_at', 'N/A')}`",
        f"- **Finished At (UTC):** `{scan.get('finished_at', 'N/A')}`",
        f"- **Total Probes Recorded:** {len(res_list)}",
        f"- **Open Services Discovered:** **{len(open_ports)}**",
        f"- **Drift Events Detected:** **{len(events_list)}** (🔴 {len(crit_events)} Critical, 🟡 {len(warn_events)} Warning)",
        "",
        "---",
        "",
        "## 2. Discovered Open Ports & Services",
        "",
    ]

    if not open_ports:
        lines.append("_No open ports discovered during this scan._\n")
    else:
        lines.extend([
            "| Host | Port | Proto | State | Service Guess | Version / Banner | Latency |",
            "|---|---|---|---|---|---|---|",
        ])
        for r in open_ports:
            host_str = r.get("ip_address") or r.get("host", "Unknown")
            port = r.get("port", 0)
            proto = r.get("protocol", "tcp")
            state = r.get("state", "open")
            svc = r.get("service_guess") or "unknown"
            banner = r.get("banner") or "—"
            lat = f"{r.get('response_time_ms')} ms" if r.get("response_time_ms") is not None else "—"
            lines.append(f"| `{host_str}` | **{port}** | `{proto}` | `{state}` | `{svc}` | `{banner}` | {lat} |")
        lines.append("")

    lines.extend([
        "---",
        "",
        "## 3. Attack-Surface Drift Events",
        "",
    ])

    if not events_list:
        lines.append("✓ **Zero drift detected** — Attack surface matches previous baseline snapshot.\n")
    else:
        lines.extend([
            "| Severity | Event Type | Target | Port | Details |",
            "|---|---|---|---|---|",
        ])
        for e in events_list:
            sev = (e.get("severity") or "info").upper()
            sev_badge = f"🔴 **{sev}**" if sev == "CRITICAL" else (f"🟡 **{sev}**" if sev == "WARNING" else f"ℹ️ {sev}")
            etype = e.get("event_type", "unknown")
            target = e.get("ip_address") or scan.get("target_spec", "Target")
            port_val = str(e.get("port") or "—")
            detail_raw = e.get("detail", "")
            try:
                detail_parsed = json.loads(detail_raw) if isinstance(detail_raw, str) and detail_raw.startswith("{") else detail_raw
                detail_str = f"`{detail_parsed}`"
            except Exception:
                detail_str = str(detail_raw)
            lines.append(f"| {sev_badge} | `{etype}` | `{target}` | `{port_val}` | {detail_str} |")
        lines.append("")

    lines.extend([
        "---",
        "",
        "## 4. Remediation & Hardening Guidance",
        "",
        "1. **Unintended Exposures:** Immediately verify whether newly opened ports correspond to approved deployment changes.",
        "2. **Outdated Versions:** Inspect service banners (e.g., legacy OpenSSH or FTP versions) against known CVE databases.",
        "3. **Continuous Monitoring:** Schedule regular automated cron scans (`driftsentry scan -a`) to detect future drift within minutes.",
        "",
        "_Report generated by DriftSentry Attack Surface Sentinel._",
        "",
    ])

    content = "\n".join(lines)
    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
    return content


def generate_html_report(
    scan_data: dict,
    results: list[dict],
    drift_events: list[dict],
    output_path: Optional[Path | str] = None,
) -> str:
    """Generate a self-contained, accessible, print-to-PDF ready HTML security audit report."""
    scan = _dict_from_row(scan_data)
    res_list = [_dict_from_row(r) for r in results]
    events_list = [_dict_from_row(e) for e in drift_events]

    open_ports = [r for r in res_list if r.get("state") == "open"]
    crit_events = [e for e in events_list if e.get("severity") == "critical"]
    warn_events = [e for e in events_list if e.get("severity") == "warning"]

    target_esc = html.escape(str(scan.get("target_spec", "Unknown")))
    scan_id_esc = html.escape(str(scan.get("scan_id", "N/A")))
    proto_esc = html.escape(str(scan.get("protocol", "tcp-connect")))
    started_esc = html.escape(str(scan.get("started_at", "—")))
    finished_esc = html.escape(str(scan.get("finished_at", "—")))
    tag_esc = html.escape(str(scan.get("baseline_tag") or "None"))

    open_rows = []
    for r in open_ports:
        h = html.escape(str(r.get("ip_address") or r.get("host") or "—"))
        p = html.escape(str(r.get("port", "")))
        pr = html.escape(str(r.get("protocol", "tcp")))
        st = html.escape(str(r.get("state", "open")))
        svc = html.escape(str(r.get("service_guess") or "unknown"))
        ban = html.escape(str(r.get("banner") or "—"))
        lat = html.escape(f"{r.get('response_time_ms')} ms") if r.get("response_time_ms") is not None else "—"
        open_rows.append(f"""
        <tr>
            <td><code>{h}</code></td>
            <td><strong class="port-badge">{p}</strong></td>
            <td><span class="badge proto-badge">{pr}</span></td>
            <td><span class="badge state-open">{st}</span></td>
            <td><strong>{svc}</strong></td>
            <td><span class="banner-text">{ban}</span></td>
            <td>{lat}</td>
        </tr>""")

    event_rows = []
    for e in events_list:
        sev = (e.get("severity") or "info").lower()
        sev_label = sev.upper()
        etype = html.escape(str(e.get("event_type", "unknown")))
        h = html.escape(str(e.get("ip_address") or scan.get("target_spec") or "—"))
        p = html.escape(str(e.get("port") or "—"))
        det = html.escape(str(e.get("detail") or "—"))
        badge_cls = f"sev-{sev}"
        event_rows.append(f"""
        <tr>
            <td><span class="badge {badge_cls}">{sev_label}</span></td>
            <td><code>{etype}</code></td>
            <td><code>{h}</code></td>
            <td><strong>{p}</strong></td>
            <td><span class="detail-text">{det}</span></td>
        </tr>""")

    open_table_html = """
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th scope="col">Host</th>
                    <th scope="col">Port</th>
                    <th scope="col">Protocol</th>
                    <th scope="col">State</th>
                    <th scope="col">Service</th>
                    <th scope="col">Version / Banner</th>
                    <th scope="col">Latency</th>
                </tr>
            </thead>
            <tbody>
    """ + "".join(open_rows) + """
            </tbody>
        </table>
    </div>
    """ if open_ports else "<div class='empty-state'>✓ No open ports discovered.</div>"

    events_table_html = """
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Event Type</th>
                    <th scope="col">Host</th>
                    <th scope="col">Port</th>
                    <th scope="col">Details</th>
                </tr>
            </thead>
            <tbody>
    """ + "".join(event_rows) + """
            </tbody>
        </table>
    </div>
    """ if events_list else "<div class='empty-state-good'>✓ Zero attack-surface drift detected since previous baseline.</div>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DriftSentry Audit Report - {target_esc} (Scan #{scan_id_esc})</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-card: #1e293b;
            --bg-table-row: #1e293b;
            --bg-table-alt: #162032;
            --border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
        }}
        @media (prefers-color-scheme: light) {{
            :root {{
                --bg-primary: #f8fafc;
                --bg-card: #ffffff;
                --bg-table-row: #ffffff;
                --bg-table-alt: #f1f5f9;
                --border: #cbd5e1;
                --text-primary: #0f172a;
                --text-secondary: #475569;
                --accent-cyan: #0891b2;
                --accent-blue: #2563eb;
                --accent-green: #059669;
                --accent-red: #dc2626;
                --accent-yellow: #d97706;
            }}
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem 1rem;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        .header-title {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 0.5rem;
        }}
        h1 {{
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--accent-cyan);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .scan-id-tag {{
            background: var(--border);
            color: var(--text-primary);
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
        }}
        .subtitle {{
            color: var(--text-secondary);
            font-size: 0.95rem;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}
        .stat-label {{
            font-size: 0.825rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            font-weight: 600;
        }}
        .stat-value {{
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--text-primary);
        }}
        .stat-sub {{
            font-size: 0.825rem;
            color: var(--text-secondary);
        }}
        .section-title {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-primary);
        }}
        .table-container {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            overflow-x: auto;
            margin-bottom: 2.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.925rem;
        }}
        th {{
            background: rgba(0, 0, 0, 0.2);
            padding: 0.875rem 1rem;
            font-weight: 600;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 0.875rem 1rem;
            border-bottom: 1px solid var(--border);
        }}
        tr:nth-child(even) {{
            background: var(--bg-table-alt);
        }}
        code {{
            background: rgba(0, 0, 0, 0.25);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.875rem;
        }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge.state-open {{ background: rgba(16, 185, 129, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }}
        .badge.proto-badge {{ background: rgba(59, 130, 246, 0.2); color: var(--accent-blue); }}
        .badge.sev-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}
        .badge.sev-warning {{ background: rgba(245, 158, 11, 0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }}
        .badge.sev-info {{ background: rgba(6, 182, 212, 0.2); color: var(--accent-cyan); }}
        .port-badge {{ font-size: 1.05rem; color: var(--accent-cyan); }}
        .banner-text {{ font-size: 0.85rem; color: var(--text-secondary); font-family: ui-monospace, monospace; }}
        .empty-state {{
            background: var(--bg-card);
            padding: 2rem;
            text-align: center;
            border: 1px dashed var(--border);
            border-radius: 10px;
            color: var(--text-secondary);
            margin-bottom: 2rem;
        }}
        .empty-state-good {{
            background: rgba(16, 185, 129, 0.1);
            color: var(--accent-green);
            padding: 1.5rem;
            border-radius: 10px;
            border: 1px solid var(--accent-green);
            text-align: center;
            font-weight: 600;
            margin-bottom: 2rem;
        }}
        footer {{
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.85rem;
            padding: 2rem 0;
            border-top: 1px solid var(--border);
        }}
        @media print {{
            body {{ background: #ffffff !important; color: #000000 !important; padding: 0; }}
            header, .stat-card, .table-container {{ box-shadow: none !important; border: 1px solid #ccc !important; }}
            tr:nth-child(even) {{ background: #f9f9f9 !important; }}
            code {{ background: #eee !important; color: #000 !important; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>🛡️ DriftSentry Security Audit Report</h1>
                <span class="scan-id-tag">Scan #{scan_id_esc}</span>
            </div>
            <p class="subtitle">Target: <strong>{target_esc}</strong> &bull; Protocol Engine: <strong>{proto_esc}</strong> &bull; Baseline: <strong>{tag_esc}</strong></p>
            <p class="subtitle" style="margin-top: 0.25rem;">Timeline: {started_esc} &rarr; {finished_esc}</p>
        </header>

        <section class="stats-grid" aria-label="Scan Statistics">
            <div class="stat-card">
                <span class="stat-label">Open Ports</span>
                <span class="stat-value" style="color: var(--accent-green);">{len(open_ports)}</span>
                <span class="stat-sub">Active listening services</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Drift Events</span>
                <span class="stat-value" style="color: {'var(--accent-red)' if crit_events else ('var(--accent-yellow)' if warn_events else 'var(--text-primary)')};">{len(events_list)}</span>
                <span class="stat-sub">🔴 {len(crit_events)} Critical &bull; 🟡 {len(warn_events)} Warning</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Total Probes</span>
                <span class="stat-value">{len(res_list)}</span>
                <span class="stat-sub">Spec: {html.escape(str(scan.get('port_spec', 'top100')))}</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Scanner Engine</span>
                <span class="stat-value" style="font-size: 1.25rem; color: var(--accent-cyan);">{proto_esc.upper()}</span>
                <span class="stat-sub">Automated Recon & Diff</span>
            </div>
        </section>

        <main>
            <h2 class="section-title">🔍 Discovered Open Ports & Services ({len(open_ports)})</h2>
            {open_table_html}

            <h2 class="section-title">⚡ Attack-Surface Drift Events ({len(events_list)})</h2>
            {events_table_html}
        </main>

        <footer>
            <p>Generated by DriftSentry v0.3.0 &bull; Continuous Attack Surface Sentinel &bull; RFC Compliant</p>
        </footer>
    </div>
</body>
</html>
"""
    if output_path:
        Path(output_path).write_text(html_content, encoding="utf-8")
    return html_content


def generate_csv_report(
    scan_data: dict,
    results: list[dict],
    drift_events: list[dict],
    output_path: Optional[Path | str] = None,
) -> str:
    """Generate an RFC 4180 CSV spreadsheet report."""
    scan = _dict_from_row(scan_data)
    res_list = [_dict_from_row(r) for r in results]
    events_list = [_dict_from_row(e) for e in drift_events]

    # Map events by port for lookup
    drift_by_port: dict[int, dict] = {}
    for e in events_list:
        p_val = e.get("port")
        if p_val is not None:
            try:
                drift_by_port[int(p_val)] = e
            except (ValueError, TypeError):
                pass

    out = io.StringIO()
    writer = csv.writer(out, quoting=csv.QUOTE_MINIMAL)
    writer.writerow([
        "scan_id",
        "target",
        "host",
        "hostname",
        "port",
        "protocol",
        "state",
        "service",
        "banner",
        "response_time_ms",
        "drift_event",
        "severity",
    ])

    scan_id = scan.get("scan_id", "")
    target = scan.get("target_spec", "")

    for r in res_list:
        p = r.get("port", 0)
        ev = drift_by_port.get(p)
        writer.writerow([
            scan_id,
            target,
            r.get("ip_address") or r.get("host") or "",
            r.get("hostname") or "",
            p,
            r.get("protocol", "tcp"),
            r.get("state", ""),
            r.get("service_guess") or "",
            r.get("banner") or "",
            r.get("response_time_ms") if r.get("response_time_ms") is not None else "",
            ev.get("event_type", "") if ev else "",
            ev.get("severity", "") if ev else "",
        ])

    csv_text = out.getvalue()
    if output_path:
        Path(output_path).write_text(csv_text, encoding="utf-8")
    return csv_text


def export_scan_report(
    conn: sqlite3.Connection,
    scan_id: int,
    report_format: str = "html",
    output_dir: Union[Path, str] = "reports",
) -> list[Path]:
    """Fetch scan from database, render selected report(s), and save to output_dir."""
    scan = db.get_scan(conn, scan_id)
    if not scan:
        raise ValueError(f"Scan ID #{scan_id} not found in database.")

    scan_dict = _dict_from_row(scan)
    results = [dict(r) for r in db.get_results_for_scan(conn, scan_id)]
    events = [dict(e) for e in db.get_drift_events(conn, scan_id)]

    out_p = Path(output_dir)
    out_p.mkdir(parents=True, exist_ok=True)

    target_clean = scan_dict.get("target_spec", "target").replace("/", "_").replace(":", "_").replace(" ", "_")
    base_name = f"driftsentry_scan_{scan_id}_{target_clean}"

    formats = ["html", "md", "csv"] if report_format.lower() in ("all", "both") else [report_format.lower()]
    written_paths: list[Path] = []

    for fmt in formats:
        if fmt == "html":
            dest = out_p / f"{base_name}.html"
            generate_html_report(scan_dict, results, events, output_path=dest)
            written_paths.append(dest)
        elif fmt in ("md", "markdown"):
            dest = out_p / f"{base_name}.md"
            generate_markdown_report(scan_dict, results, events, output_path=dest)
            written_paths.append(dest)
        elif fmt == "csv":
            dest = out_p / f"{base_name}.csv"
            generate_csv_report(scan_dict, results, events, output_path=dest)
            written_paths.append(dest)
        else:
            raise ValueError(f"Unsupported report format: '{fmt}'. Choose from 'html', 'md', 'csv', or 'all'.")

    return written_paths
