"""
cli.py — DriftSentry command-line interface.

Subcommands (MVP):
  init     — create config template + empty DB
  scan     — run one scan, diff, alert
  diff     — ad-hoc diff between two stored scans
  history  — show scan history for a host or all hosts

Post-MVP (stubs):
  watch    — daemon loop
  prune    — retention cleanup
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import logging
import sys
from datetime import datetime, timezone

# Ensure Unicode output works on Windows terminals (cp1252 → utf-8)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None

from driftsentry.alerting.sinks import (
    dispatch, debounce_events, make_json_sink,
    make_stdout_sink, make_syslog_sink, make_webhook_sink,
)
from driftsentry.config import Config, load_config
from driftsentry.diff.engine import DriftEvent, compute_drift
from driftsentry.scanner.engine import run_scan
from driftsentry.store import db

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# UI Presentation & Banners (Rich Terminal)
# ---------------------------------------------------------------------------

def print_banner() -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
        console = Console()
        banner_ascii = (
            "  ____       _  __ _   ____             _              \n"
            " |  _ \\ _ __(_)/ _| |_/ ___|  ___ _ __ | |_ _ __ _   _ \n"
            " | | | | '__| | |_| __\\___ \\ / _ \\ '_ \\| __| '__| | | |\n"
            " | |_| | |  | |  _| |_ ___) |  __/ | | | |_| |  | |_| |\n"
            " |____/|_|  |_|_|  \\__|____/ \\___|_| |_|\\__|_|   \\__, |\n"
            "                                                 |___/ "
        )
        t = Text(banner_ascii, style="bold cyan")
        t.append("\n\n🛡️  PORT SCANNER WITH ATTACK-SURFACE DRIFT DETECTION", style="bold yellow")
        t.append(" | ", style="dim")
        t.append("v0.3.0", style="bold green")
        console.print(Panel(t, border_style="cyan", padding=(0, 2)))
    except Exception:
        print("""
  ____       _  __ _   ____             _              
 |  _ \\ _ __(_)/ _| |_/ ___|  ___ _ __ | |_ _ __ _   _ 
 | | | | '__| | |_| __\\___ \\ / _ \\ '_ \\| __| '__| | | |
 | |_| | |  | |  _| |_ ___) |  __/ | | | |_| |  | |_| |
 |____/|_|  |_|_|  \\__|____/ \\___|_| |_|\\__|_|   \\__, |
                                                 |___/ 
 DriftSentry — Port Scanner with Attack-Surface Drift Detection (v0.3.0)
""")


def _print_scan_header(scan_id: int, target: str, ports: str, proto: str, conc: int, timeout: int) -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        console = Console()
        grid = Table.grid(expand=True)
        grid.add_column(style="bold yellow", width=16)
        grid.add_column(style="bold white")
        grid.add_column(style="bold yellow", width=16)
        grid.add_column(style="bold white")
        grid.add_row("🎯 Target:", f"{target}", "🔌 Port Spec:", f"{ports}")
        grid.add_row("⚡ Protocol:", f"{proto}", "⏱️  Probe Timeout:", f"{timeout} ms")
        grid.add_row("🚀 Concurrency:", f"{conc} threads", "🆔 Scan ID:", f"#{scan_id}")
        console.print(Panel(grid, title=f"[bold green]▶ Launching Scan #{scan_id}[/bold green]", border_style="green", padding=(0, 1)))
    except Exception:
        print(f"→  Scan #{scan_id} started  target={target}  ports={ports}  proto={proto}")


def _print_service_details(current_rows, scan_id: int) -> None:
    open_rows = [r for r in current_rows if r["state"] == "open"]
    if not open_rows:
        return
    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        table = Table(
            title=f"🔎 Discovered Services & Version Telemetry (Scan #{scan_id})",
            show_header=True,
            header_style="bold cyan",
            border_style="blue",
        )
        table.add_column("Target Host", style="bold white", width=16)
        table.add_column("Port / Proto", style="yellow", width=14)
        table.add_column("State", style="bold green", width=8)
        table.add_column("Service", style="cyan", width=14)
        table.add_column("Vendor / Version Fingerprint", style="magenta", width=28)
        table.add_column("Latency", style="white", width=9)
        table.add_column("Banner Preview", style="dim", overflow="ellipsis")

        for r in open_rows:
            lat = f"{r['response_time_ms']} ms" if r["response_time_ms"] is not None else "—"
            banner_str = (r["banner"] or "").strip().replace("\r", " ").replace("\n", " ")
            if len(banner_str) > 40:
                banner_str = banner_str[:37] + "..."
            table.add_row(
                r["ip_address"],
                f"{r['port']}/{r['protocol']}",
                r["state"].upper(),
                r["service_guess"].split()[0] if r["service_guess"] else "unknown",
                r["service_guess"] or "—",
                lat,
                banner_str or "—",
            )
        console.print(table)
    except Exception:
        print(f"\n--- Open Services & Versions (Scan #{scan_id}) ---")
        for r in open_rows:
            print(f"  {r['ip_address']}:{r['port']}/{r['protocol']}  [{r['state']}]  "
                  f"service={r['service_guess']} latency={r['response_time_ms']}ms")


def _print_scan_summary(scan_id: int, target: str, total_probes: int, open_ports: int, drift_events: int, elapsed_s: float) -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        console = Console()
        grid = Table.grid(expand=True)
        grid.add_column(style="bold yellow", width=16)
        grid.add_column(style="bold white")
        grid.add_column(style="bold yellow", width=16)
        grid.add_column(style="bold white")
        
        pps = f"{(total_probes / elapsed_s):.1f} probes/s" if elapsed_s > 0 else "—"
        drift_color = "red" if drift_events > 0 else "green"
        grid.add_row("🎯 Target:", f"{target}", "⏱️  Duration:", f"{elapsed_s:.2f}s")
        grid.add_row("📊 Total Probes:", f"{total_probes} ({pps})", "🟢 Open Ports:", f"{open_ports}")
        grid.add_row("⚠️  Drift Events:", f"[{drift_color}]{drift_events} changes detected[/{drift_color}]", "💾 Scan ID:", f"#{scan_id}")
        console.print(Panel(grid, title=f"[bold cyan]📊 Scan #{scan_id} Telemetry Summary[/bold cyan]", border_style="cyan", padding=(0, 1)))
    except Exception:
        print(f"\nScan #{scan_id} complete — {open_ports} open port(s), {drift_events} drift event(s) in {elapsed_s:.2f}s.")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="driftsentry",
        description="Port scanner with persistent drift detection.",
    )
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging verbosity (default: INFO)")

    subs = parser.add_subparsers(dest="command", required=True)

    # ── init ────────────────────────────────────────────────────────────────
    p_init = subs.add_parser("init", aliases=["i"], help="Create config template and empty database")
    p_init.add_argument("-d", "--db", default="driftsentry.db",
                        help="Path to the SQLite database (default: driftsentry.db)")
    p_init.add_argument("-c", "--config", default="config.yaml",
                        help="Path to write a template config.yaml")

    # ── scan ────────────────────────────────────────────────────────────────
    p_scan = subs.add_parser("scan", aliases=["s"], help="Run a scan, store results, and report drift")
    _add_scan_args(p_scan)

    # ── nmap ────────────────────────────────────────────────────────────────
    p_nmap = subs.add_parser("nmap", aliases=["nm"], help="Run scan using integrated Nmap engine with version detection")
    _add_scan_args(p_nmap)

    # ── diff ────────────────────────────────────────────────────────────────
    p_diff = subs.add_parser("diff", aliases=["d"], help="Ad-hoc diff between two stored scans")
    p_diff.add_argument("--from", dest="from_id", type=int, required=True)
    p_diff.add_argument("--to",   dest="to_id",   type=int, required=True)
    p_diff.add_argument("-d", "--db", default="driftsentry.db")
    p_diff.add_argument("--json", dest="json_out", action="store_true")

    # ── history ─────────────────────────────────────────────────────────────
    p_hist = subs.add_parser("history", aliases=["h", "hist"], help="Show scan history")
    p_hist.add_argument("--host",  default=None, help="Filter to a specific IP address")
    p_hist.add_argument("--limit", type=int, default=20)
    p_hist.add_argument("-d", "--db", default="driftsentry.db")

    # ── tag ──────────────────────────────────────────────────────────────────
    p_tag = subs.add_parser("tag", aliases=["t"], help="Apply a baseline label to a stored scan")
    p_tag.add_argument("--scan-id", type=int, required=True, dest="scan_id",
                       help="ID of the scan to tag")
    p_tag.add_argument("-n", "--name", required=True,
                       help="Baseline label, e.g. 'pre-deploy', 'golden'")
    p_tag.add_argument("-d", "--db", default="driftsentry.db")

    # ── baselines ────────────────────────────────────────────────────────────
    p_bl = subs.add_parser("baselines", aliases=["b", "base"], help="List all tagged baseline scans")
    p_bl.add_argument("-d", "--db", default="driftsentry.db")

    # ── watch ─────────────────────────────────────────────────────────────────
    p_watch = subs.add_parser("watch", aliases=["w"], help="Daemon loop: scan on a fixed interval")
    _add_scan_args(p_watch)
    p_watch.add_argument("-i", "--interval", type=int, default=300,
                         help="Scan interval in seconds (default: 300)")

    # ── prune ────────────────────────────────────────────────────────────────
    p_prune = subs.add_parser("prune", aliases=["p"], help="Delete old scans and reclaim DB space")
    p_prune.add_argument("--keep-days", type=int, default=90,
                         help="Retain scans newer than this many days (default: 90)")
    p_prune.add_argument("-d", "--db", default="driftsentry.db")

    # ── install-service ──────────────────────────────────────────────────────
    p_svc = subs.add_parser("install-service", aliases=["svc"],
                             help="Generate systemd .service + .timer unit files")
    p_svc.add_argument("-c", "--config",   default="/etc/driftsentry/config.yaml",
                       help="Config file path in the service unit")
    p_svc.add_argument("--binary",   default="/usr/local/bin/driftsentry",
                       help="Path to the driftsentry binary in the unit")
    p_svc.add_argument("-i", "--interval", default="15min",
                       help="OnUnitActiveSec for the timer (default: 15min)")
    p_svc.add_argument("-o", "--output-dir", default=".",
                       help="Directory to write .service and .timer files (default: .)")
    p_svc.add_argument("--install",  action="store_true",
                       help="Write directly to /etc/systemd/system/ (requires root)")

    # ── report ───────────────────────────────────────────────────────────────
    p_rep = subs.add_parser("report", aliases=["rep", "r"],
                            help="Generate security audit reports (HTML, Markdown, CSV)")
    p_rep.add_argument("scan_id", type=int, help="ID of the scan to generate reports for")
    p_rep.add_argument("-f", "--format", default="all", choices=["html", "md", "csv", "all"],
                       help="Report format: html, md (markdown), csv, or all (default: all)")
    p_rep.add_argument("-o", "--output-dir", default="reports",
                       help="Directory to save report files (default: reports/)")
    p_rep.add_argument("-d", "--db", default="driftsentry.db",
                       help="Path to SQLite DB (default: driftsentry.db)")

    # ── console ──────────────────────────────────────────────────────────────
    p_con = subs.add_parser("console", aliases=["c", "shell"],
                            help="Start interactive CLI console (stay inside app)")

    return parser


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-c", "--config",     default=None,
                   help="Path to config.yaml")
    p.add_argument("-t", "--target",     default=None,
                   help="Target: IP, hostname, CIDR, or @file")
    p.add_argument("-p", "--ports",      default="top100",
                   help="Port spec: top100 (default), top1000, all, 80, 1-1024, or 22,80,443")
    p.add_argument("--protocol",         default=None,
                   choices=["tcp-connect", "tcp-syn", "udp", "tcp+udp", "nmap"])
    p.add_argument("--nmap",             action="store_true", dest="use_nmap",
                   help="Run integrated native Nmap with service/version detection (-sV)")
    p.add_argument("--concurrency",      type=int, default=None)
    p.add_argument("--timeout",          type=int, default=None, dest="timeout_ms",
                   help="Per-probe timeout in ms (default: 800)")
    p.add_argument("--rate-limit",       type=int, default=None, dest="rate_limit_pps",
                   help="Max probes/sec (default: unlimited)")
    p.add_argument("-d", "--db",         default="driftsentry.db",
                   help="Path to SQLite DB (default: driftsentry.db)")
    p.add_argument("--webhook",          default=None, dest="webhook_url",
                   help="Webhook URL for alerts")
    p.add_argument("--syslog",           action="store_true", dest="syslog",
                   help="Send drift events to local syslog (Linux only)")
    p.add_argument("--json",             action="store_true", dest="json_stdout",
                   help="Machine-readable JSON output")
    p.add_argument("--always-notify",    action="store_true", dest="always_notify",
                   help="Send a full status report every run")
    p.add_argument("-a", "--auth", "--authorized", action="store_true", dest="authorized",
                   help="Confirm you have authorization to scan this target (short: -a)")
    p.add_argument("-v", "--verbose",    action="store_true", dest="verbose",
                   help="Verbose telemetry: show detailed services, vendors, versions, latency, and banners")
    p.add_argument("--compare-to",       type=int, default=None, dest="compare_to",
                   help="Compare against a specific prior scan ID")
    p.add_argument("-b", "--baseline",   default=None, dest="baseline",
                   help="Compare against a tagged baseline scan, e.g. 'pre-deploy'")
    p.add_argument("--debounce",         type=int, default=1, dest="debounce",
                   help="Only alert after N consecutive scans show same change (default: 1 = off)")


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    db_path = Path(args.db)
    cfg_path = Path(args.config)

    # Create DB
    conn = db.init_db(db_path)
    conn.close()
    print(f"✓  Database created: {db_path.resolve()}")

    # Write template config
    if not cfg_path.exists():
        template = {
            "target": "127.0.0.1",
            "ports": "top1000",
            "protocol": "tcp-connect",
            "concurrency": 300,
            "timeout_ms": 800,
            "rate_limit_pps": None,
            "retention_days": 90,
            "db_path": str(db_path),
            "alerts": {
                "webhook": None,
                "syslog": False,
                "json_stdout": False,
            },
        }
        if yaml is not None:
            with open(cfg_path, "w", encoding="utf-8") as f:
                yaml.dump(template, f, default_flow_style=False, sort_keys=False)
            print(f"✓  Config template written: {cfg_path.resolve()}")
        else:
            default_yaml = """# DriftSentry Configuration Template
target: 127.0.0.1
ports: top100
protocol: tcp-connect
concurrency: 300
timeout_ms: 800
rate_limit_pps: null
retention_days: 90
db_path: driftsentry.db
alerts:
  webhook: null
  syslog: false
  json_stdout: false
"""
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(default_yaml)
            print(f"✓  Config template written: {cfg_path.resolve()}")
    else:
        print(f"  Config already exists: {cfg_path} (skipped)")

    print("\nNext: edit config.yaml, then run:  driftsentry scan -c config.yaml --authorized")
    return 0


def cmd_nmap(args: argparse.Namespace) -> int:
    """Run scan using integrated Nmap scanner."""
    args.protocol = "nmap"
    return cmd_scan(args)


def cmd_scan(args: argparse.Namespace) -> int:
    proto = "nmap" if getattr(args, "use_nmap", False) else args.protocol
    cfg = load_config(
        config_file=args.config,
        target=args.target,
        ports=args.ports,
        protocol=proto,
        concurrency=args.concurrency,
        timeout_ms=args.timeout_ms,
        rate_limit_pps=args.rate_limit_pps,
        webhook_url=args.webhook_url,
        json_stdout=args.json_stdout,
        always_notify=args.always_notify,
        authorized=args.authorized,
        db_path=Path(args.db),
    )

    if not cfg.target:
        print("ERROR: No target specified. Use -t/--target or set 'target' in config.yaml",
              file=sys.stderr)
        return 1

    # ── Authorization gate ────────────────────────────────────────────────
    if not cfg.authorized:
        try:
            from rich.console import Console
            from rich.panel import Panel
            Console().print(Panel(
                "[bold red]⚠️  ACTIVE RECONNAISSANCE AUTHORIZATION REQUIRED[/bold red]\n\n"
                "DriftSentry actively probes target network ports. Only scan networks\n"
                "you own or have explicit written authorization to test (CFAA / UK CMA compliance).\n\n"
                "[bold yellow]👉 Add [bold white]-a[/bold white] or [bold white]--authorized[/bold white] to confirm permission and run the scan.[/bold yellow]",
                border_style="red",
                padding=(1, 2),
            ))
        except Exception:
            print(
                "\n⚠️  DriftSentry will connect to ports on the target host(s).\n"
                "   Only scan hosts/networks you own or have explicit written authorization to test.\n"
                "   Unauthorized scanning may violate laws (CFAA, Computer Misuse Act, etc.).\n"
                "\n   Re-run with -a or --authorized to confirm you have permission.\n",
                file=sys.stderr,
            )
        return 1

    conn = db.init_db(cfg.db_path)
    import time
    t0 = time.monotonic()

    try:
        # Start scan record
        scan_id = db.start_scan(
            conn,
            target_spec=cfg.target,
            port_spec=cfg.ports,
            protocol=cfg.protocol,
        )
        if not cfg.json_stdout:
            _print_scan_header(scan_id, cfg.target, cfg.ports, cfg.protocol, cfg.concurrency, cfg.timeout_ms)

        # Run the async scan
        results = asyncio.run(run_scan(conn, scan_id, cfg))
        elapsed_s = time.monotonic() - t0
        total_probes = len(results) if results else 0

        # Mark finished
        db.finish_scan(conn, scan_id)

        # ── Diff ─────────────────────────────────────────────────────────
        compare_to = getattr(args, "compare_to", None)
        baseline   = getattr(args, "baseline",   None)

        if compare_to:
            prior_scan_id = compare_to
        elif baseline:
            prior_scan_id = db.get_baseline_scan_id(conn, baseline, cfg.target)
            if prior_scan_id is None:
                print(f"WARNING: No baseline scan found with tag '{baseline}' "
                      f"for target '{cfg.target}'. Diffing against last scan.",
                      file=sys.stderr)
                prior_scan_id = db.get_prior_scan_id(conn, scan_id, cfg.target)
        else:
            prior_scan_id = db.get_prior_scan_id(conn, scan_id, cfg.target)

        current_rows = db.get_results_for_scan(conn, scan_id)
        prior_rows = db.get_results_for_scan(conn, prior_scan_id) if prior_scan_id else []

        events = compute_drift(current_rows, prior_rows, scan_id, prior_scan_id)

        # ── Debounce (v0.2) ───────────────────────────────────────────────
        debounce_n = getattr(args, "debounce", 1)
        if debounce_n > 1 and prior_scan_id:
            events = debounce_events(events, conn, scan_id, cfg.target, debounce_n)

        # ── Persist drift events to DB ────────────────────────────────────
        for ev in events:
            db.save_drift_event(
                conn,
                scan_id=ev.scan_id,
                prior_scan_id=ev.prior_scan_id,
                host_id=ev.host_id,
                port=ev.port,
                event_type=ev.event_type,
                detail=json.dumps(ev.detail),
                severity=ev.severity,
            )
        conn.commit()

        # ── Discovered Services & Version Telemetry (verbose or open ports) ──
        open_count = sum(1 for r in current_rows if r["state"] == "open")
        if not cfg.json_stdout:
            if getattr(args, "verbose", False) or open_count > 0:
                _print_service_details(current_rows, scan_id)

        # ── Alerting / Drift Output ───────────────────────────────────────
        meta = {
            "scan_id": scan_id,
            "prior_scan_id": prior_scan_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target": cfg.target,
        }

        sinks = []
        if cfg.json_stdout:
            sinks.append(make_json_sink())
        else:
            sinks.append(make_stdout_sink(use_rich=True))
        if cfg.webhook_url:
            sinks.append(make_webhook_sink(cfg.webhook_url))
        if getattr(args, "syslog", False) or cfg.syslog:
            sinks.append(make_syslog_sink())

        if events or cfg.always_notify:
            dispatch(events, meta, sinks)
        else:
            if not cfg.json_stdout:
                try:
                    from rich.console import Console
                    Console().print(f"\n[bold green]✓  No attack-surface drift detected[/bold green] [dim](scan #{scan_id} vs #{prior_scan_id or 'n/a'})[/dim]\n")
                except Exception:
                    print(f"\n✓  No drift detected  (scan #{scan_id} vs #{prior_scan_id or 'n/a'})\n")

        if not cfg.json_stdout:
            _print_scan_summary(scan_id, cfg.target, total_probes, open_count, len(events), elapsed_s)
            try:
                from rich.console import Console
                Console().print(f"[dim]💡 Tip: Generate HTML/Markdown/CSV audit reports: [bold white]driftsentry report {scan_id}[/bold white][/dim]\n")
            except Exception:
                print(f"💡 Tip: Generate report via: driftsentry report {scan_id}\n")

    except Exception as exc:
        print(f"ERROR: Scan execution failed: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()

    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    conn = db.get_connection(args.db)
    try:
        from_scan = db.get_scan(conn, args.from_id)
        if not from_scan:
            print(f"ERROR: Scan #{args.from_id} not found in {args.db}", file=sys.stderr)
            return 1
        to_scan = db.get_scan(conn, args.to_id)
        if not to_scan:
            print(f"ERROR: Scan #{args.to_id} not found in {args.db}", file=sys.stderr)
            return 1

        current_rows = db.get_results_for_scan(conn, args.to_id)
        prior_rows   = db.get_results_for_scan(conn, args.from_id)
        events = compute_drift(current_rows, prior_rows, args.to_id, args.from_id)
        meta = {"scan_id": args.to_id, "prior_scan_id": args.from_id,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        sink = make_json_sink() if args.json_out else make_stdout_sink()
        dispatch(events, meta, [sink])
    finally:
        conn.close()
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    conn = db.get_connection(args.db)
    try:
        rows = db.get_scan_history(conn, ip_address=args.host, limit=args.limit)
        if not rows:
            print("No scan history found.")
            return 0
        try:
            from rich.console import Console
            from rich.table import Table
            table = Table(title="DriftSentry Scan History", show_lines=True)
            table.add_column("ID",    width=6)
            table.add_column("Target")
            table.add_column("Ports")
            table.add_column("Proto")
            table.add_column("Started",  width=22)
            table.add_column("Finished", width=22)
            for row in rows:
                table.add_row(
                    str(row["scan_id"]),
                    row["target_spec"],
                    row["port_spec"],
                    row["protocol"],
                    row["started_at"] or "—",
                    row["finished_at"] or "—",
                )
            Console().print(table)
        except ImportError:
            for row in rows:
                print(f"#{row['scan_id']}  {row['target_spec']}  {row['started_at']}")
    finally:
        conn.close()
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    """Daemon loop: run scan repeatedly every --interval seconds.

    Handles SIGINT/SIGTERM cleanly — exits after the current scan finishes,
    never mid-write, so the DB stays consistent.
    """
    import signal
    import time

    interval = args.interval
    _stop = False

    def _handle_signal(sig, frame):
        nonlocal _stop
        print(f"\n[DriftSentry] Signal {sig} received — finishing current scan then exiting...")
        _stop = True

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    print(f"[DriftSentry] Watch mode started  interval={interval}s  "
          f"target={args.target or '(from config)'}  Ctrl-C to stop")

    run_count = 0
    while not _stop:
        run_count += 1
        print(f"\n[{run_count}] {_timestamp()} — running scan...")
        ret = cmd_scan(args)
        if ret != 0:
            print(f"[DriftSentry] Scan returned exit code {ret} — stopping watch loop.",
                  file=sys.stderr)
            return ret
        if _stop:
            break
        print(f"    Sleeping {interval}s until next scan...")
        # Sleep in small increments so SIGINT is responsive
        for _ in range(interval):
            if _stop:
                break
            time.sleep(1)

    print("[DriftSentry] Watch loop exited cleanly.")
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    """Delete scans (and their results/drift events) older than --keep-days.

    After deletion runs SQLite VACUUM to reclaim disk space.
    """
    from datetime import timedelta, timezone, datetime

    keep_days = args.keep_days
    db_path = Path(args.db)

    if not db_path.exists():
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        return 1

    conn = db.get_connection(db_path)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    try:
        # Find old scans
        old_scans = conn.execute(
            "SELECT scan_id FROM scans WHERE started_at < ?", (cutoff,)
        ).fetchall()

        if not old_scans:
            print(f"Nothing to prune — no scans older than {keep_days} days.")
            return 0

        old_ids = [r["scan_id"] for r in old_scans]
        placeholders = ",".join("?" * len(old_ids))

        # Delete in dependency order (child tables first)
        conn.execute(f"DELETE FROM drift_events WHERE scan_id IN ({placeholders})", old_ids)
        conn.execute(f"DELETE FROM results     WHERE scan_id IN ({placeholders})", old_ids)
        conn.execute(f"DELETE FROM scans       WHERE scan_id IN ({placeholders})", old_ids)
        conn.commit()

        print(f"Pruned {len(old_ids)} scan(s) older than {keep_days} days (cutoff: {cutoff}).")

        # VACUUM to reclaim disk space
        print("Running VACUUM...")
        conn.execute("VACUUM")
        print("Done.")

    finally:
        conn.close()

    return 0


def cmd_tag(args: argparse.Namespace) -> int:
    """Apply a baseline tag to an existing scan."""
    conn = db.get_connection(args.db)
    try:
        found = db.set_baseline_tag(conn, args.scan_id, args.name)
        if found:
            print(f"✓  Scan #{args.scan_id} tagged as '{args.name}'")
        else:
            print(f"ERROR: Scan #{args.scan_id} not found in {args.db}", file=sys.stderr)
            return 1
    finally:
        conn.close()
    return 0


def cmd_baselines(args: argparse.Namespace) -> int:
    """List all scans that have a baseline tag."""
    conn = db.get_connection(args.db)
    try:
        rows = db.list_baselines(conn)
        if not rows:
            print("No baseline tags found. Use: driftsentry tag --scan-id N --name NAME")
            return 0
        try:
            from rich.console import Console
            from rich.table import Table
            table = Table(title="DriftSentry Baselines", show_lines=True)
            table.add_column("Scan ID", width=8)
            table.add_column("Tag",     width=20)
            table.add_column("Target")
            table.add_column("Started", width=22)
            for row in rows:
                table.add_row(
                    str(row["scan_id"]),
                    row["baseline_tag"],
                    row["target_spec"],
                    row["started_at"],
                )
            Console().print(table)
        except ImportError:
            for row in rows:
                print(f"#{row['scan_id']}  [{row['baseline_tag']}]  "
                      f"{row['target_spec']}  {row['started_at']}")
    finally:
        conn.close()
    return 0


def cmd_install_service(args: argparse.Namespace) -> int:
    """Generate systemd .service and .timer unit files for DriftSentry.

    On Kali / Debian, copy the generated files to /etc/systemd/system/
    then run:
        systemctl daemon-reload
        systemctl enable --now driftsentry.timer
    """
    service_content = f"""\
[Unit]
Description=DriftSentry one-shot port scan
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={args.binary} scan -c {args.config} --authorized
StandardOutput=journal
StandardError=journal
"""

    timer_content = f"""\
[Unit]
Description=Run DriftSentry every {args.interval}
After=network-online.target

[Timer]
OnBootSec=2min
OnUnitActiveSec={args.interval}
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
"""

    import os

    out_dir = "/etc/systemd/system" if args.install else args.output_dir
    svc_path = os.path.join(out_dir, "driftsentry.service")
    tmr_path = os.path.join(out_dir, "driftsentry.timer")

    try:
        os.makedirs(out_dir, exist_ok=True)
        with open(svc_path, "w") as f:
            f.write(service_content)
        with open(tmr_path, "w") as f:
            f.write(timer_content)

        print(f"✓  Written: {svc_path}")
        print(f"✓  Written: {tmr_path}")

        if args.install:
            print("\nEnable and start the timer:")
            print("  systemctl daemon-reload")
            print("  systemctl enable --now driftsentry.timer")
            print("  systemctl status driftsentry.timer")
        else:
            print(f"\nTo install, copy to /etc/systemd/system/ or re-run with --install (as root):")
            print(f"  sudo cp {svc_path} {tmr_path} /etc/systemd/system/")
            print( "  sudo systemctl daemon-reload")
            print( "  sudo systemctl enable --now driftsentry.timer")

    except PermissionError:
        print(f"ERROR: Permission denied writing to {out_dir}. "
              "Re-run with sudo for --install.", file=sys.stderr)
        return 1

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate audit report(s) (HTML, Markdown, CSV) for a given scan ID."""
    from driftsentry.report.generator import export_scan_report
    conn = db.get_connection(args.db)
    try:
        written_paths = export_scan_report(
            conn,
            scan_id=args.scan_id,
            report_format=args.format,
            output_dir=args.output_dir,
        )
        try:
            from rich.console import Console
            from rich.table import Table
            c = Console()
            t = Table(title=f"DriftSentry Reports Generated (Scan #{args.scan_id})", show_lines=True)
            t.add_column("Format", style="bold cyan", width=12)
            t.add_column("File Path", style="bold green")
            t.add_column("Size", justify="right", width=14)
            for p in written_paths:
                t.add_row(p.suffix.lstrip(".").upper(), str(p.resolve()), f"{p.stat().st_size:,} bytes")
            c.print(t)
            c.print(f"[bold cyan]📁 Output Directory:[/bold cyan] {Path(args.output_dir).resolve()}\n")
        except ImportError:
            print(f"\n✓ Generated {len(written_paths)} report(s) for scan #{args.scan_id}:")
            for p in written_paths:
                print(f"  [{p.suffix.lstrip('.').upper()}] {p.resolve()} ({p.stat().st_size} bytes)")
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0


def cmd_console(args: argparse.Namespace) -> int:
    """Explicitly launch the interactive REPL console."""
    run_interactive_console()
    return 0


# ---------------------------------------------------------------------------
# Interactive REPL Console (Stays inside app)
# ---------------------------------------------------------------------------

def run_interactive_console() -> None:
    """Interactive command shell for DriftSentry.
    Keeps the user inside the application so they can type:
      scan 127.0.0.1
      s 127.0.0.1
      diff 9 10
      history
      baselines
      tag 10 golden
      exit
    """
    try:
        import readline  # enables arrow key history on Linux / Kali
    except ImportError:
        pass

    import shlex
    from rich.console import Console
    console = Console()

    print_banner()
    console.print("[bold green]Interactive Mode Active.[/bold green] Type [bold white]'help'[/bold white] for command list, [bold white]'exit'[/bold white] or [bold white]'q'[/bold white] to quit.\n")

    current_target = "127.0.0.1"

    while True:
        try:
            prompt = f"driftsentry ({current_target}) > "
            user_input = input(prompt).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting DriftSentry console.")
            break

        if not user_input:
            continue

        try:
            parts = shlex.split(user_input)
        except ValueError:
            parts = user_input.split()

        cmd = parts[0].lower()
        args_list = parts[1:]

        if cmd in ("exit", "quit", "q"):
            console.print("[dim]Exiting DriftSentry.[/dim]")
            break

        elif cmd in ("clear", "cls"):
            import os
            os.system("clear" if os.name != "nt" else "cls")
            print_banner()

        elif cmd in ("help", "?"):
            _print_console_help()

        elif cmd in ("scan", "s"):
            # Syntax: scan [target] [ports] [-v]
            target = current_target
            ports = "top100"
            verbose = False
            proto = "tcp-connect"

            idx = 0
            while idx < len(args_list):
                arg = args_list[idx]
                if arg in ("-t", "--target") and idx + 1 < len(args_list):
                    target = args_list[idx + 1]
                    idx += 2
                elif arg in ("-p", "--ports") and idx + 1 < len(args_list):
                    ports = args_list[idx + 1]
                    idx += 2
                elif arg in ("-v", "--verbose"):
                    verbose = True
                    idx += 1
                elif arg in ("--nmap", "-n"):
                    proto = "nmap"
                    idx += 1
                elif not arg.startswith("-"):
                    if idx == 0:
                        target = arg
                    elif idx == 1:
                        ports = arg
                    idx += 1
                else:
                    idx += 1

            current_target = target
            scan_args = argparse.Namespace(
                config=None,
                target=target,
                ports=ports,
                protocol=proto,
                concurrency=300,
                timeout_ms=800,
                rate_limit_pps=None,
                db="driftsentry.db",
                webhook_url=None,
                syslog=False,
                json_stdout=False,
                always_notify=False,
                authorized=True,  # inside interactive shell, authorization is implicit
                compare_to=None,
                baseline=None,
                debounce=1,
                verbose=verbose,
            )
            cmd_scan(scan_args)

        elif cmd in ("nmap", "nm"):
            # Syntax: nmap [target] [ports] [-v]
            target = current_target
            ports = "top100"
            verbose = True
            proto = "nmap"

            idx = 0
            while idx < len(args_list):
                arg = args_list[idx]
                if arg in ("-t", "--target") and idx + 1 < len(args_list):
                    target = args_list[idx + 1]
                    idx += 2
                elif arg in ("-p", "--ports") and idx + 1 < len(args_list):
                    ports = args_list[idx + 1]
                    idx += 2
                elif arg in ("-v", "--verbose"):
                    verbose = True
                    idx += 1
                elif not arg.startswith("-"):
                    if idx == 0:
                        target = arg
                    elif idx == 1:
                        ports = arg
                    idx += 1
                else:
                    idx += 1

            current_target = target
            scan_args = argparse.Namespace(
                config=None,
                target=target,
                ports=ports,
                protocol=proto,
                concurrency=300,
                timeout_ms=800,
                rate_limit_pps=None,
                db="driftsentry.db",
                webhook_url=None,
                syslog=False,
                json_stdout=False,
                always_notify=False,
                authorized=True,
                compare_to=None,
                baseline=None,
                debounce=1,
                verbose=verbose,
            )
            cmd_scan(scan_args)

        elif cmd in ("history", "h", "hist"):
            host_filter = args_list[0] if args_list else None
            hist_args = argparse.Namespace(
                host=host_filter,
                limit=20,
                db="driftsentry.db",
            )
            cmd_history(hist_args)

        elif cmd in ("diff", "d"):
            if len(args_list) < 2:
                console.print("[bold red]Usage:[/bold red] diff <from_scan_id> <to_scan_id>  (e.g.: [bold white]diff 9 10[/bold white])")
                continue
            try:
                from_id = int(args_list[0])
                to_id = int(args_list[1])
            except ValueError:
                console.print("[bold red]Scan IDs must be numbers.[/bold red]")
                continue
            diff_args = argparse.Namespace(
                from_id=from_id,
                to_id=to_id,
                db="driftsentry.db",
                json_out=False,
            )
            cmd_diff(diff_args)

        elif cmd in ("baselines", "b", "base"):
            base_args = argparse.Namespace(db="driftsentry.db")
            cmd_baselines(base_args)

        elif cmd in ("tag", "t"):
            if len(args_list) < 2:
                console.print("[bold red]Usage:[/bold red] tag <scan_id> <name>  (e.g.: [bold white]tag 10 golden[/bold white])")
                continue
            try:
                sid = int(args_list[0])
            except ValueError:
                console.print("[bold red]Scan ID must be a number.[/bold red]")
                continue
            name = args_list[1]
            tag_args = argparse.Namespace(scan_id=sid, name=name, db="driftsentry.db")
            cmd_tag(tag_args)

        elif cmd in ("prune", "p"):
            keep_days = int(args_list[0]) if args_list else 90
            prune_args = argparse.Namespace(keep_days=keep_days, db="driftsentry.db")
            cmd_prune(prune_args)

        elif cmd in ("report", "rep", "r"):
            if not args_list:
                console.print("[bold red]Usage:[/bold red] report <scan_id> [format]  (e.g.: [bold white]report 1[/bold white] or [bold white]report 1 html[/bold white])")
                continue
            try:
                sid = int(args_list[0])
            except ValueError:
                console.print("[bold red]Scan ID must be a number.[/bold red]")
                continue
            fmt = args_list[1] if len(args_list) > 1 else "all"
            rep_args = argparse.Namespace(
                scan_id=sid,
                format=fmt,
                output_dir="reports",
                db="driftsentry.db",
            )
            cmd_report(rep_args)

        elif cmd == "target":
            if args_list:
                current_target = args_list[0]
                console.print(f"Target set to: [bold cyan]{current_target}[/bold cyan]")
            else:
                console.print(f"Current target: [bold cyan]{current_target}[/bold cyan]")

        else:
            console.print(f"[bold red]Unknown command:[/bold red] '{cmd}'. Type [bold white]'help'[/bold white] for command list.")


def _print_console_help() -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        table = Table(title="DriftSentry Interactive Console Commands", show_header=True, header_style="bold cyan")
        table.add_column("Command", style="bold yellow", width=24)
        table.add_column("Short", style="bold green", width=8)
        table.add_column("Description", style="white")
        table.add_column("Example", style="dim")
        table.add_row("scan [ip] [ports] [-v]", "s", "Run port scan & detect drift", "scan 127.0.0.1 top100 -v")
        table.add_row("nmap [ip] [ports]", "nm", "Run integrated Nmap scan (-sV)", "nmap 192.168.1.10 21-100")
        table.add_row("report <id> [fmt]", "rep", "Generate audit report (html/md/csv/all)", "report 1 all")
        table.add_row("history [ip]", "h", "Show past scan timeline", "history")
        table.add_row("diff <id1> <id2>", "d", "Compare any two past scans", "diff 9 10")
        table.add_row("baselines", "b", "List tagged baseline scans", "baselines")
        table.add_row("tag <id> <name>", "t", "Label a scan as baseline", "tag 10 pre-deploy")
        table.add_row("target <ip>", "—", "Set default target IP/CIDR", "target 192.168.1.1")
        table.add_row("prune [days]", "p", "Delete old scans & shrink DB", "prune 30")
        table.add_row("clear", "cls", "Clear screen and redraw banner", "clear")
        table.add_row("exit / quit", "q", "Exit interactive console", "exit")
        console.print(table)
    except Exception:
        print("""
Commands:
  scan [ip] [ports] [-v]   (s)  - Run scan & detect drift (e.g. scan 127.0.0.1)
  nmap [ip] [ports]        (nm) - Run integrated Nmap scan (-sV) (e.g. nmap 192.168.1.1 21-100)
  report <id> [fmt]        (rep) - Generate audit report (e.g. report 1 all)
  history                  (h)  - Show scan history
  diff <id1> <id2>         (d)  - Compare two past scans (e.g. diff 9 10)
  baselines                (b)  - List tagged baselines
  tag <id> <name>          (t)  - Tag baseline (e.g. tag 10 golden)
  target <ip>                   - Set default target IP
  clear                         - Clear screen
  exit / quit              (q)  - Exit console
""")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    # If launched with no arguments, open the interactive console directly!
    if len(sys.argv) == 1:
        run_interactive_console()
        return

    if "-h" in sys.argv or "--help" in sys.argv:
        print_banner()

    parser = _build_parser()
    args = parser.parse_args()
    _setup_logging(args.log_level)

    dispatch_map = {
        "init":            cmd_init, "i": cmd_init,
        "scan":            cmd_scan, "s": cmd_scan,
        "nmap":            cmd_nmap, "nm": cmd_nmap,
        "report":          cmd_report, "rep": cmd_report, "r": cmd_report,
        "diff":            cmd_diff, "d": cmd_diff,
        "history":         cmd_history, "h": cmd_history, "hist": cmd_history,
        "tag":             cmd_tag, "t": cmd_tag,
        "baselines":       cmd_baselines, "b": cmd_baselines, "base": cmd_baselines,
        "watch":           cmd_watch, "w": cmd_watch,
        "prune":           cmd_prune, "p": cmd_prune,
        "install-service": cmd_install_service, "svc": cmd_install_service,
        "console":         cmd_console, "c": cmd_console, "shell": cmd_console,
    }

    handler = dispatch_map.get(args.command)
    if not handler:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()


