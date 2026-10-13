# 🛡️ DriftSentry — Port Scanner with Attack-Surface Drift Detection

[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Debian%20%7C%20Ubuntu-blue.svg)](https://www.kali.org/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-brightgreen.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-24%2F24%20Passing-success.svg)](tests/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-AsyncIO%20%2B%20SQLite%20WAL-orange.svg)](driftsentry/)

> **DriftSentry** is an autonomous CLI reconnaissance and security auditing application that scans network targets, records historical snapshots in SQLite, and automatically computes **temporal attack-surface drift** between consecutive runs.

Instead of only reporting *"what ports are open right now,"* DriftSentry answers:
**"What changed, what new services appeared, which banners were modified, and when?"**

---

## 📌 Executive Summary & Problem Statement

Point-in-time network scanners (Nmap, Masscan, RustScan) excel at discovering active listening ports today, but real-world security incidents typically originate from **unauthorized infrastructure changes**:
- A developer temporarily spins up an unauthenticated debug daemon (Redis, FTP, HTTP) and forgets to terminate it.
- A firewall rule or security group gets loosened during a production deployment.
- A service is upgraded or downgraded, introducing an exploitable version banner.

Catching these risks requires either manual log diffing (error-prone and rarely done) or an automated sentinel. **DriftSentry bridges this gap** by turning individual scan snapshots into a searchable, temporal timeline with automated delta alerting.

---

## ✨ Key Features

- **💻 Interactive CLI Application:**
  - Launch `driftsentry` to enter a persistent interactive command shell.
  - Run scans (`scan`, `s`), integrated Nmap scans (`nmap`, `nm`), ad-hoc diffs (`diff`, `d`), reports (`report`), baseline labeling (`tag`), and history timelines without retyping full terminal commands.
- **⚡ Native Nmap Engine Integration:**
  - Integrated execution of native `/usr/bin/nmap` with service version detection (`-sV -Pn -T4`).
  - High-speed XML stream parser (`-oX -`) extracting IP, port, service name, vendor, version banner, and round-trip latency directly into SQLite.
- **🎯 Multi-Protocol Asynchronous Scanner:**
  - Unprivileged TCP-connect scanner (`asyncio.open_connection`) requiring zero root privileges.
  - Opt-in TCP-SYN stealth probing and UDP probing.
  - Semaphore-bounded concurrency with token-bucket rate limiting.
- **🔄 Temporal Attack-Surface Drift Engine:**
  - Detects `new_port`, `closed_port`, `banner_changed`, `host_up`, and `host_down`.
  - Configurable debounce mechanism to filter out transient packet drops.
- **📊 3-Report Security Audit System:**
  - **HTML Visual Dashboard:** Self-contained, responsive report with executive stat cards, open ports table, severity badges, and print-to-PDF ready CSS.
  - **Technical Markdown Report:** Clean GitHub-flavored Markdown for bug bounty logs, documentation, and academic presentation submissions.
  - **Analyst CSV Spreadsheet:** RFC 4180 CSV export formatted for Microsoft Excel, LibreOffice Calc, or SIEM ingestion.
- **💾 Local SQLite WAL Persistence:**
  - Stores scans, hosts, results, baseline tags, and drift events in SQLite with WAL mode (`Write-Ahead Logging`) to prevent disk stalls during large scans.
- **🔔 Pluggable Alert Sinks:**
  - Formatted terminal table output via Rich, machine-readable JSON stdout, local syslog, and webhook integration for Slack/Discord/SIEM.
- **⏱️ Systemd Daemon & Timer Integration:**
  - Built-in `install-service` generator to produce systemd unit files (`driftsentry.service` and `driftsentry.timer`) for unattended cron monitoring.

---

## 🏗️ Architecture & Workflow

```text
       ┌────────────────────────┐
       │     Target Network     │
       └───────────┬────────────┘
                   │
         [ Active Reconnaissance ]
         ├── TCP-Connect (AsyncIO)
         └── Native Nmap (-sV -Pn)
                   │
                   ▼
       ┌────────────────────────┐
       │   Port & Service Probe │
       │  (Banner / Version ID) │
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │ SQLite Persistence Engine│
       │ (Scans, Results, Hosts) │
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │   Diff & Drift Engine  │ ◄── Prior Scan / Baseline
       │ (Temporal Delta Calc)  │
       └───────────┬────────────┘
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
┌──────────────────┐ ┌──────────────────────────┐
│  Alert Sinks     │ │  3-Report Generation     │
│  - Rich Console  │ │  - Executive HTML        │
│  - Webhook/Slack │ │  - Technical Markdown    │
│  - Syslog / JSON │ │  - Analyst CSV Export    │
└──────────────────┘ └──────────────────────────┘
```

---

## 🚀 Installation & Setup

### Requirements
- **Python 3.11+**
- **Kali Linux**, Debian, Ubuntu, or Windows
- **Nmap** (pre-installed on Kali Linux; on Debian/Ubuntu: `sudo apt install nmap`)

### 1. Clone the Repository
```bash
git clone https://github.com/varadanvinodshanbhag-netizen/Drift-Sentry-Port-Scanner.git
cd Drift-Sentry-Port-Scanner
```

### 2. Install Dependencies
```bash
# Option A: Install in editable development mode (Recommended)
pip install -e .

# Option B: Standard requirements install
pip install -r requirements.txt
```

### 3. Verify Installation
```bash
# Run the test suite (24 unit tests)
pytest tests/ -v

# Check CLI binary
driftsentry --help
```

---

## 🖥️ Usage Guide

### Mode 1: Interactive CLI Console (Recommended)
Launch the interactive shell to stay inside the application:
```bash
driftsentry
```
```text
  ____       _  __ _   ____             _              
 |  _ \ _ __(_)/ _| |_/ ___|  ___ _ __ | |_ _ __ _   _ 
 | | | | '__| | |_| __\___ \ / _ \ '_ \| __| '__| | | |
 | |_| | |  | |  _| |_ ___) |  __/ | | | |_| |  | |_| |
 |____/|_|  |_|_|  \__|____/ \___|_| |_|\__|_|   \__, |
                                                 |___/ 
🛡️  PORT SCANNER WITH ATTACK-SURFACE DRIFT DETECTION | v0.3.0

Interactive Mode Active. Type 'help' for command list, 'exit' or 'q' to quit.

driftsentry (127.0.0.1) > scan 192.168.1.100 21-100
driftsentry (192.168.1.100) > scan 192.168.1.100 top100
driftsentry (192.168.1.100) > history
driftsentry (192.168.1.100) > diff 1 2
driftsentry (192.168.1.100) > tag 1 golden-baseline
driftsentry (192.168.1.100) > report 1 all
driftsentry (192.168.1.100) > exit
```

### Mode 2: Standalone CLI Commands (Bash / Scripts)

#### 1. Run Port Scan & Drift Detection
```bash
# Standard port scan against target (-a confirms authorized testing)
driftsentry scan -t 192.168.1.100 -p 21-445 -a

# Fast top-100 ports scan
driftsentry scan -t 192.168.1.100 -p top100 -a
```

#### 2. Run High-Speed Asynchronous TCP Scan
```bash
driftsentry scan -t 192.168.1.100 -p top1000 --concurrency 500 -a
```

#### 3. Generate Security Audit Reports
```bash
# Generate all 3 report formats (HTML + Markdown + CSV)
driftsentry report 1

# Generate standalone visual HTML report
driftsentry report 1 -f html

# Generate GitHub-Flavored Markdown report
driftsentry report 1 -f md

# Generate CSV spreadsheet export
driftsentry report 1 -f csv
```

#### 4. Historical Inspection & Ad-hoc Diffing
```bash
# View timeline of past scans
driftsentry history

# Compare two arbitrary scans
driftsentry diff --from 1 --to 2

# Tag a baseline snapshot
driftsentry tag --scan-id 1 --name "pre-deploy"

# Diff against a named baseline
driftsentry scan -t 192.168.1.100 -b "pre-deploy" -a
```

---

## 📊 Report Formats Showcase

Reports are saved to `reports/` with automatic timestamps and target indicators:

1. **HTML Dashboard (`.html`):**
   - High-contrast responsive layout compliant with modern accessibility standards (≥4.5:1 contrast).
   - Executive metric cards (Total Probes, Open Ports, Drift Alerts).
   - Color-coded badges: 🔴 `CRITICAL`, 🟡 `WARNING`, ℹ️ `INFO`.
   - Discovered service tables and latency metrics.
   - Built-in `@media print` CSS for **instant Print-to-PDF** export in any browser (`Ctrl+P`).
2. **Markdown Audit (`.md`):**
   - Ready to drop into technical documentation, Jira tickets, or academic project portfolios.
3. **CSV Export (`.csv`):**
   - Formatted for Excel, LibreOffice, Pandas, and SIEM data pipelines.

---

## 📁 Project Structure

```text
driftsentry/
├── driftsentry/
│   ├── alerting/
│   │   └── sinks.py          # Rich stdout, webhook, syslog, JSON sinks
│   ├── diff/
│   │   └── engine.py         # Temporal delta & drift calculation
│   ├── report/
│   │   ├── __init__.py
│   │   └── generator.py      # 3-report engine (HTML, Markdown, CSV)
│   ├── scanner/
│   │   ├── engine.py         # Async orchestrator & protocol router
│   │   ├── fingerprint.py    # Service banner regex heuristics
│   │   ├── nmap.py           # Native Nmap runner & XML parser
│   │   ├── tcp_connect.py    # Unprivileged asyncio TCP prober
│   │   ├── tcp_syn.py        # Raw SYN scanner (CAP_NET_RAW)
│   │   └── udp.py            # UDP probe engine
│   ├── store/
│   │   └── db.py             # SQLite WAL database & schema queries
│   ├── cli.py                # Command-line interface & interactive shell
│   └── config.py             # Configuration loader & top ports
├── tests/
│   ├── test_diff_engine.py   # Unit tests for drift calculations
│   ├── test_nmap_parser.py   # Unit tests for Nmap XML output
│   └── test_reports.py       # Unit tests for HTML, MD, and CSV reports
├── config.example.yaml       # Template configuration
├── pyproject.toml            # Package specification & entrypoint
├── requirements.txt          # Python dependency list
├── LICENSE                   # MIT Open Source License
└── README.md                 # Complete project documentation
```

---

## 🧪 Automated Testing

DriftSentry follows test-driven development (TDD). Run the automated test suite with:

```bash
pytest tests/ -v
```

Expected result:
```text
tests/test_cli_edge_cases.py::test_parse_ports_valid_ranges_and_presets PASSED
tests/test_cli_edge_cases.py::test_parse_ports_invalid_bounds_and_format PASSED
tests/test_cli_edge_cases.py::test_parse_targets_edge_cases PASSED
tests/test_cli_edge_cases.py::test_compute_drift_empty_scans PASSED
tests/test_cli_edge_cases.py::test_cmd_diff_nonexistent_scans PASSED
tests/test_cli_edge_cases.py::test_nmap_scan_missing_binary PASSED
tests/test_cli_edge_cases.py::test_db_baseline_nonexistent_tag PASSED
tests/test_cli_edge_cases.py::test_cmd_scan_unauthorized_exit PASSED
tests/test_cli_edge_cases.py::test_export_scan_report_nonexistent_scan PASSED
tests/test_diff_engine.py::test_no_events_when_identical PASSED
tests/test_diff_engine.py::test_new_port_detected PASSED
tests/test_diff_engine.py::test_closed_port_detected PASSED
tests/test_diff_engine.py::test_banner_change_detected PASSED
tests/test_diff_engine.py::test_no_banner_change_when_same PASSED
tests/test_diff_engine.py::test_host_up_detected PASSED
tests/test_diff_engine.py::test_host_down_detected PASSED
tests/test_diff_engine.py::test_first_scan_no_prior PASSED
tests/test_diff_engine.py::test_closed_state_not_reported_as_new PASSED
tests/test_diff_engine.py::test_multiple_hosts PASSED
tests/test_nmap_parser.py::test_parse_nmap_xml PASSED
tests/test_reports.py::test_generate_markdown_report PASSED
tests/test_reports.py::test_generate_html_report PASSED
tests/test_reports.py::test_generate_csv_report PASSED
tests/test_reports.py::test_export_scan_report PASSED

======================== 24 passed in 0.30s ========================
```

---

## ⚖️ Legal & Ethical Notice

DriftSentry actively transmits network packets to target endpoints. Only scan networks and hosts you **own** or have **explicit written authorization** to test (compliance with the Computer Fraud and Abuse Act - CFAA, UK Computer Misuse Act, and relevant local legislation). The `--authorized` (`-a`) flag confirms active testing permission.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
