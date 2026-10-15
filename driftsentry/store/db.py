"""
store/db.py — SQLite backend for DriftSentry.

Responsibilities:
  - Open / create the database file.
  - Apply the schema (idempotent, using CREATE TABLE IF NOT EXISTS).
  - Provide low-level CRUD helpers used by the scanner and diff engine.

All writes go through sqlite3 connection objects that the caller must obtain
via get_connection().  We intentionally do not keep a module-level singleton
so that the tool stays safe when used in tests or future async contexts.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Schema DDL (verbatim from PRD §10)
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    target_spec   TEXT NOT NULL,
    port_spec     TEXT NOT NULL,
    protocol      TEXT NOT NULL,
    config_hash   TEXT,
    baseline_tag  TEXT            -- optional human-readable label, e.g. "pre-deploy"
);

CREATE TABLE IF NOT EXISTS hosts (
    host_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address    TEXT NOT NULL UNIQUE,
    hostname      TEXT
);

CREATE TABLE IF NOT EXISTS results (
    result_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans(scan_id),
    host_id           INTEGER NOT NULL REFERENCES hosts(host_id),
    port              INTEGER NOT NULL,
    protocol          TEXT NOT NULL,
    state             TEXT NOT NULL,
    banner            TEXT,
    service_guess     TEXT,
    response_time_ms  INTEGER,
    UNIQUE(scan_id, host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS drift_events (
    event_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(scan_id),
    prior_scan_id  INTEGER REFERENCES scans(scan_id),
    host_id        INTEGER NOT NULL REFERENCES hosts(host_id),
    port           INTEGER,
    event_type     TEXT NOT NULL,
    detail         TEXT,
    detected_at    TEXT NOT NULL,
    severity       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
CREATE INDEX IF NOT EXISTS idx_drift_scan   ON drift_events(scan_id);
"""

# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def get_connection(db_path: str | Path) -> sqlite3.Connection:
    """Open (or create) the SQLite DB at *db_path* and return a connection.

    row_factory is set to sqlite3.Row so callers can access columns by name.
    Foreign-key enforcement is enabled per connection.
    WAL mode and NORMAL sync prevent event loop disk stalls during large scans.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    except Exception:
        pass
    return conn


def init_db(db_path: str | Path) -> sqlite3.Connection:
    """Create the DB file (if needed) and apply the schema. Returns connection.

    Also runs non-destructive migrations for existing databases so that
    upgrading from v0.1 works without recreating the DB.
    """
    conn = get_connection(db_path)
    conn.executescript(_SCHEMA)
    _migrate(conn)
    conn.commit()
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Apply incremental, idempotent schema migrations."""
    # v0.3: add baseline_tag column if missing
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(scans)").fetchall()]
    if "baseline_tag" not in cols:
        conn.execute("ALTER TABLE scans ADD COLUMN baseline_tag TEXT")



# ---------------------------------------------------------------------------
# Scan lifecycle
# ---------------------------------------------------------------------------

def start_scan(conn: sqlite3.Connection, target_spec: str, port_spec: str,
               protocol: str, config_hash: Optional[str] = None) -> int:
    """Insert a new scan row with started_at = now(UTC). Returns scan_id."""
    now = _utcnow()
    cur = conn.execute(
        "INSERT INTO scans (started_at, target_spec, port_spec, protocol, config_hash) "
        "VALUES (?, ?, ?, ?, ?)",
        (now, target_spec, port_spec, protocol, config_hash),
    )
    conn.commit()
    return cur.lastrowid  # type: ignore[return-value]


def finish_scan(conn: sqlite3.Connection, scan_id: int) -> None:
    """Set finished_at for the given scan_id to now(UTC)."""
    conn.execute(
        "UPDATE scans SET finished_at = ? WHERE scan_id = ?",
        (_utcnow(), scan_id),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Host helpers
# ---------------------------------------------------------------------------

def upsert_host(conn: sqlite3.Connection, ip_address: str,
                hostname: Optional[str] = None) -> int:
    """Insert the host if not present; return host_id either way."""
    conn.execute(
        "INSERT OR IGNORE INTO hosts (ip_address, hostname) VALUES (?, ?)",
        (ip_address, hostname),
    )
    if hostname:
        conn.execute(
            "UPDATE hosts SET hostname = ? WHERE ip_address = ?",
            (hostname, ip_address),
        )
    row = conn.execute(
        "SELECT host_id FROM hosts WHERE ip_address = ?", (ip_address,)
    ).fetchone()
    return row["host_id"]


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------

def save_result(
    conn: sqlite3.Connection,
    scan_id: int,
    host_id: int,
    port: int,
    protocol: str,
    state: str,
    banner: Optional[str] = None,
    service_guess: Optional[str] = None,
    response_time_ms: Optional[int] = None,
) -> None:
    """Persist one port-probe result. Silently replaces duplicates (same scan/host/port/proto)."""
    conn.execute(
        """INSERT OR REPLACE INTO results
           (scan_id, host_id, port, protocol, state, banner, service_guess, response_time_ms)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, host_id, port, protocol, state, banner, service_guess, response_time_ms),
    )


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_scan(conn: sqlite3.Connection, scan_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()


def get_prior_scan_id(conn: sqlite3.Connection, current_scan_id: int,
                      target_spec: str) -> Optional[int]:
    """Return the most recent scan_id for *target_spec* before *current_scan_id*, or None."""
    row = conn.execute(
        """SELECT scan_id FROM scans
           WHERE target_spec = ? AND scan_id < ?
           ORDER BY scan_id DESC LIMIT 1""",
        (target_spec, current_scan_id),
    ).fetchone()
    return row["scan_id"] if row else None


def get_latest_scan_id(conn: sqlite3.Connection,
                       target_spec: Optional[str] = None) -> Optional[int]:
    """Return the most recent scan_id (optionally filtered by target_spec), or None."""
    if target_spec:
        row = conn.execute(
            """SELECT scan_id FROM scans
               WHERE target_spec = ?
               ORDER BY scan_id DESC LIMIT 1""",
            (target_spec,),
        ).fetchone()
        if row:
            return row["scan_id"]
    row = conn.execute("SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT 1").fetchone()
    return row["scan_id"] if row else None


def get_results_for_scan(conn: sqlite3.Connection,
                         scan_id: int) -> list[sqlite3.Row]:
    """Return all port results for a scan, joined with host IP."""
    return conn.execute(
        """SELECT r.*, h.ip_address, h.hostname
           FROM results r JOIN hosts h USING (host_id)
           WHERE r.scan_id = ?""",
        (scan_id,),
    ).fetchall()


def save_drift_event(
    conn: sqlite3.Connection,
    scan_id: int,
    prior_scan_id: Optional[int],
    host_id: int,
    port: Optional[int],
    event_type: str,
    detail: Optional[str],
    severity: str,
) -> None:
    conn.execute(
        """INSERT INTO drift_events
           (scan_id, prior_scan_id, host_id, port, event_type, detail, detected_at, severity)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, prior_scan_id, host_id, port, event_type, detail, _utcnow(), severity),
    )


def get_drift_events(conn: sqlite3.Connection, scan_id: int) -> list[sqlite3.Row]:
    """Retrieve all drift events detected during the given scan."""
    return conn.execute(
        """SELECT d.*, h.ip_address, h.hostname
           FROM drift_events d
           LEFT JOIN hosts h USING (host_id)
           WHERE d.scan_id = ?
           ORDER BY d.event_id ASC""",
        (scan_id,),
    ).fetchall()


def get_scan_history(conn: sqlite3.Connection,
                     ip_address: Optional[str] = None,
                     limit: int = 20) -> list[sqlite3.Row]:
    if ip_address:
        return conn.execute(
            """SELECT s.*, GROUP_CONCAT(DISTINCT r.state) as states
               FROM scans s
               JOIN results r USING (scan_id)
               JOIN hosts h USING (host_id)
               WHERE h.ip_address = ?
               GROUP BY s.scan_id
               ORDER BY s.scan_id DESC LIMIT ?""",
            (ip_address, limit),
        ).fetchall()
    return conn.execute(
        "SELECT * FROM scans ORDER BY scan_id DESC LIMIT ?", (limit,)
    ).fetchall()


def set_baseline_tag(conn: sqlite3.Connection, scan_id: int, tag: str) -> bool:
    """Apply a baseline tag to a scan. Returns True if the scan was found."""
    cur = conn.execute(
        "UPDATE scans SET baseline_tag = ? WHERE scan_id = ?", (tag, scan_id)
    )
    conn.commit()
    return cur.rowcount > 0


def get_baseline_scan_id(conn: sqlite3.Connection,
                         tag: str,
                         target_spec: Optional[str] = None) -> Optional[int]:
    """Find the most recent scan_id with the given baseline tag.

    If target_spec is provided, only looks at scans for that target.
    """
    if target_spec:
        row = conn.execute(
            """SELECT scan_id FROM scans
               WHERE baseline_tag = ? AND target_spec = ?
               ORDER BY scan_id DESC LIMIT 1""",
            (tag, target_spec),
        ).fetchone()
    else:
        row = conn.execute(
            """SELECT scan_id FROM scans
               WHERE baseline_tag = ?
               ORDER BY scan_id DESC LIMIT 1""",
            (tag,),
        ).fetchone()
    return row["scan_id"] if row else None


def list_baselines(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return all scans that have a baseline tag."""
    return conn.execute(
        """SELECT scan_id, baseline_tag, target_spec, started_at
           FROM scans WHERE baseline_tag IS NOT NULL
           ORDER BY scan_id DESC"""
    ).fetchall()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

