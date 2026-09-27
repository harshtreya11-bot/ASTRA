"""
core/database.py - SQLite persistence layer
"""

import json
import logging
import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Optional

import config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT,
    source_ip TEXT,
    method TEXT,
    endpoint TEXT,
    query_string TEXT,
    parameters TEXT,          -- JSON
    status_code INTEGER,
    response_size INTEGER,
    user_agent TEXT,
    referer TEXT,
    raw_request TEXT,
    normalized_request TEXT,
    raw_path TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT,
    source_ip TEXT,
    attack_type TEXT,
    risk_level TEXT,
    risk_score INTEGER,
    endpoint TEXT,
    parameter TEXT,
    evidence TEXT,
    rule_id TEXT,
    rule_description TEXT,
    confidence INTEGER,
    raw_request TEXT,
    method TEXT,
    status_code INTEGER,
    user_agent TEXT,
    recommended_action TEXT,
    status TEXT DEFAULT 'Open',
    event_id TEXT,
    explanation TEXT
);

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    source_ip TEXT,
    first_seen TEXT,
    last_seen TEXT,
    duration_seconds INTEGER,
    total_alerts INTEGER,
    attack_types TEXT,        -- JSON
    affected_endpoints TEXT,  -- JSON
    risk_score INTEGER,
    risk_level TEXT,
    alert_ids TEXT,           -- JSON
    summary TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(attack_type);
CREATE INDEX IF NOT EXISTS idx_alerts_risk ON alerts(risk_level);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
"""


def _ts(dt) -> str:
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt) if dt else ""


def _from_ts(s: str) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------

class Database:
    """Thin SQLite wrapper for events, alerts, and campaigns."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or config.DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        logger.info("Database initialized at %s", self.db_path)

    # ------------------------------------------------------------------ #
    #  Events
    # ------------------------------------------------------------------ #

    def insert_events(self, events: List[Dict]) -> int:
        sql = """
        INSERT OR IGNORE INTO events
            (event_id, timestamp, source_ip, method, endpoint, query_string,
             parameters, status_code, response_size, user_agent, referer,
             raw_request, normalized_request, raw_path)
        VALUES
            (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """
        rows = [
            (
                e["event_id"],
                _ts(e.get("timestamp")),
                e.get("source_ip", ""),
                e.get("method", ""),
                e.get("endpoint", ""),
                e.get("query_string", ""),
                json.dumps(e.get("parameters", {})),
                e.get("status_code", 0),
                e.get("response_size", 0),
                e.get("user_agent", ""),
                e.get("referer", ""),
                e.get("raw_request", ""),
                e.get("normalized_request", ""),
                e.get("raw_path", ""),
            )
            for e in events
        ]
        with self._connect() as conn:
            conn.executemany(sql, rows)
        logger.info("Inserted %d events", len(events))
        return len(events)

    def get_events(self, limit: int = 10000) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def count_events(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # ------------------------------------------------------------------ #
    #  Alerts
    # ------------------------------------------------------------------ #

    def insert_alerts(self, alerts: List[Dict]) -> int:
        sql = """
        INSERT OR IGNORE INTO alerts
            (alert_id, timestamp, source_ip, attack_type, risk_level, risk_score,
             endpoint, parameter, evidence, rule_id, rule_description, confidence,
             raw_request, method, status_code, user_agent, recommended_action,
             status, event_id, explanation)
        VALUES
            (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """
        rows = [
            (
                a["alert_id"],
                _ts(a.get("timestamp")),
                a.get("source_ip", ""),
                a.get("attack_type", ""),
                a.get("risk_level", ""),
                a.get("risk_score", 0),
                a.get("endpoint", ""),
                a.get("parameter", ""),
                a.get("evidence", ""),
                a.get("rule_id", ""),
                a.get("rule_description", ""),
                a.get("confidence", 0),
                a.get("raw_request", ""),
                a.get("method", ""),
                a.get("status_code", 0),
                a.get("user_agent", ""),
                a.get("recommended_action", ""),
                a.get("status", "Open"),
                a.get("event_id", ""),
                a.get("explanation", ""),
            )
            for a in alerts
        ]
        with self._connect() as conn:
            conn.executemany(sql, rows)
        logger.info("Inserted %d alerts", len(alerts))
        return len(alerts)

    def get_alerts(self, limit: int = 5000) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_alerts_by_ip(self, ip: str) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE source_ip=? ORDER BY timestamp",
                (ip,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_alerts_by_endpoint(self, endpoint: str) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE endpoint=? ORDER BY timestamp",
                (endpoint,),
            ).fetchall()
        return [dict(r) for r in rows]

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        with self._connect() as conn:
            conn.execute(
                "UPDATE alerts SET status=? WHERE alert_id=?", (status, alert_id)
            )
        return True

    def count_alerts(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    # ------------------------------------------------------------------ #
    #  Campaigns
    # ------------------------------------------------------------------ #

    def insert_campaigns(self, campaigns: List[Dict]) -> int:
        sql = """
        INSERT OR IGNORE INTO campaigns
            (campaign_id, source_ip, first_seen, last_seen, duration_seconds,
             total_alerts, attack_types, affected_endpoints, risk_score, risk_level,
             alert_ids, summary)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """
        rows = [
            (
                c["campaign_id"],
                c.get("source_ip", ""),
                _ts(c.get("first_seen")),
                _ts(c.get("last_seen")),
                c.get("duration_seconds", 0),
                c.get("total_alerts", 0),
                json.dumps(c.get("attack_types", {})),
                json.dumps(c.get("affected_endpoints", [])),
                c.get("risk_score", 0),
                c.get("risk_level", ""),
                json.dumps(c.get("alert_ids", [])),
                c.get("summary", ""),
            )
            for c in campaigns
        ]
        with self._connect() as conn:
            conn.executemany(sql, rows)
        logger.info("Inserted %d campaigns", len(campaigns))
        return len(campaigns)

    def get_campaigns(self) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM campaigns ORDER BY risk_score DESC"
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["attack_types"] = json.loads(d.get("attack_types") or "{}")
            d["affected_endpoints"] = json.loads(d.get("affected_endpoints") or "[]")
            d["alert_ids"] = json.loads(d.get("alert_ids") or "[]")
            result.append(d)
        return result

    def count_campaigns(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]

    # ------------------------------------------------------------------ #
    #  Housekeeping
    # ------------------------------------------------------------------ #

    def clear_all(self):
        with self._connect() as conn:
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM campaigns")
        logger.info("Database cleared")


# Module-level singleton
_db: Optional[Database] = None


def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db
