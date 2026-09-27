"""
core/detector.py - Main attack detection engine
"""

import logging
import uuid
from typing import List, Dict, Optional
from datetime import datetime
from collections import defaultdict

from rules.attack_rules import ALL_RULES, RULE_MAP, AttackRule
import config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Detection targets: what text gets checked for each rule
# ---------------------------------------------------------------------------

def _build_detection_target(event: Dict) -> str:
    """
    Build the full text blob that rules run against.
    Uses normalized_request (decoded) for best coverage.
    Falls back to raw_request if normalization wasn't done.
    """
    parts = [
        event.get("normalized_request") or event.get("raw_request", ""),
        event.get("decoded_params") and str(event["decoded_params"]) or "",
        event.get("user_agent", ""),
    ]
    return " ".join(str(p) for p in parts if p)


# ---------------------------------------------------------------------------
# Alert builder
# ---------------------------------------------------------------------------

_SEVERITY_SCORES = {
    "CRITICAL": 90,
    "HIGH":     70,
    "MEDIUM":   45,
    "LOW":      20,
}


def _build_alert(event: Dict, rule: AttackRule, confidence: int, evidence: str) -> Dict:
    """Construct an alert dict from an event + matched rule."""
    base_score = _SEVERITY_SCORES.get(rule.severity, 45)
    # Adjust score by confidence
    risk_score = int(base_score * (confidence / 100))
    risk_score = max(0, min(100, risk_score))

    # Map score to level
    level = "LOW"
    for lvl, (lo, hi) in config.RISK_LEVELS.items():
        if lo <= risk_score <= hi:
            level = lvl
            break

    # Determine best suspect parameter
    suspect_param = _find_suspect_param(event, evidence)

    return {
        "alert_id": str(uuid.uuid4()),
        "timestamp": event.get("timestamp", datetime.utcnow()),
        "source_ip": event.get("source_ip", ""),
        "attack_type": rule.attack_type,
        "risk_level": level,
        "risk_score": risk_score,
        "endpoint": event.get("endpoint", ""),
        "parameter": suspect_param,
        "evidence": evidence,
        "rule_id": rule.rule_id,
        "rule_description": rule.description,
        "confidence": confidence,
        "raw_request": event.get("raw_request", ""),
        "method": event.get("method", ""),
        "status_code": event.get("status_code", 0),
        "user_agent": event.get("user_agent", ""),
        "recommended_action": rule.recommended_action,
        "status": "Open",           # Open | Investigating | Resolved
        "event_id": event.get("event_id", ""),
        "explanation": _build_explanation(rule, evidence, event),
    }


def _find_suspect_param(event: Dict, evidence: str) -> str:
    """Try to identify which parameter contains the suspicious content."""
    params = event.get("decoded_params") or event.get("parameters") or {}
    for k, v in params.items():
        v_str = str(v)
        if any(snippet.lower() in v_str.lower() for snippet in evidence.split("|")):
            return k
    # Fall back to query string
    return event.get("query_string", "")[:60] if event.get("query_string") else ""


def _build_explanation(rule: AttackRule, evidence: str, event: Dict) -> str:
    """Human-readable explanation of why the alert was raised."""
    explanations = {
        "SQL Injection": (
            f"The request contains a SQL pattern matched by rule {rule.rule_id} "
            f"({rule.description}). The evidence '{evidence[:80]}' suggests an attempt "
            "to manipulate the application's database query."
        ),
        "Cross-Site Scripting": (
            f"The request contains a cross-site scripting payload matched by rule {rule.rule_id} "
            f"({rule.description}). The evidence '{evidence[:80]}' suggests an attempt "
            "to inject executable scripts into the application."
        ),
        "Path Traversal": (
            f"The request contains directory traversal sequences matched by rule {rule.rule_id} "
            f"({rule.description}). The evidence '{evidence[:80]}' suggests an attempt "
            "to access files outside the intended directory."
        ),
        "Command Injection": (
            f"The request contains OS command injection patterns matched by rule {rule.rule_id} "
            f"({rule.description}). The evidence '{evidence[:80]}' suggests an attempt "
            "to execute arbitrary shell commands on the server."
        ),
        "Parameter Manipulation": (
            f"The request exhibits suspicious parameter patterns matched by rule {rule.rule_id} "
            f"({rule.description}). The evidence '{evidence[:80]}' may indicate an attempt "
            "to exploit parameter handling vulnerabilities."
        ),
        "Authentication Attack": (
            "Multiple failed authentication attempts have been detected from this source IP "
            "within the configured time window, suggesting a brute-force or credential "
            "stuffing attack."
        ),
    }
    return explanations.get(rule.attack_type, f"Suspicious pattern detected: {evidence[:80]}")


# ---------------------------------------------------------------------------
# Brute-force / Authentication Attack detection
# ---------------------------------------------------------------------------

def detect_auth_attacks(
    events: List[Dict],
    threshold: int = None,
    window_minutes: int = None,
) -> List[Dict]:
    """
    Detect repeated failed authentication from the same IP within a time window.
    Returns a list of alert dicts.
    """
    threshold = threshold or config.BRUTE_FORCE_THRESHOLD
    window_minutes = window_minutes or config.BRUTE_FORCE_WINDOW_MINUTES

    # Group failed logins by IP
    from datetime import timedelta

    failed: Dict[str, List[Dict]] = defaultdict(list)
    for ev in events:
        if ev.get("method") in ("POST", "GET") and ev.get("status_code") in (
            401, 403
        ):
            path = ev.get("endpoint", "").lower()
            if any(kw in path for kw in ("/login", "/auth", "/signin", "/account", "/wp-login")):
                failed[ev["source_ip"]].append(ev)

    alerts = []
    window = timedelta(minutes=window_minutes)

    for ip, evs in failed.items():
        # Sort by time
        evs_sorted = sorted(evs, key=lambda e: e["timestamp"])
        # Sliding window check
        generated_windows: set = set()
        for i, ev_start in enumerate(evs_sorted):
            window_evs = [
                e for e in evs_sorted[i:]
                if (e["timestamp"] - ev_start["timestamp"]) <= window
            ]
            if len(window_evs) >= threshold:
                key = (ip, ev_start["timestamp"].replace(second=0, microsecond=0))
                if key in generated_windows:
                    continue
                generated_windows.add(key)

                endpoints = list({e["endpoint"] for e in window_evs})
                evidence = (
                    f"Failed login attempts: {len(window_evs)} "
                    f"in {window_minutes} minutes | "
                    f"Endpoints: {', '.join(endpoints[:3])}"
                )
                confidence = min(100, 60 + len(window_evs) * 3)
                risk_score = min(100, 65 + len(window_evs))
                level = "HIGH"
                if risk_score >= 80:
                    level = "CRITICAL"

                alert = {
                    "alert_id": str(uuid.uuid4()),
                    "timestamp": ev_start["timestamp"],
                    "source_ip": ip,
                    "attack_type": "Authentication Attack",
                    "risk_level": level,
                    "risk_score": risk_score,
                    "endpoint": endpoints[0] if endpoints else "/login",
                    "parameter": "",
                    "evidence": evidence,
                    "rule_id": "AUTH-001",
                    "rule_description": "Brute-force / credential stuffing detection",
                    "confidence": confidence,
                    "raw_request": window_evs[0].get("raw_request", ""),
                    "method": "POST",
                    "status_code": 401,
                    "user_agent": window_evs[0].get("user_agent", ""),
                    "recommended_action": (
                        "1. Block or rate-limit this source IP.\n"
                        "2. Check if any authentication succeeded after failures.\n"
                        "3. Enable account lockout policy.\n"
                        "4. Review application logs around this time window."
                    ),
                    "status": "Open",
                    "event_id": window_evs[0].get("event_id", ""),
                    "explanation": (
                        f"Source IP {ip} produced {len(window_evs)} failed "
                        f"authentication requests within {window_minutes} minutes. "
                        "This pattern is consistent with a brute-force or credential "
                        "stuffing attack."
                    ),
                    "failed_count": len(window_evs),
                }
                alerts.append(alert)
                break  # one alert per IP per analysis run is enough

    return alerts


# ---------------------------------------------------------------------------
# Duplicate parameter detection
# ---------------------------------------------------------------------------

def detect_param_pollution(events: List[Dict]) -> List[Dict]:
    """Detect HTTP Parameter Pollution from duplicate params in events."""
    alerts = []
    for ev in events:
        dups = ev.get("duplicate_params", [])
        if len(dups) >= config.DUPLICATE_PARAM_THRESHOLD:
            evidence = f"Duplicate parameters: {', '.join(dups)}"
            alert = {
                "alert_id": str(uuid.uuid4()),
                "timestamp": ev.get("timestamp", datetime.utcnow()),
                "source_ip": ev.get("source_ip", ""),
                "attack_type": "Parameter Manipulation",
                "risk_level": "MEDIUM",
                "risk_score": 45,
                "endpoint": ev.get("endpoint", ""),
                "parameter": ", ".join(dups),
                "evidence": evidence,
                "rule_id": "PARAM-004",
                "rule_description": "HTTP Parameter Pollution (duplicate parameters)",
                "confidence": 65,
                "raw_request": ev.get("raw_request", ""),
                "method": ev.get("method", ""),
                "status_code": ev.get("status_code", 0),
                "user_agent": ev.get("user_agent", ""),
                "recommended_action": (
                    "1. Investigate why multiple same-named parameters are sent.\n"
                    "2. Check if application processes the duplicate in an insecure way."
                ),
                "status": "Open",
                "event_id": ev.get("event_id", ""),
                "explanation": (
                    f"The request contains {len(dups)} duplicate parameter(s) "
                    f"({', '.join(dups)}), which may indicate HTTP Parameter Pollution."
                ),
            }
            alerts.append(alert)
    return alerts


# ---------------------------------------------------------------------------
# Main detection function
# ---------------------------------------------------------------------------

def detect_attacks(
    events: List[Dict],
    enabled_rule_ids: Optional[set] = None,
    brute_threshold: int = None,
    brute_window: int = None,
) -> List[Dict]:
    """
    Run all detection rules against a list of normalized events.
    Returns a flat list of alert dicts.
    """
    alerts = []

    active_rules = [
        r for r in ALL_RULES
        if r.enabled and (enabled_rule_ids is None or r.rule_id in enabled_rule_ids)
    ]

    for event in events:
        target = _build_detection_target(event)

        for rule in active_rules:
            matched, confidence, evidence = rule.matches(target)
            if matched and confidence > 0:
                alert = _build_alert(event, rule, confidence, evidence)
                alerts.append(alert)

    # Authentication brute-force detection (time-window based)
    auth_alerts = detect_auth_attacks(events, brute_threshold, brute_window)
    alerts.extend(auth_alerts)

    # Parameter pollution
    param_alerts = detect_param_pollution(events)
    alerts.extend(param_alerts)

    # ML Anomaly detection
    from core.ml_engine import detect_anomalies_ml
    ml_alerts = detect_anomalies_ml(events)
    alerts.extend(ml_alerts)

    logger.info(
        "Detection complete: %d events → %d alerts", len(events), len(alerts)
    )
    return alerts
