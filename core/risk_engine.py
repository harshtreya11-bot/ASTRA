"""
core/risk_engine.py - Risk scoring and prioritization
"""

from typing import List, Dict
import config


def score_to_level(score: int) -> str:
    """Convert numeric risk score to label."""
    for level, (lo, hi) in config.RISK_LEVELS.items():
        if lo <= score <= hi:
            return level
    return "LOW"


def level_to_score(level: str) -> int:
    """Return midpoint score for a level label."""
    ranges = {
        "CRITICAL": 90,
        "HIGH": 70,
        "MEDIUM": 45,
        "LOW": 15,
    }
    return ranges.get(level.upper(), 15)


def recalculate_alert_risk(alert: Dict) -> Dict:
    """
    Recalculate risk_level from risk_score.
    Useful after aggregation adjustments.
    """
    alert["risk_level"] = score_to_level(alert.get("risk_score", 0))
    return alert


def elevate_ip_risk(alerts: List[Dict]) -> List[Dict]:
    """
    If the same IP appears in 3+ alerts of HIGH or CRITICAL severity,
    elevate all alerts from that IP one level.
    """
    from collections import Counter

    ip_counts = Counter(
        a["source_ip"]
        for a in alerts
        if a.get("risk_level") in ("HIGH", "CRITICAL")
    )
    elevated_ips = {ip for ip, cnt in ip_counts.items() if cnt >= 3}

    level_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for alert in alerts:
        if alert["source_ip"] in elevated_ips:
            current = alert.get("risk_level", "LOW")
            idx = level_order.index(current)
            if idx < len(level_order) - 1:
                alert["risk_level"] = level_order[idx + 1]
                alert["risk_score"] = min(100, alert.get("risk_score", 0) + 10)

    return alerts


def compute_ip_risk_score(ip_alerts: List[Dict]) -> int:
    """
    Compute an aggregate risk score for a source IP based on its alerts.
    """
    if not ip_alerts:
        return 0
    scores = [a.get("risk_score", 0) for a in ip_alerts]
    max_score = max(scores)
    # Bonus for variety of attack types
    attack_types = {a.get("attack_type") for a in ip_alerts}
    variety_bonus = min(20, len(attack_types) * 5)
    return min(100, max_score + variety_bonus)


def get_risk_color(level: str) -> str:
    """Return CSS-friendly hex color for a risk level."""
    colors = {
        "CRITICAL": "#ff4d4d",
        "HIGH": "#ff9900",
        "MEDIUM": "#f0c040",
        "LOW": "#4caf50",
    }
    return colors.get(level.upper(), "#888888")


def get_risk_badge(level: str) -> str:
    """Return an emoji badge for a risk level (for Streamlit display)."""
    badges = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🟢",
    }
    return badges.get(level.upper(), "⚪")
