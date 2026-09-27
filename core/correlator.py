"""
core/correlator.py - Event correlation and attack campaign grouping
"""

import uuid
import logging
from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Optional

import config
from core.risk_engine import compute_ip_risk_score, score_to_level

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Campaign dataclass (as dict for easy JSON / SQLite storage)
# ---------------------------------------------------------------------------

def _make_campaign(
    source_ip: str,
    alerts: List[Dict],
    window_minutes: int,
) -> Dict:
    if not alerts:
        return {}

    sorted_alerts = sorted(alerts, key=lambda a: a["timestamp"])
    first_seen = sorted_alerts[0]["timestamp"]
    last_seen = sorted_alerts[-1]["timestamp"]
    duration_sec = (last_seen - first_seen).total_seconds()

    attack_types = defaultdict(int)
    for a in alerts:
        attack_types[a["attack_type"]] += 1

    endpoints = list({a["endpoint"] for a in alerts})
    risk_score = compute_ip_risk_score(alerts)
    risk_level = score_to_level(risk_score)
    alert_ids = [a["alert_id"] for a in alerts]

    return {
        "campaign_id": f"CAMP-{str(uuid.uuid4())[:8].upper()}",
        "source_ip": source_ip,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration_seconds": int(duration_sec),
        "total_alerts": len(alerts),
        "attack_types": dict(attack_types),
        "affected_endpoints": endpoints,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "alert_ids": alert_ids,
        "summary": _build_campaign_summary(
            source_ip, alerts, attack_types, endpoints, duration_sec, risk_level
        ),
    }


def _build_campaign_summary(
    ip: str,
    alerts: List[Dict],
    attack_types: Dict,
    endpoints: List[str],
    duration_sec: float,
    risk_level: str,
) -> str:
    minutes = int(duration_sec // 60)
    secs = int(duration_sec % 60)
    duration_str = f"{minutes}m {secs}s" if minutes > 0 else f"{secs}s"
    at_summary = ", ".join(
        f"{at} ({cnt})" for at, cnt in sorted(attack_types.items(), key=lambda x: -x[1])
    )
    ep_summary = ", ".join(endpoints[:5])
    return (
        f"Source IP {ip} launched {len(alerts)} attacks over {duration_str}. "
        f"Attack types: {at_summary}. "
        f"Targeted endpoints: {ep_summary}. "
        f"Overall risk: {risk_level}."
    )


# ---------------------------------------------------------------------------
# Main correlator
# ---------------------------------------------------------------------------

def correlate_alerts(
    alerts: List[Dict],
    window_minutes: Optional[int] = None,
    min_alerts: Optional[int] = None,
) -> List[Dict]:
    """
    Group alerts into attack campaigns.
    An IP with >= min_alerts alerts within window_minutes forms a campaign.

    Returns list of campaign dicts.
    """
    window_minutes = window_minutes or config.CORRELATION_WINDOW_MINUTES
    min_alerts = min_alerts or config.CAMPAIGN_MIN_ALERTS
    window = timedelta(minutes=window_minutes)

    # Group alerts by source IP
    by_ip: Dict[str, List[Dict]] = defaultdict(list)
    for alert in alerts:
        by_ip[alert["source_ip"]].append(alert)

    campaigns = []
    for ip, ip_alerts in by_ip.items():
        if len(ip_alerts) < min_alerts:
            continue

        sorted_alerts = sorted(ip_alerts, key=lambda a: a["timestamp"])

        # Sliding window: find the largest window with >= min_alerts
        consumed: set = set()
        i = 0
        while i < len(sorted_alerts):
            if sorted_alerts[i]["alert_id"] in consumed:
                i += 1
                continue

            window_alerts = [
                a for a in sorted_alerts[i:]
                if (a["timestamp"] - sorted_alerts[i]["timestamp"]) <= window
                and a["alert_id"] not in consumed
            ]

            if len(window_alerts) >= min_alerts:
                campaign = _make_campaign(ip, window_alerts, window_minutes)
                campaigns.append(campaign)
                for a in window_alerts:
                    consumed.add(a["alert_id"])
            i += 1

    logger.info("Correlation: %d alerts → %d campaigns", len(alerts), len(campaigns))
    return campaigns
