"""
tests/test_correlator.py - Unit tests for correlation engine and brute-force detection
"""

import unittest
from datetime import datetime, timedelta
from core.normalizer import normalize_event
from core.detector import detect_attacks, detect_auth_attacks
from core.correlator import correlate_alerts


def _create_event(path: str, ip: str = "192.168.1.50", method: str = "POST", status: int = 401, ts: datetime = None) -> dict:
    if ts is None:
        ts = datetime.utcnow()
    event = {
        "event_id": f"ev-{ts.timestamp()}",
        "timestamp": ts,
        "source_ip": ip,
        "method": method,
        "raw_path": path,
        "endpoint": path.split("?")[0],
        "query_string": "",
        "parameters": {},
        "status_code": status,
        "user_agent": "Mozilla/5.0",
        "referer": "-",
        "raw_request": f"{method} {path} HTTP/1.1",
        "normalized_request": "",
    }
    return normalize_event(event)


class TestCorrelatorAndAuth(unittest.TestCase):

    def test_auth_brute_force_detection_positive(self):
        base_time = datetime(2026, 9, 25, 10, 0, 0)
        events = []
        # Generate 6 failed logins within 3 minutes from same IP
        for i in range(6):
            ts = base_time + timedelta(seconds=i * 20)
            events.append(_create_event("/login", ip="192.168.1.100", status=401, ts=ts))

        alerts = detect_auth_attacks(events, threshold=5, window_minutes=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["attack_type"], "Authentication Attack")
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.100")
        self.assertEqual(alerts[0]["failed_count"], 6)
        self.assertIn("HIGH", ["HIGH", "CRITICAL"])

    def test_auth_brute_force_detection_negative(self):
        base_time = datetime(2026, 9, 25, 10, 0, 0)
        events = []
        # Generate only 3 failed logins (below threshold of 5)
        for i in range(3):
            ts = base_time + timedelta(seconds=i * 30)
            events.append(_create_event("/login", ip="192.168.1.101", status=401, ts=ts))

        alerts = detect_auth_attacks(events, threshold=5, window_minutes=5)
        self.assertEqual(len(alerts), 0)

    def test_campaign_correlation(self):
        base_time = datetime(2026, 9, 25, 10, 0, 0)
        alerts = [
            {
                "alert_id": "a1",
                "timestamp": base_time,
                "source_ip": "10.0.0.99",
                "attack_type": "SQL Injection",
                "risk_level": "CRITICAL",
                "risk_score": 90,
                "endpoint": "/login",
            },
            {
                "alert_id": "a2",
                "timestamp": base_time + timedelta(minutes=1),
                "source_ip": "10.0.0.99",
                "attack_type": "XSS",
                "risk_level": "HIGH",
                "risk_score": 75,
                "endpoint": "/search",
            },
            {
                "alert_id": "a3",
                "timestamp": base_time + timedelta(minutes=2),
                "source_ip": "10.0.0.99",
                "attack_type": "Path Traversal",
                "risk_level": "HIGH",
                "risk_score": 80,
                "endpoint": "/download",
            },
        ]

        campaigns = correlate_alerts(alerts, window_minutes=10, min_alerts=3)
        self.assertEqual(len(campaigns), 1)
        camp = campaigns[0]
        self.assertEqual(camp["source_ip"], "10.0.0.99")
        self.assertEqual(camp["total_alerts"], 3)
        self.assertEqual(camp["risk_level"], "CRITICAL")
        self.assertIn("/login", camp["affected_endpoints"])
        self.assertIn("/search", camp["affected_endpoints"])


if __name__ == "__main__":
    unittest.main()
