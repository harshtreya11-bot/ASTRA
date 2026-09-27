"""
tests/test_detector.py - Unit tests for attack detection rules
"""

import unittest
from datetime import datetime
from core.normalizer import normalize_event
from core.detector import detect_attacks, detect_auth_attacks


def _create_event(raw_path: str, method: str = "GET", ip: str = "192.168.1.20", status: int = 200, ua: str = "Mozilla/5.0") -> dict:
    parts = raw_path.split("?", 1)
    endpoint = parts[0]
    query = parts[1] if len(parts) > 1 else ""
    event = {
        "event_id": "test-123",
        "timestamp": datetime.utcnow(),
        "source_ip": ip,
        "method": method,
        "raw_path": raw_path,
        "endpoint": endpoint,
        "query_string": query,
        "parameters": {},
        "status_code": status,
        "user_agent": ua,
        "referer": "-",
        "raw_request": f"{method} {raw_path} HTTP/1.1",
        "normalized_request": "",
    }
    return normalize_event(event)


class TestDetector(unittest.TestCase):

    # --- SQL Injection Tests ---
    def test_sqli_detection_positive(self):
        event = _create_event("/login?username=admin%27%20OR%201%3D1--")
        alerts = detect_attacks([event])
        sqli_alerts = [a for a in alerts if a["attack_type"] == "SQL Injection"]
        self.assertTrue(len(sqli_alerts) >= 1)
        self.assertEqual(sqli_alerts[0]["risk_level"], "CRITICAL")
        self.assertIn("OR", sqli_alerts[0]["evidence"].upper())

    def test_sqli_detection_union_select(self):
        event = _create_event("/search?q=%27%20UNION%20SELECT%201%2C2%2C3--")
        alerts = detect_attacks([event])
        sqli_alerts = [a for a in alerts if a["attack_type"] == "SQL Injection"]
        self.assertTrue(len(sqli_alerts) >= 1)

    def test_sqli_detection_negative(self):
        # Normal query containing the word 'select' should not be flagged as critical SQLi
        event = _create_event("/search?q=select+items+from+catalog")
        alerts = detect_attacks([event])
        crit_sqli = [a for a in alerts if a["attack_type"] == "SQL Injection" and a["risk_level"] == "CRITICAL"]
        self.assertEqual(len(crit_sqli), 0)

    # --- XSS Tests ---
    def test_xss_detection_script_tag(self):
        event = _create_event("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        alerts = detect_attacks([event])
        xss_alerts = [a for a in alerts if a["attack_type"] == "Cross-Site Scripting"]
        self.assertTrue(len(xss_alerts) >= 1)
        self.assertIn("Script tag", xss_alerts[0]["rule_description"])

    def test_xss_detection_onerror_img(self):
        event = _create_event("/profile?name=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")
        alerts = detect_attacks([event])
        xss_alerts = [a for a in alerts if a["attack_type"] == "Cross-Site Scripting"]
        self.assertTrue(len(xss_alerts) >= 1)

    def test_xss_detection_negative(self):
        event = _create_event("/search?q=javascript+tutorials")
        alerts = detect_attacks([event])
        high_xss = [a for a in alerts if a["attack_type"] == "Cross-Site Scripting" and a["risk_level"] in ("HIGH", "CRITICAL")]
        self.assertEqual(len(high_xss), 0)

    # --- Path Traversal Tests ---
    def test_path_traversal_detection_positive(self):
        event = _create_event("/download?file=../../etc/passwd")
        alerts = detect_attacks([event])
        pt_alerts = [a for a in alerts if a["attack_type"] == "Path Traversal"]
        self.assertTrue(len(pt_alerts) >= 1)

    def test_path_traversal_encoded(self):
        event = _create_event("/static?path=%2e%2e%2f%2e%2e%2fetc%2Fhosts")
        alerts = detect_attacks([event])
        pt_alerts = [a for a in alerts if a["attack_type"] == "Path Traversal"]
        self.assertTrue(len(pt_alerts) >= 1)

    def test_path_traversal_negative(self):
        event = _create_event("/download?file=report_2026.pdf")
        alerts = detect_attacks([event])
        pt_alerts = [a for a in alerts if a["attack_type"] == "Path Traversal"]
        self.assertEqual(len(pt_alerts), 0)

    # --- Command Injection Tests ---
    def test_command_injection_positive(self):
        event = _create_event("/ping?host=127.0.0.1%3Bwhoami")
        alerts = detect_attacks([event])
        cmdi_alerts = [a for a in alerts if a["attack_type"] == "Command Injection"]
        self.assertTrue(len(cmdi_alerts) >= 1)

    def test_command_injection_pipe_id(self):
        event = _create_event("/lookup?domain=example.com%7Cid")
        alerts = detect_attacks([event])
        cmdi_alerts = [a for a in alerts if a["attack_type"] == "Command Injection"]
        self.assertTrue(len(cmdi_alerts) >= 1)

    def test_command_injection_negative(self):
        event = _create_event("/search?q=curl+command+documentation")
        alerts = detect_attacks([event])
        crit_cmdi = [a for a in alerts if a["attack_type"] == "Command Injection" and a["risk_level"] == "CRITICAL"]
        self.assertEqual(len(crit_cmdi), 0)

    # --- Parameter Manipulation Tests ---
    def test_null_byte_injection(self):
        event = _create_event("/view?file=doc.pdf%00.txt")
        alerts = detect_attacks([event])
        param_alerts = [a for a in alerts if a["attack_type"] == "Parameter Manipulation"]
        self.assertTrue(len(param_alerts) >= 1)


if __name__ == "__main__":
    unittest.main()
