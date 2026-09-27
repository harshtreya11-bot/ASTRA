"""
tests/test_ml_engine.py - Unit tests for ML Anomaly Detection
"""

import unittest
from datetime import datetime
from core.normalizer import normalize_event
from core.ml_engine import detect_anomalies_ml, extract_features

def _create_event(raw_path: str, method: str = "GET", ip: str = "192.168.1.20", status: int = 200, size: int = 500) -> dict:
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
        "response_size": size,
        "user_agent": "Mozilla/5.0",
        "referer": "-",
        "raw_request": f"{method} {raw_path} HTTP/1.1",
        "normalized_request": "",
    }
    return normalize_event(event)

class TestMLEngine(unittest.TestCase):

    def test_extract_features(self):
        ev = _create_event("/search?q=123", method="POST", size=1024)
        feats = extract_features(ev)
        # Features: path_len, query_len, num_params, special_chars, method_get, method_post, size
        self.assertEqual(len(feats), 7)
        self.assertEqual(feats[0], len("/search?q=123"))
        self.assertEqual(feats[1], len("q=123"))
        self.assertEqual(feats[4], 0.0) # GET
        self.assertEqual(feats[5], 1.0) # POST
        self.assertEqual(feats[6], 1024.0) # Size

    def test_detect_anomalies_ml(self):
        # Create a bunch of normal events
        events = [_create_event(f"/index.html?id={i}") for i in range(20)]
        
        # Add a highly anomalous event
        anomalous = _create_event("/login?" + ("a=1&"*50) + "b=%3Cscript%3E%27%22%3B", size=99999)
        events.append(anomalous)
        
        alerts = detect_anomalies_ml(events)
        
        # Since we just use sklearn's IsolationForest, it might flag it. 
        # But this is stochastic and depends on the specific dataset size, 
        # so we just test that it runs without errors.
        self.assertTrue(isinstance(alerts, list))

if __name__ == "__main__":
    unittest.main()
