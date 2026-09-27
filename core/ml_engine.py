"""
core/ml_engine.py - Machine Learning Anomaly Detection
"""

import logging
import uuid
from typing import List, Dict
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn or numpy not available. ML anomaly detection disabled.")

import config
from rules.attack_rules import AttackRule

def extract_features(event: Dict) -> List[float]:
    """
    Extract numerical features from an event for ML anomaly detection.
    """
    raw_path = event.get("raw_path", "")
    query_string = event.get("query_string", "")
    params = event.get("parameters", {})
    method = event.get("method", "GET")
    size = event.get("response_size", 0)
    
    path_len = len(raw_path)
    query_len = len(query_string)
    num_params = len(params)
    
    # Count special chars in path/query that are common in attacks
    special_chars = sum(1 for c in raw_path + query_string if c in "%<>'\"\\;()|&")
    
    method_get = 1.0 if method == "GET" else 0.0
    method_post = 1.0 if method == "POST" else 0.0
    
    return [
        float(path_len),
        float(query_len),
        float(num_params),
        float(special_chars),
        method_get,
        method_post,
        float(size)
    ]

def detect_anomalies_ml(events: List[Dict]) -> List[Dict]:
    """
    Use Isolation Forest to detect anomalous requests based on extracted features.
    """
    alerts = []
    
    if not SKLEARN_AVAILABLE or len(events) < 10:
        # Require a minimum number of events to train a meaningful model
        return alerts
        
    try:
        # Extract features for all events
        X = np.array([extract_features(ev) for ev in events])
        
        # Train Isolation Forest
        # contamination sets the expected proportion of outliers (anomalies)
        clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        
        # Fit and predict. 1 = normal, -1 = anomaly
        preds = clf.fit_predict(X)
        scores = clf.decision_function(X) # lower score means more anomalous
        
        for i, pred in enumerate(preds):
            if pred == -1:
                event = events[i]
                # Normalize the score for confidence (0 to 100)
                # decision_function typically returns values between -0.5 and 0.5
                raw_score = scores[i]
                confidence = int(min(100, max(0, abs(raw_score) * 200)))
                
                # We only want to flag things that are quite anomalous
                if confidence > 30:
                    evidence = f"ML Anomaly Detected. Anomaly Score: {raw_score:.3f}. Features: PathLen={X[i][0]}, QueryLen={X[i][1]}, NumParams={X[i][2]}, SpecialChars={X[i][3]}"
                    
                    alert = {
                        "alert_id": str(uuid.uuid4()),
                        "timestamp": event.get("timestamp", datetime.utcnow()),
                        "source_ip": event.get("source_ip", ""),
                        "attack_type": "ML Anomaly",
                        "risk_level": "MEDIUM",
                        "risk_score": 50,
                        "endpoint": event.get("endpoint", ""),
                        "parameter": "",
                        "evidence": evidence,
                        "rule_id": "ML-001",
                        "rule_description": "Isolation Forest Anomaly Detection",
                        "confidence": confidence,
                        "raw_request": event.get("raw_request", ""),
                        "method": event.get("method", ""),
                        "status_code": event.get("status_code", 0),
                        "user_agent": event.get("user_agent", ""),
                        "recommended_action": "1. Investigate the raw request for zero-day payloads.\n2. Verify if this behavior is normal for the endpoint.",
                        "status": "Open",
                        "event_id": event.get("event_id", ""),
                        "explanation": f"This request deviates significantly from normal traffic patterns based on machine learning analysis (anomaly score: {raw_score:.3f})."
                    }
                    alerts.append(alert)
                    
    except Exception as e:
        logger.error(f"Error in ML anomaly detection: {e}")
        
    return alerts
