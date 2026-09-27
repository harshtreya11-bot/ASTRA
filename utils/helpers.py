"""
utils/helpers.py - Shared utility functions
"""

import re
import json
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional


def truncate(text: str, max_len: int = 80, suffix: str = "…") -> str:
    """Truncate text to max_len characters."""
    if not text:
        return ""
    return text if len(text) <= max_len else text[:max_len] + suffix


def highlight_evidence(text: str, evidence_snippet: str) -> str:
    """Return text with evidence wrapped in angle brackets for display."""
    if not evidence_snippet or not text:
        return text
    # Try to highlight the first match
    try:
        pattern = re.compile(re.escape(evidence_snippet[:40]), re.IGNORECASE)
        return pattern.sub(lambda m: f"⚠️{m.group(0)}⚠️", text, count=1)
    except re.error:
        return text


def format_timestamp(dt) -> str:
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(dt, str):
        return dt[:19]
    return str(dt)


def safe_json_loads(text: str, default=None):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else {}


def generate_short_id(prefix: str = "") -> str:
    """Generate a short deterministic-ish ID."""
    import uuid
    short = str(uuid.uuid4())[:8].upper()
    return f"{prefix}{short}" if prefix else short


def count_by_field(items: List[Dict], field: str) -> Dict[str, int]:
    """Count occurrences of field values in a list of dicts."""
    counts: Dict[str, int] = {}
    for item in items:
        val = str(item.get(field, "Unknown"))
        counts[val] = counts.get(val, 0) + 1
    return counts


def top_n(d: Dict[str, int], n: int = 10) -> List[tuple]:
    """Return top-n items from a count dict, sorted descending."""
    return sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]


def risk_sort_key(level: str) -> int:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return order.get(level.upper(), 0)


def parse_json_field(value) -> Any:
    """Parse a JSON string or return the value as-is if already parsed."""
    if isinstance(value, str):
        return safe_json_loads(value, {})
    return value
