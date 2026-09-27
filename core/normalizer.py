"""
core/normalizer.py - Request normalization before detection
"""

import html
import re
import logging
from typing import Dict
from urllib.parse import unquote_plus, parse_qs

logger = logging.getLogger(__name__)

_WHITESPACE_RE = re.compile(r'\s+')


def _url_decode_repeatedly(text: str, max_passes: int = 3) -> str:
    """Repeatedly URL-decode until stable (handles double-encoding)."""
    for _ in range(max_passes):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text


def _decode_html_entities(text: str) -> str:
    """Decode HTML entities like &lt; &gt; &amp; &#39; etc."""
    return html.unescape(text)


def _normalize_whitespace(text: str) -> str:
    return _WHITESPACE_RE.sub(' ', text).strip()


def _extract_params(query_string: str) -> Dict[str, object]:
    """Extract and normalize query parameters."""
    try:
        parsed = parse_qs(query_string, keep_blank_values=True)
        return {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
    except Exception:
        return {}


def normalize_event(event: Dict) -> Dict:
    """
    Normalize an event dict in-place.
    - URL-decode the raw path
    - HTML-entity decode
    - Lowercase for comparison
    - Re-extract parameters from decoded URL
    - Normalize whitespace

    IMPORTANT: raw_request is NEVER modified. Only normalized_request is set.
    """
    raw = event.get("raw_request", "")
    raw_path = event.get("raw_path", "")
    query_string = event.get("query_string", "")
    ua = event.get("user_agent", "")
    referer = event.get("referer", "")

    # Build the combined text used for detection
    # We apply multi-pass decode on path and query
    decoded_path = _url_decode_repeatedly(raw_path)
    decoded_path = _decode_html_entities(decoded_path)
    decoded_path = _normalize_whitespace(decoded_path)

    decoded_query = _url_decode_repeatedly(query_string)
    decoded_query = _decode_html_entities(decoded_query)
    decoded_query = _normalize_whitespace(decoded_query)

    # Re-extract parameters from decoded query string
    if decoded_query:
        decoded_params = _extract_params(decoded_query)
    else:
        decoded_params = event.get("parameters", {})

    # Check for duplicate parameters in raw (possible param pollution)
    raw_param_names = [p.split("=")[0] for p in query_string.split("&") if "=" in p]
    duplicate_params = {
        name for name in raw_param_names if raw_param_names.count(name) >= 2
    }

    # Full normalized text for the detector (combine everything)
    normalized_parts = [
        event.get("method", ""),
        decoded_path,
        decoded_query,
        ua,
        referer,
    ]
    normalized_request = " ".join(p for p in normalized_parts if p)

    # Update the event
    event["normalized_request"] = normalized_request
    event["decoded_path"] = decoded_path
    event["decoded_query"] = decoded_query
    event["decoded_params"] = decoded_params
    event["duplicate_params"] = list(duplicate_params)

    return event


def normalize_events(events: list) -> list:
    """Normalize a list of events."""
    return [normalize_event(e) for e in events]
