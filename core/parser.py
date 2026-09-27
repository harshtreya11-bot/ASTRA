"""
core/parser.py - HTTP access-log parser and CSV loader
"""

import re
import csv
import io
import logging
import uuid
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, unquote_plus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Common Log Format (CLF) + Combined Log Format regex
# ---------------------------------------------------------------------------
# 192.168.1.1 - - [25/Sep/2026:10:32:15 +0530] "GET /path?q=val HTTP/1.1" 200 512 "-" "UA"
_CLF_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'               # source IP
    r'\S+\s+'                        # ident (-)
    r'\S+\s+'                        # user (-)
    r'\[(?P<time>[^\]]+)\]\s+'       # timestamp
    r'"(?P<request>[^"]+)"\s+'       # request line
    r'(?P<status>\d{3})\s+'          # status code
    r'(?P<size>\S+)'                 # response bytes
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'  # optional referer+UA
)

_REQUEST_LINE = re.compile(
    r'(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<version>HTTP/\S+)'
)

_TIMESTAMP_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
]


def _parse_timestamp(raw: str) -> Optional[datetime]:
    for fmt in _TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    return None


def _parse_url_parts(raw_path: str) -> Dict:
    """Split URL into path, query string, and parameters."""
    try:
        parsed = urlparse(raw_path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        # Flatten single-value params
        flat_params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
        return {
            "endpoint": parsed.path,
            "query_string": parsed.query,
            "parameters": flat_params,
        }
    except Exception:
        return {"endpoint": raw_path, "query_string": "", "parameters": {}}


def parse_clf_line(line: str, line_number: int = 0) -> Optional[Dict]:
    """Parse a single CLF/Combined log line into an event dict."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    m = _CLF_PATTERN.match(line)
    if not m:
        logger.debug("Unmatched log line %d: %s", line_number, line[:80])
        return None

    # Parse request line
    req_m = _REQUEST_LINE.match(m.group("request"))
    if not req_m:
        return None

    raw_path = req_m.group("path")
    url_parts = _parse_url_parts(raw_path)

    ts = _parse_timestamp(m.group("time"))
    if ts is None:
        logger.debug("Unparseable timestamp on line %d", line_number)
        ts = datetime.utcnow()

    try:
        status_code = int(m.group("status"))
    except ValueError:
        status_code = 0

    size_raw = m.group("size")
    try:
        response_size = int(size_raw)
    except (ValueError, TypeError):
        response_size = 0

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts,
        "source_ip": m.group("ip"),
        "method": req_m.group("method"),
        "raw_path": raw_path,
        "endpoint": url_parts["endpoint"],
        "query_string": url_parts["query_string"],
        "parameters": url_parts["parameters"],
        "http_version": req_m.group("version"),
        "status_code": status_code,
        "response_size": response_size,
        "referer": m.group("referer") or "",
        "user_agent": m.group("ua") or "",
        "raw_request": line,
        "normalized_request": "",   # filled by normalizer
    }


def parse_clf_text(text: str) -> List[Dict]:
    """Parse an entire log text (multi-line) and return list of events."""
    events = []
    for i, line in enumerate(text.splitlines(), start=1):
        ev = parse_clf_line(line, i)
        if ev:
            events.append(ev)
    logger.info("Parsed %d events from CLF text", len(events))
    return events


# ---------------------------------------------------------------------------
# CSV Parser
# ---------------------------------------------------------------------------
_REQUIRED_CSV_COLUMNS = {"timestamp", "source_ip", "method", "endpoint", "status_code"}
_OPTIONAL_CSV_COLUMNS = {"query", "user_agent", "referer", "response_size"}


def parse_csv_text(text: str) -> tuple[List[Dict], Optional[str]]:
    """
    Parse CSV text into events.
    Returns (events, error_message).
    """
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return [], "CSV file has no headers."

    fieldnames_lower = {f.strip().lower() for f in reader.fieldnames}
    missing = _REQUIRED_CSV_COLUMNS - fieldnames_lower
    if missing:
        return [], f"CSV is missing required columns: {', '.join(sorted(missing))}"

    events = []
    for i, row in enumerate(reader, start=2):
        # Normalise keys
        row = {k.strip().lower(): v for k, v in row.items()}
        ts = _parse_timestamp(row.get("timestamp", ""))
        if ts is None:
            ts = datetime.utcnow()

        query = row.get("query", "")
        endpoint = row.get("endpoint", "/")
        if query:
            raw_path = f"{endpoint}?{query}"
        else:
            raw_path = endpoint

        url_parts = _parse_url_parts(raw_path)

        try:
            status_code = int(row.get("status_code", 0))
        except ValueError:
            status_code = 0

        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": ts,
            "source_ip": row.get("source_ip", "0.0.0.0"),
            "method": row.get("method", "GET").upper(),
            "raw_path": raw_path,
            "endpoint": url_parts["endpoint"],
            "query_string": url_parts["query_string"],
            "parameters": url_parts["parameters"],
            "http_version": "HTTP/1.1",
            "status_code": status_code,
            "response_size": int(row.get("response_size", 0) or 0),
            "referer": row.get("referer", ""),
            "user_agent": row.get("user_agent", ""),
            "raw_request": str(row),
            "normalized_request": "",
        })

    logger.info("Parsed %d events from CSV", len(events))
    return events, None


# ---------------------------------------------------------------------------
# Auto-detect format and parse uploaded content
# ---------------------------------------------------------------------------

def parse_log_stream(stream, filename: str = "", chunk_size: int = 50000):
    """
    Stream-parse an open file object or string iterator in chunks of `chunk_size`.
    Yields (events_chunk, lines_read_count, error_message).
    Designed to handle 4GB+ log files without keeping all raw text or objects in memory.
    """
    filename_lower = filename.lower()
    is_csv = filename_lower.endswith(".csv")

    current_chunk = []
    line_number = 0

    if is_csv:
        def line_decoder(st):
            for line in st:
                if isinstance(line, bytes):
                    yield line.decode("utf-8", errors="replace")
                else:
                    yield line

        decoded_stream = line_decoder(stream)
        reader = csv.DictReader(decoded_stream)
        if not reader.fieldnames:
            yield [], 0, "CSV file has no headers."
            return

        fieldnames_lower = {f.strip().lower() for f in reader.fieldnames}
        missing = _REQUIRED_CSV_COLUMNS - fieldnames_lower
        if missing:
            yield [], 0, f"CSV is missing required columns: {', '.join(sorted(missing))}"
            return

        for row in reader:
            line_number += 1
            row = {k.strip().lower(): v for k, v in row.items() if k}
            ts = _parse_timestamp(row.get("timestamp", ""))
            if ts is None:
                ts = datetime.utcnow()

            query = row.get("query", "")
            endpoint = row.get("endpoint", "/")
            raw_path = f"{endpoint}?{query}" if query else endpoint
            url_parts = _parse_url_parts(raw_path)

            try:
                status_code = int(row.get("status_code", 0))
            except ValueError:
                status_code = 0

            event = {
                "event_id": str(uuid.uuid4()),
                "timestamp": ts,
                "source_ip": row.get("source_ip", "0.0.0.0"),
                "method": row.get("method", "GET").upper(),
                "raw_path": raw_path,
                "endpoint": url_parts["endpoint"],
                "query_string": url_parts["query_string"],
                "parameters": url_parts["parameters"],
                "http_version": "HTTP/1.1",
                "status_code": status_code,
                "response_size": int(row.get("response_size", 0) or 0),
                "referer": row.get("referer", ""),
                "user_agent": row.get("user_agent", ""),
                "raw_request": str(row),
                "normalized_request": "",
            }
            current_chunk.append(event)
            if len(current_chunk) >= chunk_size:
                yield current_chunk, line_number, None
                current_chunk = []

        if current_chunk:
            yield current_chunk, line_number, None
        return

    # CLF / Auto-detect mode
    for line in stream:
        line_number += 1
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")

        event = parse_clf_line(line, line_number)
        if event:
            current_chunk.append(event)

        if len(current_chunk) >= chunk_size:
            yield current_chunk, line_number, None
            current_chunk = []

    if current_chunk:
        yield current_chunk, line_number, None
    elif line_number == 0:
        yield [], 0, "Log file is empty."


def parse_log_content(content: str, filename: str = "") -> tuple[List[Dict], Optional[str]]:
    """
    Auto-detect log format and parse (in-memory wrapper around parse_log_stream).
    Returns (events, error_message).
    """
    if not content or not content.strip():
        return [], "Uploaded file is empty."

    all_events = []
    last_err = None
    stream = io.StringIO(content)
    for chunk, _, err in parse_log_stream(stream, filename=filename):
        if err:
            last_err = err
        all_events.extend(chunk)

    if not all_events and last_err:
        return [], last_err

    if not all_events:
        return [], (
            "Could not detect log format. "
            "Supported formats: Apache/Nginx CLF and CSV with columns "
            "timestamp, source_ip, method, endpoint, status_code."
        )

    return all_events, None

