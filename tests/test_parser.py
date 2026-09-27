"""
tests/test_parser.py - Unit tests for log parser and normalizer
"""

import unittest
from datetime import datetime
from core.parser import parse_clf_line, parse_clf_text, parse_csv_text, parse_log_content
from core.normalizer import normalize_event, normalize_events


class TestParser(unittest.TestCase):

    def test_valid_clf_line(self):
        line = '192.168.1.20 - - [25/Sep/2026:10:32:15 +0530] "GET /login?username=admin%27%20OR%201%3D1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        event = parse_clf_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["source_ip"], "192.168.1.20")
        self.assertEqual(event["method"], "GET")
        self.assertEqual(event["endpoint"], "/login")
        self.assertEqual(event["status_code"], 200)
        self.assertEqual(event["response_size"], 512)
        self.assertEqual(event["user_agent"], "Mozilla/5.0")
        self.assertIn("username", event["parameters"])

    def test_invalid_clf_line(self):
        line = 'invalid log line format'
        event = parse_clf_line(line)
        self.assertIsNone(event)

    def test_missing_fields_clf_line(self):
        line = '192.168.1.20 - - [25/Sep/2026:10:32:15 +0530] "GET / HTTP/1.1"'
        event = parse_clf_line(line)
        self.assertIsNone(event)

    def test_csv_parser_valid(self):
        csv_data = (
            "timestamp,source_ip,method,endpoint,query,status_code,user_agent\n"
            "2026-09-25 10:30:00,10.0.0.1,GET,/search,q=test,200,Mozilla/5.0\n"
            "2026-09-25 10:30:05,10.0.0.2,POST,/login,,401,curl/7.68.0\n"
        )
        events, err = parse_csv_text(csv_data)
        self.assertIsNone(err)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["source_ip"], "10.0.0.1")
        self.assertEqual(events[0]["endpoint"], "/search")
        self.assertEqual(events[1]["status_code"], 401)

    def test_csv_parser_missing_required_column(self):
        csv_data = "source_ip,method,endpoint\n10.0.0.1,GET,/\n"
        events, err = parse_csv_text(csv_data)
        self.assertIsNotNone(err)
        self.assertIn("missing required columns", err)
        self.assertEqual(len(events), 0)

    def test_auto_detect_parse_log_content(self):
        clf = '192.168.1.20 - - [25/Sep/2026:10:32:15 +0530] "GET /about HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        events, err = parse_log_content(clf)
        self.assertIsNone(err)
        self.assertEqual(len(events), 1)

    def test_normalizer(self):
        event = {
            "raw_request": 'GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1',
            "raw_path": '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E',
            "query_string": 'q=%3Cscript%3Ealert(1)%3C%2Fscript%3E',
            "method": "GET",
            "user_agent": "Mozilla/5.0",
            "referer": "",
        }
        norm = normalize_event(event)
        self.assertIn("<script>alert(1)</script>", norm["normalized_request"])
        self.assertEqual(norm["raw_request"], 'GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1')


    def test_stream_parser(self):
        import io
        from core.parser import parse_log_stream
        lines = [
            '192.168.1.20 - - [25/Sep/2026:10:32:15 +0530] "GET /about HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n',
            '192.168.1.21 - - [25/Sep/2026:10:32:16 +0530] "GET /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n',
            '192.168.1.22 - - [25/Sep/2026:10:32:17 +0530] "POST /api HTTP/1.1" 201 256 "-" "Mozilla/5.0"\n',
        ]
        stream = io.StringIO("".join(lines))
        chunks = list(parse_log_stream(stream, chunk_size=2))
        self.assertEqual(len(chunks), 2)
        chunk1_events, chunk1_count, err1 = chunks[0]
        self.assertIsNone(err1)
        self.assertEqual(len(chunk1_events), 2)
        chunk2_events, chunk2_count, err2 = chunks[1]
        self.assertIsNone(err2)
        self.assertEqual(len(chunk2_events), 1)


if __name__ == "__main__":
    unittest.main()

