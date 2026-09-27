"""
test_app/app.py - Controlled Test Application for HTTP Request Logging

This lightweight Flask application provides safe, harmless endpoints
to simulate a target web application during security testing (e.g. with Burp Suite or curl).
It logs incoming HTTP requests in Apache/Nginx Combined Log Format (CLF).
"""

import os
import sys
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# Configure log file destination
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
os.makedirs(LOG_DIR, exist_ok=True)
ACCESS_LOG_PATH = os.path.join(LOG_DIR, "test_app_access.log")

# Setup logger
log_formatter = logging.Formatter('%(message)s')
file_handler = logging.FileHandler(ACCESS_LOG_PATH)
file_handler.setFormatter(log_formatter)
logger = logging.getLogger("TestAppAccessLogger")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)


@app.after_request
def log_request(response):
    """Format and log the HTTP request in Combined Log Format (CLF)."""
    ip = request.remote_addr or "127.0.0.1"
    now_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S %z")
    if not now_str.endswith("+") and not "-" in now_str[-5:]:
        now_str += " +0000"
    
    full_path = request.full_path
    if full_path.endswith("?"):
        full_path = full_path[:-1]
    
    method = request.method
    http_version = request.environ.get("SERVER_PROTOCOL", "HTTP/1.1")
    status = response.status_code
    size = response.content_length or len(response.get_data())
    referer = request.headers.get("Referer", "-")
    user_agent = request.headers.get("User-Agent", "-")
    
    log_entry = (
        f'{ip} - - [{now_str}] "{method} {full_path} {http_version}" '
        f'{status} {size} "{referer}" "{user_agent}"'
    )
    logger.info(log_entry)
    print(f"[ACCESS LOG] {log_entry}")
    return response


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Controlled Test Target</title>
    <style>
        body { font-family: sans-serif; background: #0d1117; color: #c9d1d9; padding: 40px; }
        h1 { color: #58a6ff; }
        code { background: #161b22; padding: 2px 6px; border-radius: 4px; color: #f0c040; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>🛡️ Controlled Test Target Application</h1>
    <p>This harmless test application logs incoming HTTP requests to <code>data/test_app_access.log</code>.</p>
    <div class="card">
        <h3>Available Endpoints</h3>
        <ul>
            <li><code>GET /</code> - Main Index</li>
            <li><code>POST /login</code> - Login Endpoint (returns 401 on bad credentials)</li>
            <li><code>GET /search?q=query</code> - Search Endpoint</li>
            <li><code>GET /download?file=filename</code> - File Download Endpoint</li>
            <li><code>GET /ping?host=ip</code> - Network Diagnostic Endpoint</li>
            <li><code>GET /admin</code> - Restricted Admin Endpoint</li>
        </ul>
    </div>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username") or request.args.get("username", "")
        password = request.form.get("password") or request.args.get("password", "")
        if user == "admin" and password == "secret123":
            return jsonify({"status": "success", "message": "Authenticated successfully"}), 200
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    return render_template_string(HTML_TEMPLATE)


@app.route("/search")
def search():
    query = request.args.get("q", "")
    return jsonify({"endpoint": "/search", "query": query, "results": []}), 200


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    return jsonify({"endpoint": "/download", "file": filename, "status": "simulated_file_content"}), 200


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return jsonify({"endpoint": "/ping", "target": host, "output": "PING 127.0.0.1 56 bytes of data."}), 200


@app.route("/admin")
def admin():
    return jsonify({"status": "forbidden", "message": "Admin area access restricted"}), 403


if __name__ == "__main__":
    print(f"Starting Test Application on http://127.0.0.1:5000")
    print(f"Logging requests to: {ACCESS_LOG_PATH}")
    app.run(host="127.0.0.1", port=5000, debug=True)
