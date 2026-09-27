"""
app.py - Main Streamlit Dashboard for Web Application Attack Detector
"""

import logging
import os
import sys
from datetime import datetime
from typing import List, Dict, Optional
from collections import Counter

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

import io
import config
from core.parser import parse_log_content, parse_log_stream
from core.normalizer import normalize_events
from core.detector import detect_attacks
from core.correlator import correlate_alerts
from core.database import get_db
from core.risk_engine import get_risk_badge, get_risk_color, compute_ip_risk_score
from rules.attack_rules import ALL_RULES
from utils.helpers import format_timestamp, truncate, count_by_field, top_n
from utils.demo_data import generate_demo_log
from reports.report_generator import generate_pdf_report, REPORTLAB_AVAILABLE

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Streamlit page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title=config.APP_TITLE,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Global CSS – Dark SOC Theme
# ---------------------------------------------------------------------------
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  :root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #1c2128;
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --accent: #58a6ff;
    --accent-green: #3fb950;
    --critical: #ff4d4d;
    --high: #ff9900;
    --medium: #f0c040;
    --low: #4caf50;
  }

  html, body, [data-testid="stAppViewContainer"] {
    background-color: var(--bg-primary) !important;
    color: var(--text-primary) !important;
    font-family: 'Inter', sans-serif !important;
  }

  [data-testid="stSidebar"] {
    background-color: var(--bg-secondary) !important;
    border-right: 1px solid var(--border) !important;
  }

  [data-testid="stSidebar"] * {
    color: var(--text-primary) !important;
  }

  .metric-card {
    background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 20px;
    text-align: center;
    transition: transform 0.2s ease, border-color 0.2s ease;
    margin-bottom: 8px;
  }
  .metric-card:hover {
    transform: translateY(-2px);
    border-color: var(--accent);
  }
  .metric-value {
    font-size: 2rem;
    font-weight: 700;
    color: var(--accent);
    line-height: 1.2;
    font-family: 'JetBrains Mono', monospace;
  }
  .metric-label {
    font-size: 0.75rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 4px;
  }
  .metric-critical .metric-value { color: var(--critical); }
  .metric-high .metric-value     { color: var(--high); }
  .metric-medium .metric-value   { color: var(--medium); }
  .metric-low .metric-value      { color: var(--low); }

  .risk-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.05em;
  }
  .badge-critical { background: rgba(255,77,77,0.2); color: #ff4d4d; border: 1px solid #ff4d4d; }
  .badge-high     { background: rgba(255,153,0,0.2); color: #ff9900; border: 1px solid #ff9900; }
  .badge-medium   { background: rgba(240,192,64,0.2); color: #f0c040; border: 1px solid #f0c040; }
  .badge-low      { background: rgba(76,175,80,0.2); color: #4caf50; border: 1px solid #4caf50; }

  .section-header {
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    margin-bottom: 16px;
    letter-spacing: 0.03em;
  }

  .evidence-box {
    background: var(--bg-secondary);
    border: 1px solid #f0c040;
    border-radius: 6px;
    padding: 10px 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: #f0c040;
    word-break: break-all;
    margin: 8px 0;
  }

  .alert-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-left-width: 4px;
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 10px;
  }
  .alert-card-critical { border-left-color: var(--critical) !important; }
  .alert-card-high     { border-left-color: var(--high) !important; }
  .alert-card-medium   { border-left-color: var(--medium) !important; }
  .alert-card-low      { border-left-color: var(--low) !important; }

  .campaign-card {
    background: linear-gradient(135deg, #1a1f2e 0%, #161b22 100%);
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 12px;
  }

  .info-row {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin: 8px 0;
  }
  .info-item {
    font-size: 0.8rem;
    color: var(--text-secondary);
  }
  .info-item strong { color: var(--text-primary); }

  .stDataFrame { background: var(--bg-secondary); }
  .stTextInput>div>div>input,
  .stSelectbox>div>div>select,
  .stTextArea textarea {
    background: var(--bg-secondary) !important;
    color: var(--text-primary) !important;
    border-color: var(--border) !important;
  }
  .stButton>button {
    background: linear-gradient(135deg, #1f6feb, #388bfd);
    color: white !important;
    border: none !important;
    border-radius: 6px !important;
    font-weight: 500 !important;
  }
  .stButton>button:hover {
    background: linear-gradient(135deg, #388bfd, #58a6ff) !important;
  }

  div[data-testid="stExpander"] {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
  }

  .app-title {
    font-size: 1.6rem;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: 0.05em;
  }
  .app-subtitle {
    font-size: 0.8rem;
    color: var(--text-secondary);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-top: -4px;
    margin-bottom: 16px;
  }

  .status-open        { color: #ff9900; }
  .status-investigating { color: #58a6ff; }
  .status-resolved    { color: #4caf50; }

  .plotly-graph-div {
    background: var(--bg-secondary) !important;
    border-radius: 10px;
  }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Session state helpers
# ---------------------------------------------------------------------------

def _init_state():
    defaults = {
        "events": [],
        "alerts": [],
        "campaigns": [],
        "data_loaded": False,
        "brute_threshold": config.BRUTE_FORCE_THRESHOLD,
        "brute_window": config.BRUTE_FORCE_WINDOW_MINUTES,
        "corr_window": config.CORRELATION_WINDOW_MINUTES,
        "enabled_rules": {r.rule_id for r in ALL_RULES},
        "page": "Dashboard",
        "selected_alert_id": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def _load_and_analyze(source, source_label: str = "upload"):
    """
    Memory-efficient streaming pipeline for large (up to 4GB+) log files:
    parse stream chunk → normalize → detect → save to DB → correlate → render summary.
    """
    db = get_db()
    db.clear_all()

    total_parsed_events = 0
    all_alerts = []
    sample_events = []

    file_to_close = None
    if isinstance(source, str) and os.path.exists(source):
        stream = open(source, "rb")
        file_to_close = stream
        filename = source
    elif isinstance(source, str):
        stream = io.StringIO(source)
        filename = source_label
    else:
        stream = source
        filename = getattr(source, "name", source_label)

    status_text = st.empty()
    progress_bar = st.progress(0)
    status_text.text("🚀 Initializing log analysis engine...")

    batch_count = 0
    chunk_size = 50000

    try:
        for events_chunk, lines_processed, err in parse_log_stream(stream, filename=filename, chunk_size=chunk_size):
            if err:
                st.error(f"Parse error: {err}")
                return False

            if not events_chunk:
                continue

            batch_count += 1
            status_text.text(
                f"⏳ Processing batch #{batch_count} | {lines_processed:,} lines parsed | "
                f"{len(all_alerts):,} alerts detected so far..."
            )

            # 1. Normalize
            events_chunk = normalize_events(events_chunk)

            # 2. Detect attacks
            chunk_alerts = detect_attacks(
                events_chunk,
                enabled_rule_ids=st.session_state.get("enabled_rules"),
                brute_threshold=st.session_state.get("brute_threshold"),
                brute_window=st.session_state.get("brute_window"),
            )
            all_alerts.extend(chunk_alerts)

            # 3. Store batch in SQLite
            db.insert_events(events_chunk)
            if chunk_alerts:
                db.insert_alerts(chunk_alerts)

            total_parsed_events += len(events_chunk)

            # Keep a sample of up to 10,000 events for fast UI preview
            if len(sample_events) < 10000:
                needed = 10000 - len(sample_events)
                sample_events.extend(events_chunk[:needed])

    finally:
        if file_to_close:
            file_to_close.close()

    if total_parsed_events == 0:
        status_text.empty()
        progress_bar.empty()
        st.warning("No valid log events parsed from the provided data.")
        return False

    status_text.text("🔗 Correlating attack campaigns across alerts...")
    campaigns = correlate_alerts(
        all_alerts,
        window_minutes=st.session_state.get("corr_window"),
    )

    if campaigns:
        db.insert_campaigns(campaigns)

    st.session_state["events"] = sample_events
    st.session_state["total_events_count"] = total_parsed_events
    st.session_state["alerts"] = all_alerts
    st.session_state["campaigns"] = campaigns
    st.session_state["data_loaded"] = True

    status_text.empty()
    progress_bar.empty()

    st.success(
        f"✅ Analysis complete! Processed {total_parsed_events:,} events | "
        f"{len(all_alerts):,} alerts | {len(campaigns):,} campaigns"
    )
    return True


# ---------------------------------------------------------------------------
# Plotly theme helpers
# ---------------------------------------------------------------------------

_PLOTLY_LAYOUT = dict(
    paper_bgcolor="#161b22",
    plot_bgcolor="#0d1117",
    font=dict(color="#c9d1d9", family="Inter"),
    margin=dict(l=10, r=10, t=30, b=10),
    legend=dict(
        bgcolor="#1c2128",
        bordercolor="#30363d",
        borderwidth=1,
        font=dict(color="#c9d1d9"),
    ),
)

_RISK_COLORS_MAP = {
    "CRITICAL": "#ff4d4d",
    "HIGH": "#ff9900",
    "MEDIUM": "#f0c040",
    "LOW": "#4caf50",
}

_ATTACK_COLOR_SEQ = [
    "#58a6ff", "#3fb950", "#f0c040", "#ff9900", "#ff4d4d", "#a371f7",
]


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def _sidebar():
    with st.sidebar:
        st.markdown('<div class="app-title">🛡️ ASTRA</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="app-subtitle">Attack Detector Platform</div>',
            unsafe_allow_html=True,
        )
        st.divider()

        # Navigation
        pages = [
            ("📊", "Dashboard"),
            ("📋", "Log Analysis"),
            ("🚨", "Alerts"),
            ("⏱️", "Attack Timeline"),
            ("🔎", "IP Investigation"),
            ("🎯", "Endpoint Analysis"),
            ("📄", "Reports"),
            ("📏", "Detection Rules"),
            ("⚙️", "Settings"),
        ]
        selected = None
        for icon, label in pages:
            if st.button(
                f"{icon}  {label}",
                key=f"nav_{label}",
                use_container_width=True,
                type="secondary" if st.session_state.page != label else "primary",
            ):
                st.session_state.page = label
                selected = label

        st.divider()

        # Data loading
        st.markdown("**📂 Data Source**")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🎭 Demo", use_container_width=True):
                demo_log = generate_demo_log()
                _load_and_analyze(demo_log, "demo")
                st.session_state.page = "Dashboard"
                st.rerun()
        with col2:
            if st.button("🗑️ Clear", use_container_width=True):
                get_db().clear_all()
                st.session_state["events"] = []
                st.session_state["total_events_count"] = 0
                st.session_state["alerts"] = []
                st.session_state["campaigns"] = []
                st.session_state["data_loaded"] = False
                st.rerun()

        uploaded = st.file_uploader(
            "Upload Log/CSV (Up to 5GB)",
            type=["log", "txt", "csv"],
            label_visibility="collapsed",
        )
        if uploaded:
            if _load_and_analyze(uploaded, uploaded.name):
                st.session_state.page = "Dashboard"
                st.rerun()

        with st.expander("📁 Analyze Local Disk File (4GB+)"):
            local_path = st.text_input(
                "Local file path",
                placeholder="/path/to/access.log",
                key="sidebar_local_path"
            )
            if st.button("⚡ Analyze Local File", use_container_width=True):
                if local_path and os.path.exists(local_path):
                    if _load_and_analyze(local_path, local_path):
                        st.session_state.page = "Dashboard"
                        st.rerun()
                else:
                    st.error("File not found at specified path.")

        st.divider()

        # Quick stats
        if st.session_state.data_loaded:
            alerts = st.session_state["alerts"]
            rc = Counter(a.get("risk_level") for a in alerts)
            total_ev = st.session_state.get("total_events_count", len(st.session_state['events']))
            st.markdown(f"""
            <div style="font-size:0.75rem; color:#8b949e;">
            📌 <b style="color:#e6edf3;">{total_ev:,}</b> events&nbsp;&nbsp;
            🚨 <b style="color:#e6edf3;">{len(alerts):,}</b> alerts<br>
            🔴 {rc.get('CRITICAL',0)} critical &nbsp;
            🟠 {rc.get('HIGH',0)} high<br>
            🟡 {rc.get('MEDIUM',0)} medium &nbsp;
            🟢 {rc.get('LOW',0)} low
            </div>
            """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Dashboard page
# ---------------------------------------------------------------------------

def _metric_card(label: str, value, css_class: str = "") -> str:
    cls = f"metric-card {css_class}"
    return f"""
    <div class="{cls}">
      <div class="metric-value">{value}</div>
      <div class="metric-label">{label}</div>
    </div>"""


def page_dashboard():
    st.markdown(f"<h1 style='color:#58a6ff;font-size:1.8rem;margin-bottom:0'>{config.APP_TITLE}</h1>", unsafe_allow_html=True)
    st.markdown(f"<p style='color:#8b949e;margin-top:0;font-size:0.85rem;letter-spacing:0.08em'>{config.APP_SUBTITLE}</p>", unsafe_allow_html=True)

    if not st.session_state.data_loaded:
        st.info("👈 Load demo data or upload a log file from the sidebar to begin.")
        _show_welcome()
        return

    events = st.session_state["events"]
    alerts = st.session_state["alerts"]
    campaigns = st.session_state["campaigns"]

    risk_counts = Counter(a.get("risk_level") for a in alerts)
    suspicious_ips = {a["source_ip"] for a in alerts}

    # ---- Metric cards ----
    total_events = st.session_state.get("total_events_count", len(events))
    cols = st.columns(6)
    metrics = [
        ("Total Requests", f"{total_events:,}", ""),
        ("Suspicious Requests", len({a["event_id"] for a in alerts if a.get("event_id")}), ""),
        ("Critical Alerts", risk_counts.get("CRITICAL", 0), "metric-critical"),
        ("High Alerts", risk_counts.get("HIGH", 0), "metric-high"),
        ("Suspicious IPs", len(suspicious_ips), ""),
        ("Campaigns", len(campaigns), ""),
    ]
    for col, (label, value, css) in zip(cols, metrics):
        with col:
            st.markdown(_metric_card(label, value, css), unsafe_allow_html=True)

    st.markdown("---")

    # ---- Charts row 1 ----
    col1, col2, col3 = st.columns([1, 1, 2])

    with col1:
        st.markdown('<div class="section-header">Attack Distribution</div>', unsafe_allow_html=True)
        attack_counts = count_by_field(alerts, "attack_type")
        if attack_counts:
            fig = px.pie(
                names=list(attack_counts.keys()),
                values=list(attack_counts.values()),
                color_discrete_sequence=_ATTACK_COLOR_SEQ,
                hole=0.45,
            )
            fig.update_layout(**_PLOTLY_LAYOUT, showlegend=True, height=260)
            fig.update_traces(textfont_color="white")
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown('<div class="section-header">Risk Distribution</div>', unsafe_allow_html=True)
        if risk_counts:
            fig = px.bar(
                x=list(risk_counts.values()),
                y=list(risk_counts.keys()),
                orientation="h",
                color=list(risk_counts.keys()),
                color_discrete_map=_RISK_COLORS_MAP,
            )
            fig.update_layout(**_PLOTLY_LAYOUT, showlegend=False, height=260)
            st.plotly_chart(fig, use_container_width=True)

    with col3:
        st.markdown('<div class="section-header">Requests Over Time</div>', unsafe_allow_html=True)
        df_events = _events_to_df(events)
        if not df_events.empty and "timestamp" in df_events.columns:
            df_time = df_events.copy()
            df_time["ts_minute"] = pd.to_datetime(df_time["timestamp"]).dt.floor("1min")
            req_over_time = df_time.groupby("ts_minute").size().reset_index(name="count")
            fig = px.area(
                req_over_time,
                x="ts_minute",
                y="count",
                color_discrete_sequence=["#58a6ff"],
            )
            fig.update_layout(**_PLOTLY_LAYOUT, height=260)
            fig.update_traces(fill="tozeroy", line_color="#58a6ff", fillcolor="rgba(88,166,255,0.15)")
            st.plotly_chart(fig, use_container_width=True)

    # ---- Charts row 2 ----
    col4, col5 = st.columns(2)

    with col4:
        st.markdown('<div class="section-header">Top Attacking IPs</div>', unsafe_allow_html=True)
        ip_counts = count_by_field(alerts, "source_ip")
        top_ips = top_n(ip_counts, 8)
        if top_ips:
            ips, counts = zip(*top_ips)
            fig = px.bar(
                x=list(counts),
                y=list(ips),
                orientation="h",
                color_discrete_sequence=["#ff4d4d"],
            )
            fig.update_layout(**_PLOTLY_LAYOUT, showlegend=False, height=240)
            st.plotly_chart(fig, use_container_width=True)

    with col5:
        st.markdown('<div class="section-header">Most Targeted Endpoints</div>', unsafe_allow_html=True)
        ep_counts = count_by_field(alerts, "endpoint")
        top_eps = top_n(ep_counts, 8)
        if top_eps:
            eps, counts = zip(*top_eps)
            fig = px.bar(
                x=list(counts),
                y=[truncate(e, 30) for e in eps],
                orientation="h",
                color_discrete_sequence=["#f0c040"],
            )
            fig.update_layout(**_PLOTLY_LAYOUT, showlegend=False, height=240)
            st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    # ---- Recent Alerts Table ----
    st.markdown('<div class="section-header">Recent Alerts</div>', unsafe_allow_html=True)
    _show_alerts_table(alerts[:20], show_status_update=True)


def _show_welcome():
    st.markdown("""
    <div style="background:#161b22;border:1px solid #30363d;border-radius:12px;padding:32px;margin-top:20px;">
      <h3 style="color:#58a6ff;margin-top:0;">Welcome to Web Application Attack Detector</h3>
      <p style="color:#8b949e;">This platform analyzes HTTP web-server logs to detect, investigate, and report on suspicious web attack patterns.</p>
      <h4 style="color:#e6edf3;">Quick Start</h4>
      <ol style="color:#8b949e;">
        <li>Click <b style="color:#58a6ff;">🎭 Demo</b> in the sidebar to load sample attack data</li>
        <li>Or upload your own Apache/Nginx access log or CSV file</li>
        <li>Navigate through the pages using the sidebar menu</li>
      </ol>
      <h4 style="color:#e6edf3;">Detected Attack Types</h4>
      <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:8px;">
        <span class="risk-badge badge-critical">SQL Injection</span>
        <span class="risk-badge badge-high">XSS</span>
        <span class="risk-badge badge-high">Path Traversal</span>
        <span class="risk-badge badge-critical">Command Injection</span>
        <span class="risk-badge badge-high">Auth Attacks</span>
        <span class="risk-badge badge-medium">Parameter Manipulation</span>
      </div>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Alerts page
# ---------------------------------------------------------------------------

def page_alerts():
    st.markdown("## 🚨 Alert Investigation")

    if not st.session_state.data_loaded:
        st.info("Load data first.")
        return

    alerts = st.session_state["alerts"]
    if not alerts:
        st.success("No alerts detected.")
        return

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        attack_types = ["All"] + sorted({a.get("attack_type", "") for a in alerts})
        sel_type = st.selectbox("Attack Type", attack_types, key="filter_type")
    with col2:
        risk_levels = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sel_risk = st.selectbox("Risk Level", risk_levels, key="filter_risk")
    with col3:
        ips = ["All"] + sorted({a.get("source_ip", "") for a in alerts})
        sel_ip = st.selectbox("Source IP", ips, key="filter_ip")

    filtered = alerts
    if sel_type != "All":
        filtered = [a for a in filtered if a.get("attack_type") == sel_type]
    if sel_risk != "All":
        filtered = [a for a in filtered if a.get("risk_level") == sel_risk]
    if sel_ip != "All":
        filtered = [a for a in filtered if a.get("source_ip") == sel_ip]

    st.caption(f"Showing {len(filtered)} of {len(alerts)} alerts")

    # If alert selected
    if st.session_state.get("selected_alert_id"):
        aid = st.session_state["selected_alert_id"]
        selected = next((a for a in alerts if a["alert_id"] == aid), None)
        if selected:
            _show_alert_detail(selected)
            if st.button("← Back to Alert List"):
                st.session_state["selected_alert_id"] = None
                st.rerun()
            return

    _show_alerts_table(filtered, show_status_update=True, show_investigate=True)


def _badge(level: str) -> str:
    cls = f"badge-{level.lower()}"
    return f'<span class="risk-badge {cls}">{level}</span>'


def _show_alerts_table(alerts: List[Dict], show_status_update: bool = False, show_investigate: bool = False):
    if not alerts:
        st.info("No alerts to display.")
        return

    level_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    sorted_alerts = sorted(
        alerts,
        key=lambda a: (level_order.get(a.get("risk_level", "LOW"), 0), a.get("risk_score", 0)),
        reverse=True,
    )

    for alert in sorted_alerts[:config.PAGE_SIZE]:
        risk = alert.get("risk_level", "LOW")
        badge = get_risk_badge(risk)
        with st.expander(
            f"{badge} [{risk}] {alert.get('attack_type')} | {alert.get('source_ip')} → {truncate(alert.get('endpoint',''), 40)}",
            expanded=False,
        ):
            col1, col2, col3 = st.columns([2, 2, 2])
            with col1:
                st.markdown(f"**Time:** {format_timestamp(alert.get('timestamp', ''))}")
                st.markdown(f"**Source IP:** `{alert.get('source_ip', '')}`")
                st.markdown(f"**Endpoint:** `{truncate(alert.get('endpoint',''), 50)}`")
            with col2:
                st.markdown(f"**Rule:** `{alert.get('rule_id', '')}`")
                st.markdown(f"**Confidence:** {alert.get('confidence', 0)}%")
                st.markdown(f"**Risk Score:** {alert.get('risk_score', 0)}/100")
            with col3:
                current_status = alert.get("status", "Open")
                st.markdown(f"**Status:** {current_status}")
                if show_status_update:
                    new_status = st.selectbox(
                        "Update Status",
                        ["Open", "Investigating", "Resolved"],
                        index=["Open", "Investigating", "Resolved"].index(current_status),
                        key=f"status_{alert['alert_id']}",
                        label_visibility="collapsed",
                    )
                    if new_status != current_status:
                        get_db().update_alert_status(alert["alert_id"], new_status)
                        alert["status"] = new_status

            st.markdown("**Evidence:**")
            st.markdown(
                f'<div class="evidence-box">{alert.get("evidence", "")}</div>',
                unsafe_allow_html=True,
            )
            st.markdown(f"*{alert.get('explanation', '')}*")

            if show_investigate:
                if st.button("🔬 Investigate", key=f"inv_{alert['alert_id']}"):
                    st.session_state["selected_alert_id"] = alert["alert_id"]
                    st.session_state.page = "Alerts"
                    st.rerun()


def _show_alert_detail(alert: Dict):
    risk = alert.get("risk_level", "LOW")
    badge_html = _badge(risk)
    score = alert.get("risk_score", 0)

    st.markdown(f"""
    <div class="alert-card alert-card-{risk.lower()}">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div>
          <span style="font-size:1.1rem;font-weight:700;color:#e6edf3;">{alert.get('attack_type')}</span>
          &nbsp;&nbsp;{badge_html}
        </div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#8b949e;">
          {alert.get('alert_id','')[:16]}
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### 📋 Alert Details")
        details = {
            "Alert ID": alert.get("alert_id", "")[:16] + "…",
            "Timestamp": format_timestamp(alert.get("timestamp", "")),
            "Source IP": alert.get("source_ip", ""),
            "HTTP Method": alert.get("method", ""),
            "Endpoint": alert.get("endpoint", ""),
            "Status Code": alert.get("status_code", ""),
            "Parameter": truncate(alert.get("parameter", ""), 50),
        }
        for k, v in details.items():
            st.markdown(f"**{k}:** `{v}`")

    with col2:
        st.markdown("#### 🎯 Detection Info")
        det_details = {
            "Risk Level": risk,
            "Risk Score": f"{score}/100",
            "Confidence": f"{alert.get('confidence', 0)}%",
            "Rule ID": alert.get("rule_id", ""),
            "Rule Description": alert.get("rule_description", ""),
            "Status": alert.get("status", "Open"),
        }
        for k, v in det_details.items():
            st.markdown(f"**{k}:** `{v}`")

    st.markdown("---")
    st.markdown("#### 🔎 Evidence")
    st.markdown(
        f'<div class="evidence-box">{alert.get("evidence", "N/A")}</div>',
        unsafe_allow_html=True,
    )

    st.markdown("#### ❓ Why Was This Detected?")
    st.info(alert.get("explanation", ""))

    st.markdown("#### 🔬 Raw Request")
    st.code(alert.get("raw_request", ""), language="text")

    st.markdown("#### ✅ Recommended Investigation Steps")
    action = alert.get("recommended_action", "")
    if action:
        for line in action.strip().splitlines():
            if line.strip():
                st.markdown(line)

    st.markdown("---")
    new_status = st.selectbox(
        "Update Alert Status",
        ["Open", "Investigating", "Resolved"],
        index=["Open", "Investigating", "Resolved"].index(alert.get("status", "Open")),
        key=f"detail_status_{alert['alert_id']}",
    )
    if new_status != alert.get("status"):
        get_db().update_alert_status(alert["alert_id"], new_status)
        alert["status"] = new_status
        st.success(f"Status updated to {new_status}")


# ---------------------------------------------------------------------------
# Attack Timeline page
# ---------------------------------------------------------------------------

def page_timeline():
    st.markdown("## ⏱️ Attack Timeline")

    if not st.session_state.data_loaded:
        st.info("Load data first.")
        return

    alerts = st.session_state["alerts"]
    if not alerts:
        st.info("No alerts to display.")
        return

    df = pd.DataFrame(alerts)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        attack_types = ["All"] + sorted(df["attack_type"].unique().tolist())
        sel_type = st.selectbox("Attack Type", attack_types, key="tl_type")
    with col2:
        risk_levels = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sel_risk = st.selectbox("Risk Level", risk_levels, key="tl_risk")
    with col3:
        ips = ["All"] + sorted(df["source_ip"].unique().tolist())
        sel_ip = st.selectbox("Source IP", ips, key="tl_ip")

    fdf = df.copy()
    if sel_type != "All":
        fdf = fdf[fdf["attack_type"] == sel_type]
    if sel_risk != "All":
        fdf = fdf[fdf["risk_level"] == sel_risk]
    if sel_ip != "All":
        fdf = fdf[fdf["source_ip"] == sel_ip]

    if fdf.empty:
        st.info("No alerts match the selected filters.")
        return

    # Scatter timeline
    fig = px.scatter(
        fdf,
        x="timestamp",
        y="attack_type",
        color="risk_level",
        color_discrete_map=_RISK_COLORS_MAP,
        size="risk_score",
        size_max=18,
        hover_data=["source_ip", "endpoint", "confidence", "evidence"],
        title="Attack Timeline",
    )
    fig.update_layout(**_PLOTLY_LAYOUT, height=400, title_font_color="#58a6ff")
    st.plotly_chart(fig, use_container_width=True)

    # Tabular timeline
    st.markdown('<div class="section-header">Timeline Events</div>', unsafe_allow_html=True)
    tbl = fdf[["timestamp", "risk_level", "attack_type", "source_ip", "endpoint", "evidence"]].copy()
    tbl["timestamp"] = tbl["timestamp"].dt.strftime("%H:%M:%S")
    tbl["evidence"] = tbl["evidence"].apply(lambda x: truncate(str(x), 60))
    st.dataframe(
        tbl.sort_values("timestamp"),
        use_container_width=True,
        hide_index=True,
    )


# ---------------------------------------------------------------------------
# IP Investigation page
# ---------------------------------------------------------------------------

def page_ip_investigation():
    st.markdown("## 🔎 IP Investigation")

    if not st.session_state.data_loaded:
        st.info("Load data first.")
        return

    alerts = st.session_state["alerts"]
    events = st.session_state["events"]

    all_ips = sorted({a.get("source_ip", "") for a in alerts})
    if not all_ips:
        st.info("No suspicious IPs found.")
        return

    col1, col2 = st.columns([2, 4])
    with col1:
        ip = st.selectbox("Select IP to investigate", all_ips, key="inv_ip")
    with col2:
        ip_input = st.text_input("Or enter IP manually", placeholder="192.168.1.20", key="inv_ip_manual")
        if ip_input.strip():
            ip = ip_input.strip()

    if not ip:
        return

    ip_alerts = [a for a in alerts if a.get("source_ip") == ip]
    ip_events = [e for e in events if e.get("source_ip") == ip]

    risk_score = compute_ip_risk_score(ip_alerts)
    attack_types = count_by_field(ip_alerts, "attack_type")
    endpoints = list({a.get("endpoint") for a in ip_alerts})

    ts_list = [
        a["timestamp"] for a in ip_alerts
        if a.get("timestamp")
    ]
    if ts_list:
        def _to_dt(t):
            if isinstance(t, datetime):
                return t
            try:
                from datetime import datetime as dt
                return dt.fromisoformat(str(t)[:19])
            except Exception:
                return datetime.utcnow()
        dt_list = [_to_dt(t) for t in ts_list]
        first_seen = min(dt_list).strftime("%Y-%m-%d %H:%M:%S")
        last_seen = max(dt_list).strftime("%Y-%m-%d %H:%M:%S")
    else:
        first_seen = last_seen = "N/A"

    # IP summary card
    st.markdown(f"""
    <div style="background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin-bottom:16px;">
      <h3 style="color:#58a6ff;margin:0 0 12px 0;">🌐 {ip}</h3>
      <div style="display:flex;gap:24px;flex-wrap:wrap;">
        <div><div style="color:#8b949e;font-size:0.75rem;">TOTAL REQUESTS</div><div style="color:#e6edf3;font-size:1.3rem;font-weight:700;">{len(ip_events)}</div></div>
        <div><div style="color:#8b949e;font-size:0.75rem;">ALERTS</div><div style="color:#ff4d4d;font-size:1.3rem;font-weight:700;">{len(ip_alerts)}</div></div>
        <div><div style="color:#8b949e;font-size:0.75rem;">RISK SCORE</div><div style="color:#ff9900;font-size:1.3rem;font-weight:700;">{risk_score}/100</div></div>
        <div><div style="color:#8b949e;font-size:0.75rem;">FIRST SEEN</div><div style="color:#e6edf3;font-size:0.9rem;">{first_seen}</div></div>
        <div><div style="color:#8b949e;font-size:0.75rem;">LAST SEEN</div><div style="color:#e6edf3;font-size:0.9rem;">{last_seen}</div></div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Attack Types**")
        if attack_types:
            fig = px.pie(
                names=list(attack_types.keys()),
                values=list(attack_types.values()),
                color_discrete_sequence=_ATTACK_COLOR_SEQ,
                hole=0.4,
            )
            fig.update_layout(**_PLOTLY_LAYOUT, height=220)
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("**Targeted Endpoints**")
        for ep in endpoints[:8]:
            ep_count = sum(1 for a in ip_alerts if a.get("endpoint") == ep)
            st.markdown(f"`{truncate(ep, 45)}` — **{ep_count}** alert(s)")

    st.markdown('<div class="section-header">Related Alerts</div>', unsafe_allow_html=True)
    _show_alerts_table(ip_alerts, show_status_update=False, show_investigate=True)


# ---------------------------------------------------------------------------
# Endpoint Analysis page
# ---------------------------------------------------------------------------

def page_endpoint_analysis():
    st.markdown("## 🎯 Endpoint Analysis")

    if not st.session_state.data_loaded:
        st.info("Load data first.")
        return

    alerts = st.session_state["alerts"]
    events = st.session_state["events"]

    endpoints = sorted({a.get("endpoint", "") for a in alerts})
    if not endpoints:
        st.info("No endpoints with alerts found.")
        return

    ep = st.selectbox("Select Endpoint", endpoints, key="ep_select")

    ep_alerts = [a for a in alerts if a.get("endpoint") == ep]
    ep_events = [e for e in events if e.get("endpoint") == ep]

    rc = Counter(a.get("risk_level") for a in ep_alerts)
    ip_counts = count_by_field(ep_alerts, "source_ip")
    at_counts = count_by_field(ep_alerts, "attack_type")

    st.markdown(f"""
    <div style="background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin-bottom:16px;">
      <h3 style="color:#f0c040;margin:0 0 12px 0;">🎯 {ep}</h3>
      <div style="display:flex;gap:24px;flex-wrap:wrap;">
        <div><div style="color:#8b949e;font-size:0.75rem;">TOTAL REQUESTS</div><div style="color:#e6edf3;font-size:1.3rem;font-weight:700;">{len(ep_events)}</div></div>
        <div><div style="color:#8b949e;font-size:0.75rem;">ALERTS</div><div style="color:#ff4d4d;font-size:1.3rem;font-weight:700;">{len(ep_alerts)}</div></div>
        <div><div style="color:#8b949e;font-size:0.75rem;">CRITICAL</div><div style="color:#ff4d4d;font-size:1.3rem;font-weight:700;">{rc.get('CRITICAL',0)}</div></div>
        <div><div style="color:#8b949e;font-size:0.75rem;">HIGH</div><div style="color:#ff9900;font-size:1.3rem;font-weight:700;">{rc.get('HIGH',0)}</div></div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        if at_counts:
            fig = px.bar(
                x=list(at_counts.keys()),
                y=list(at_counts.values()),
                color=list(at_counts.keys()),
                color_discrete_sequence=_ATTACK_COLOR_SEQ,
                title="Attack Types",
            )
            fig.update_layout(**_PLOTLY_LAYOUT, height=250, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        if ip_counts:
            top_ips = top_n(ip_counts, 8)
            ips_l, cnts_l = zip(*top_ips)
            fig = px.bar(
                x=list(cnts_l),
                y=list(ips_l),
                orientation="h",
                color_discrete_sequence=["#ff4d4d"],
                title="Top Attacking IPs",
            )
            fig.update_layout(**_PLOTLY_LAYOUT, height=250, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

    st.markdown('<div class="section-header">Alerts on this Endpoint</div>', unsafe_allow_html=True)
    _show_alerts_table(ep_alerts, show_status_update=True)


# ---------------------------------------------------------------------------
# Log Analysis page
# ---------------------------------------------------------------------------

def page_log_analysis():
    st.markdown("## 📋 Log Analysis")

    if not st.session_state.data_loaded:
        st.info("Load data first.")
        return

    events = st.session_state["events"]
    df = _events_to_df(events)

    total_ev = st.session_state.get("total_events_count", len(events))
    st.markdown(f"**{total_ev:,} total events processed** (showing sample preview)")

    # Search
    search = st.text_input("🔍 Search events (IP, endpoint, user agent…)", key="ev_search")
    if search:
        mask = df.apply(lambda row: row.astype(str).str.contains(search, case=False).any(), axis=1)
        df = df[mask]

    # Status filter
    col1, col2 = st.columns(2)
    with col1:
        methods = ["All"] + sorted(df["method"].unique().tolist() if "method" in df.columns else [])
        sel_method = st.selectbox("HTTP Method", methods, key="ev_method")
    with col2:
        status_opts = ["All"] + sorted(df["status_code"].astype(str).unique().tolist() if "status_code" in df.columns else [])
        sel_status = st.selectbox("Status Code", status_opts, key="ev_status")

    if sel_method != "All" and "method" in df.columns:
        df = df[df["method"] == sel_method]
    if sel_status != "All" and "status_code" in df.columns:
        df = df[df["status_code"].astype(str) == sel_status]

    display_cols = ["timestamp", "source_ip", "method", "endpoint", "status_code", "user_agent"]
    display_cols = [c for c in display_cols if c in df.columns]

    st.dataframe(
        df[display_cols].head(500),
        use_container_width=True,
        hide_index=True,
    )


def _events_to_df(events: List[Dict]) -> pd.DataFrame:
    if not events:
        return pd.DataFrame()
    df = pd.DataFrame(events)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


# ---------------------------------------------------------------------------
# Reports page
# ---------------------------------------------------------------------------

def page_reports():
    st.markdown("## 📄 Security Report Generation")

    if not st.session_state.data_loaded:
        st.info("Load data first.")
        return

    events = st.session_state["events"]
    alerts = st.session_state["alerts"]
    campaigns = st.session_state["campaigns"]

    st.markdown("Generate a comprehensive PDF security report from the current analysis.")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"**Events:** {len(events)}")
        st.markdown(f"**Alerts:** {len(alerts)}")
        st.markdown(f"**Campaigns:** {len(campaigns)}")

    if not REPORTLAB_AVAILABLE:
        st.error(
            "⚠️ ReportLab is not installed. Install it with: `pip install reportlab`"
        )
        return

    if st.button("📥 Generate PDF Report", type="primary"):
        with st.spinner("Generating PDF…"):
            path = generate_pdf_report(events, alerts, campaigns)

        if path and os.path.exists(path):
            with open(path, "rb") as f:
                pdf_bytes = f.read()
            st.download_button(
                label="⬇️ Download Security Report",
                data=pdf_bytes,
                file_name=os.path.basename(path),
                mime="application/pdf",
            )
            st.success(f"Report generated: {os.path.basename(path)}")
        else:
            st.error("PDF generation failed. Check logs for details.")

    # Campaign summary cards
    if campaigns:
        st.markdown("---")
        st.markdown("### 🔗 Attack Campaigns")
        for camp in campaigns:
            at_str = " | ".join(
                f"{at}: {c}" for at, c in camp.get("attack_types", {}).items()
            )
            eps_str = ", ".join(camp.get("affected_endpoints", [])[:5])
            risk = camp.get("risk_level", "LOW")
            badge = get_risk_badge(risk)
            st.markdown(f"""
            <div class="campaign-card">
              <div style="display:flex;justify-content:space-between;">
                <b style="color:#58a6ff;">{camp.get('campaign_id')}</b>
                <span>{badge} {risk}</span>
              </div>
              <div style="color:#8b949e;font-size:0.8rem;margin-top:8px;">
                <b style="color:#e6edf3;">IP:</b> {camp.get('source_ip')} &nbsp;|&nbsp;
                <b style="color:#e6edf3;">Alerts:</b> {camp.get('total_alerts')} &nbsp;|&nbsp;
                <b style="color:#e6edf3;">Duration:</b> {camp.get('duration_seconds')}s<br>
                <b style="color:#e6edf3;">Attacks:</b> {at_str}<br>
                <b style="color:#e6edf3;">Endpoints:</b> {eps_str}
              </div>
              <div style="color:#8b949e;font-size:0.75rem;margin-top:8px;">{camp.get('summary','')}</div>
            </div>
            """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Detection Rules page
# ---------------------------------------------------------------------------

def page_rules():
    st.markdown("## 📏 Detection Rules")
    st.markdown("Enable or disable individual detection rules. Changes apply on next analysis.")

    enabled = st.session_state.get("enabled_rules", {r.rule_id for r in ALL_RULES})

    attack_groups = {}
    for rule in ALL_RULES:
        attack_groups.setdefault(rule.attack_type, []).append(rule)

    severity_colors = {"CRITICAL": "#ff4d4d", "HIGH": "#ff9900", "MEDIUM": "#f0c040", "LOW": "#4caf50"}

    for attack_type, rules in attack_groups.items():
        st.markdown(f"#### {attack_type}")
        for rule in rules:
            col1, col2, col3, col4 = st.columns([1, 3, 1, 1])
            with col1:
                st.code(rule.rule_id, language=None)
            with col2:
                st.markdown(rule.description)
            with col3:
                color = severity_colors.get(rule.severity, "#888")
                st.markdown(f"<span style='color:{color};font-weight:600'>{rule.severity}</span>", unsafe_allow_html=True)
            with col4:
                is_enabled = rule.rule_id in enabled
                toggled = st.checkbox(
                    "Enabled",
                    value=is_enabled,
                    key=f"rule_{rule.rule_id}",
                    label_visibility="collapsed",
                )
                if toggled and rule.rule_id not in enabled:
                    enabled.add(rule.rule_id)
                elif not toggled and rule.rule_id in enabled:
                    enabled.discard(rule.rule_id)

        st.divider()

    st.session_state["enabled_rules"] = enabled
    st.caption(f"{len(enabled)} / {len(ALL_RULES)} rules enabled")


# ---------------------------------------------------------------------------
# Settings page
# ---------------------------------------------------------------------------

def page_settings():
    st.markdown("## ⚙️ Settings")
    st.markdown("Configure detection thresholds. Changes apply on next analysis run.")

    with st.form("settings_form"):
        st.markdown("#### Authentication Attack Detection")
        bt = st.number_input(
            "Brute-force threshold (failed logins)",
            min_value=2, max_value=100,
            value=st.session_state.get("brute_threshold", config.BRUTE_FORCE_THRESHOLD),
            step=1,
        )
        bw = st.number_input(
            "Brute-force time window (minutes)",
            min_value=1, max_value=60,
            value=st.session_state.get("brute_window", config.BRUTE_FORCE_WINDOW_MINUTES),
            step=1,
        )

        st.markdown("#### Correlation Engine")
        cw = st.number_input(
            "Campaign correlation window (minutes)",
            min_value=1, max_value=120,
            value=st.session_state.get("corr_window", config.CORRELATION_WINDOW_MINUTES),
            step=1,
        )

        submitted = st.form_submit_button("💾 Save Settings")
        if submitted:
            st.session_state["brute_threshold"] = int(bt)
            st.session_state["brute_window"] = int(bw)
            st.session_state["corr_window"] = int(cw)
            st.success("Settings saved. Re-run analysis to apply.")

    st.markdown("---")
    st.markdown("#### Database")
    col1, col2 = st.columns(2)
    with col1:
        db = get_db()
        st.metric("Events stored", db.count_events())
        st.metric("Alerts stored", db.count_alerts())
        st.metric("Campaigns stored", db.count_campaigns())
    with col2:
        if st.button("🗑️ Clear Database", type="secondary"):
            db.clear_all()
            st.session_state["events"] = []
            st.session_state["alerts"] = []
            st.session_state["campaigns"] = []
            st.session_state["data_loaded"] = False
            st.success("Database cleared.")
            st.rerun()


# ---------------------------------------------------------------------------
# Main router
# ---------------------------------------------------------------------------

def main():
    _init_state()
    _sidebar()

    page = st.session_state.get("page", "Dashboard")

    if page == "Dashboard":
        page_dashboard()
    elif page == "Log Analysis":
        page_log_analysis()
    elif page == "Alerts":
        page_alerts()
    elif page == "Attack Timeline":
        page_timeline()
    elif page == "IP Investigation":
        page_ip_investigation()
    elif page == "Endpoint Analysis":
        page_endpoint_analysis()
    elif page == "Reports":
        page_reports()
    elif page == "Detection Rules":
        page_rules()
    elif page == "Settings":
        page_settings()


if __name__ == "__main__":
    main()
