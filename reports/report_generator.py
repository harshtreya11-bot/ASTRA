"""
reports/report_generator.py - PDF security report using ReportLab
"""

import os
import logging
from datetime import datetime
from typing import List, Dict, Optional
from collections import Counter

logger = logging.getLogger(__name__)

try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True

    _DARK_BG = colors.HexColor("#0d1117")
    _HEADER_BG = colors.HexColor("#161b22")
    _ACCENT = colors.HexColor("#58a6ff")
    _CRITICAL = colors.HexColor("#ff4d4d")
    _HIGH = colors.HexColor("#ff9900")
    _MEDIUM = colors.HexColor("#f0c040")
    _LOW = colors.HexColor("#4caf50")
    _TEXT = colors.HexColor("#c9d1d9")
    _BORDER = colors.HexColor("#30363d")
    _TABLE_ALT = colors.HexColor("#1c2128")

    _RISK_COLORS = {
        "CRITICAL": _CRITICAL,
        "HIGH": _HIGH,
        "MEDIUM": _MEDIUM,
        "LOW": _LOW,
    }

    def _risk_color(level: str):
        return _RISK_COLORS.get(level.upper(), colors.grey)

except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab not installed. PDF reports unavailable.")
    def _risk_color(level: str):
        return None

import config
from utils.helpers import format_timestamp, truncate


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def _build_styles():
    styles = getSampleStyleSheet()
    custom = {}

    custom["Title"] = ParagraphStyle(
        "CustomTitle",
        fontSize=22,
        leading=28,
        textColor=_ACCENT,
        spaceAfter=6,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )
    custom["Subtitle"] = ParagraphStyle(
        "CustomSubtitle",
        fontSize=11,
        leading=14,
        textColor=_TEXT,
        spaceAfter=4,
        alignment=TA_CENTER,
    )
    custom["SectionHeader"] = ParagraphStyle(
        "SectionHeader",
        fontSize=13,
        leading=16,
        textColor=_ACCENT,
        fontName="Helvetica-Bold",
        spaceBefore=14,
        spaceAfter=6,
        borderPadding=(4, 0, 4, 0),
    )
    custom["Body"] = ParagraphStyle(
        "Body",
        fontSize=9,
        leading=13,
        textColor=_TEXT,
        spaceAfter=4,
    )
    custom["Small"] = ParagraphStyle(
        "Small",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#8b949e"),
    )
    custom["Evidence"] = ParagraphStyle(
        "Evidence",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#e3b341"),
        fontName="Courier",
        backColor=colors.HexColor("#161b22"),
        borderPadding=(4, 6, 4, 6),
    )
    return custom


# ---------------------------------------------------------------------------
# Table helpers
# ---------------------------------------------------------------------------

def _header_row_style(cols: int):
    return [
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), _ACCENT),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_DARK_BG, _TABLE_ALT]),
        ("TEXTCOLOR", (0, 1), (-1, -1), _TEXT),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, _BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

def generate_pdf_report(
    events: List[Dict],
    alerts: List[Dict],
    campaigns: List[Dict],
    output_path: Optional[str] = None,
) -> Optional[str]:
    """
    Generate a PDF security report.
    Returns the output path if successful, None otherwise.
    """
    if not REPORTLAB_AVAILABLE:
        logger.error("ReportLab not available. Cannot generate PDF.")
        return None

    os.makedirs(config.REPORT_DIR, exist_ok=True)
    if not output_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(config.REPORT_DIR, f"security_report_{ts}.pdf")

    styles = _build_styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )
    story = []

    # ------------------------------------------------------------------ #
    # Cover
    # ------------------------------------------------------------------ #
    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph("WEB APPLICATION ATTACK DETECTOR", styles["Title"]))
    story.append(Paragraph("Security Analysis Report", styles["Subtitle"]))
    story.append(Spacer(1, 0.3 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=_ACCENT))
    story.append(Spacer(1, 0.3 * cm))

    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    story.append(Paragraph(f"Generated: {gen_time}", styles["Small"]))
    story.append(Paragraph(
        "CONFIDENTIAL – For authorized security personnel only",
        styles["Small"],
    ))
    story.append(Spacer(1, 1 * cm))

    # ------------------------------------------------------------------ #
    # Executive Summary
    # ------------------------------------------------------------------ #
    story.append(Paragraph("Executive Summary", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
    story.append(Spacer(1, 0.2 * cm))

    risk_counts = Counter(a.get("risk_level", "LOW") for a in alerts)
    attack_type_counts = Counter(a.get("attack_type") for a in alerts)
    suspicious_ips = {a["source_ip"] for a in alerts}
    total_requests = len(events)
    total_alerts = len(alerts)
    total_campaigns = len(campaigns)

    if events:
        timestamps = [e.get("timestamp") for e in events if e.get("timestamp")]
        if timestamps:
            try:
                # Handle both datetime objects and strings
                def to_dt(t):
                    if isinstance(t, datetime):
                        return t
                    from datetime import datetime as dt
                    try:
                        return dt.fromisoformat(str(t)[:19])
                    except Exception:
                        return datetime.utcnow()
                ts_list = [to_dt(t) for t in timestamps]
                analysis_start = min(ts_list).strftime("%Y-%m-%d %H:%M:%S")
                analysis_end = max(ts_list).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                analysis_start = analysis_end = "Unknown"
        else:
            analysis_start = analysis_end = "Unknown"
    else:
        analysis_start = analysis_end = "Unknown"

    summary_data = [
        ["Metric", "Value"],
        ["Analysis Period", f"{analysis_start} → {analysis_end}"],
        ["Total HTTP Requests", str(total_requests)],
        ["Total Alerts Generated", str(total_alerts)],
        ["Suspicious Source IPs", str(len(suspicious_ips))],
        ["Attack Campaigns Detected", str(total_campaigns)],
        ["Critical Alerts", str(risk_counts.get("CRITICAL", 0))],
        ["High Alerts", str(risk_counts.get("HIGH", 0))],
        ["Medium Alerts", str(risk_counts.get("MEDIUM", 0))],
        ["Low Alerts", str(risk_counts.get("LOW", 0))],
    ]

    t = Table(summary_data, colWidths=[8 * cm, 9 * cm])
    t.setStyle(TableStyle(_header_row_style(2)))
    story.append(t)
    story.append(Spacer(1, 0.5 * cm))

    # Narrative
    crit = risk_counts.get("CRITICAL", 0)
    high = risk_counts.get("HIGH", 0)
    narrative = (
        f"During the analysis period, {total_requests} HTTP requests were processed. "
        f"The detection engine identified {total_alerts} suspicious events from "
        f"{len(suspicious_ips)} unique source IP address(es). "
    )
    if crit > 0:
        narrative += (
            f"Of these, {crit} alert(s) were classified as CRITICAL risk, "
            f"requiring immediate attention. "
        )
    if high > 0:
        narrative += f"An additional {high} alert(s) were classified as HIGH risk. "
    if total_campaigns > 0:
        narrative += (
            f"Correlation analysis identified {total_campaigns} coordinated attack "
            f"campaign(s) suggesting targeted activity against this application."
        )
    story.append(Paragraph(narrative, styles["Body"]))
    story.append(Spacer(1, 0.5 * cm))

    # ------------------------------------------------------------------ #
    # Attack Summary
    # ------------------------------------------------------------------ #
    story.append(Paragraph("Attack Type Summary", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
    story.append(Spacer(1, 0.2 * cm))

    attack_data = [["Attack Type", "Alert Count", "Highest Risk", "Affected Endpoints"]]
    for attack_type, count in sorted(attack_type_counts.items(), key=lambda x: -x[1]):
        type_alerts = [a for a in alerts if a.get("attack_type") == attack_type]
        risk_levels = [a.get("risk_level", "LOW") for a in type_alerts]
        level_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        highest = max(risk_levels, key=lambda l: level_order.get(l, 0))
        endpoints = list({a.get("endpoint", "") for a in type_alerts})[:3]
        ep_str = ", ".join(endpoints)
        attack_data.append([attack_type, str(count), highest, truncate(ep_str, 40)])

    t = Table(attack_data, colWidths=[5 * cm, 3 * cm, 3 * cm, 6 * cm])
    t.setStyle(TableStyle(_header_row_style(4)))
    story.append(t)
    story.append(Spacer(1, 0.5 * cm))

    # ------------------------------------------------------------------ #
    # Top Suspicious Sources
    # ------------------------------------------------------------------ #
    story.append(Paragraph("Top Suspicious Source IPs", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
    story.append(Spacer(1, 0.2 * cm))

    ip_alert_counts = Counter(a["source_ip"] for a in alerts)
    ip_data = [["Source IP", "Alert Count", "Attack Types", "Highest Risk"]]
    for ip, cnt in ip_alert_counts.most_common(10):
        ip_alerts = [a for a in alerts if a["source_ip"] == ip]
        types = list({a.get("attack_type", "") for a in ip_alerts})
        risk_levels = [a.get("risk_level", "LOW") for a in ip_alerts]
        level_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        highest = max(risk_levels, key=lambda l: level_order.get(l, 0))
        ip_data.append([ip, str(cnt), truncate(", ".join(types), 30), highest])

    t = Table(ip_data, colWidths=[4 * cm, 3 * cm, 7 * cm, 3 * cm])
    t.setStyle(TableStyle(_header_row_style(4)))
    story.append(t)
    story.append(Spacer(1, 0.5 * cm))

    # ------------------------------------------------------------------ #
    # Attack Campaigns
    # ------------------------------------------------------------------ #
    if campaigns:
        story.append(Paragraph("Correlated Attack Campaigns", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
        story.append(Spacer(1, 0.2 * cm))

        for camp in campaigns[:10]:
            camp_data = [
                ["Campaign ID", camp.get("campaign_id", "")],
                ["Source IP", camp.get("source_ip", "")],
                ["Risk Level", camp.get("risk_level", "")],
                ["Risk Score", str(camp.get("risk_score", 0))],
                ["Total Alerts", str(camp.get("total_alerts", 0))],
                ["First Seen", format_timestamp(camp.get("first_seen", ""))],
                ["Last Seen", format_timestamp(camp.get("last_seen", ""))],
                ["Duration", f"{camp.get('duration_seconds', 0)}s"],
                ["Endpoints", truncate(", ".join(camp.get("affected_endpoints", [])[:5]), 60)],
            ]
            attack_types_str = ", ".join(
                f"{at}({c})" for at, c in camp.get("attack_types", {}).items()
            )
            camp_data.append(["Attack Types", truncate(attack_types_str, 60)])

            t = Table(camp_data, colWidths=[5 * cm, 12 * cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), _HEADER_BG),
                ("TEXTCOLOR", (0, 0), (0, -1), _ACCENT),
                ("TEXTCOLOR", (1, 0), (1, -1), _TEXT),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.3, _BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("BACKGROUND", (1, 0), (1, -1), _DARK_BG),
            ]))
            story.append(t)
            story.append(Paragraph(camp.get("summary", ""), styles["Small"]))
            story.append(Spacer(1, 0.4 * cm))

    # ------------------------------------------------------------------ #
    # Detailed Alerts (top 30 by risk)
    # ------------------------------------------------------------------ #
    story.append(PageBreak())
    story.append(Paragraph("Detailed Alert Analysis", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
    story.append(Spacer(1, 0.2 * cm))

    level_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    sorted_alerts = sorted(
        alerts,
        key=lambda a: (level_order.get(a.get("risk_level", "LOW"), 0), a.get("risk_score", 0)),
        reverse=True,
    )[:30]

    for i, alert in enumerate(sorted_alerts, 1):
        risk_col = _risk_color(alert.get("risk_level", "LOW"))
        items = [
            [f"Alert #{i}", f"{alert.get('risk_level', '')} | Score: {alert.get('risk_score', 0)} | {alert.get('attack_type', '')}"],
            ["Timestamp", format_timestamp(alert.get("timestamp", ""))],
            ["Source IP", alert.get("source_ip", "")],
            ["Endpoint", alert.get("endpoint", "")],
            ["Parameter", truncate(alert.get("parameter", ""), 50)],
            ["Rule", f"{alert.get('rule_id', '')} – {alert.get('rule_description', '')}"],
            ["Confidence", f"{alert.get('confidence', 0)}%"],
            ["Evidence", truncate(alert.get("evidence", ""), 80)],
        ]
        t = Table(items, colWidths=[4 * cm, 13 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), risk_col),
            ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
            ("BACKGROUND", (1, 0), (1, 0), _HEADER_BG),
            ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
            ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 1), (0, -1), _HEADER_BG),
            ("TEXTCOLOR", (0, 1), (0, -1), _ACCENT),
            ("TEXTCOLOR", (1, 1), (1, -1), _TEXT),
            ("BACKGROUND", (1, 1), (1, -1), _DARK_BG),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, _BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ]))
        explanation = alert.get("explanation", "")
        if explanation:
            story.append(KeepTogether([t, Paragraph(explanation, styles["Small"]), Spacer(1, 0.3 * cm)]))
        else:
            story.append(KeepTogether([t, Spacer(1, 0.3 * cm)]))

    # ------------------------------------------------------------------ #
    # Conclusion
    # ------------------------------------------------------------------ #
    story.append(PageBreak())
    story.append(Paragraph("Conclusion", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
    story.append(Spacer(1, 0.2 * cm))

    if not alerts:
        conclusion = (
            "Analysis of the provided HTTP log data did not identify any "
            "suspicious activity matching the configured detection rules. "
            "No actionable alerts were generated."
        )
    else:
        attack_list = ", ".join(sorted(set(a.get("attack_type", "") for a in alerts)))
        conclusion = (
            f"Analysis of {total_requests} HTTP requests identified {total_alerts} "
            f"suspicious event(s) from {len(suspicious_ips)} unique source IP(s). "
            f"Detected attack categories include: {attack_list}. "
        )
        if crit > 0:
            conclusion += (
                f"{crit} CRITICAL alert(s) were identified and require immediate "
                "investigation and remediation. "
            )
        if total_campaigns > 0:
            conclusion += (
                f"Correlation analysis identified {total_campaigns} coordinated "
                "attack campaign(s), suggesting active targeting of this application. "
            )
        conclusion += (
            "Recommended actions include reviewing parameterized query implementation, "
            "input validation, rate limiting, and IP-based access controls for the "
            "affected endpoints listed in this report."
        )

    story.append(Paragraph(conclusion, styles["Body"]))
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(
        "This report was generated by Web Application Attack Detector. "
        "All findings are based on pattern matching against supplied log data. "
        "Manual verification is recommended before taking enforcement action.",
        styles["Small"],
    ))

    # Build
    try:
        doc.build(story)
        logger.info("PDF report generated: %s", output_path)
        return output_path
    except Exception as e:
        logger.error("PDF generation failed: %s", e)
        return None
