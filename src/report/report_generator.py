# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""
src/report/report_generator.py

Production-ready, template-free report generator for SOC-Log-Analyzer.

(unchanged header docstring)
"""

import os
import base64
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
import json
from collections import defaultdict

import pandas as pd

try:
    import pdfkit
    _HAS_PDFKIT = True
except Exception:
    pdfkit = None
    _HAS_PDFKIT = False

logger = logging.getLogger("report_generator")


# -----------------------
# Filesystem helpers
# -----------------------
def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _file_to_data_uri(path: Path) -> Optional[str]:
    """Read file bytes and return a data URI (png/jpeg). Returns None on failure."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        mime = "image/png"
        if path.suffix.lower() in {".jpg", ".jpeg"}:
            mime = "image/jpeg"
        b64 = base64.b64encode(data).decode("utf-8")
        return f"data:{mime};base64,{b64}"
    except Exception as e:
        logger.warning("Failed to embed image %s: %s", path, e)
        return None


def _safe_str(v: Any) -> str:
    try:
        return "" if v is None else str(v)
    except Exception:
        return ""


# -----------------------
# Anonymization helpers
# -----------------------
def _anonymize_identity(name: Optional[str], mapping: Dict[str, str], prefix: str = "User") -> str:
    if not name or str(name).strip() in {"", "Unknown", "None"}:
        return "Unknown"
    s = str(name)
    if s not in mapping:
        mapping[s] = f"{prefix}-{len(mapping)+1}"
    return mapping[s]


def _anonymize_top_users(top_users: Dict[str, int], mapping: Dict[str, str]) -> Dict[str, int]:
    if not top_users:
        return {}
    anonymized: Dict[str, int] = {}
    for user, cnt in top_users.items():
        alias = _anonymize_identity(user, mapping, prefix="User")
        anonymized[alias] = anonymized.get(alias, 0) + int(cnt)
    return anonymized


def _anonymize_grouped_alerts(grouped_alerts: List[Dict[str, Any]], mapping: Dict[str, str]) -> List[Dict[str, Any]]:
    out = []
    for g in grouped_alerts or []:
        g2 = dict(g)
        g2["user"] = _anonymize_identity(g2.get("user"), mapping, prefix="User")
        out.append(g2)
    return out


# -----------------------
# Grouping & severity helpers (fallback if caller didn't supply groups)
# -----------------------
def _normalize_timestamp(alert: Dict[str, Any]) -> Optional[pd.Timestamp]:
    # common keys: 'timestamp', 'TimeCreated'
    val = alert.get("timestamp") or alert.get("TimeCreated")
    if not val:
        return None
    try:
        return pd.to_datetime(val, errors="coerce")
    except Exception:
        return None


def _infer_severity(alert: Dict[str, Any]) -> str:
    """Fallback severity if detectors didn't set one."""
    # Prefer provided severity
    s = alert.get("severity")
    if s:
        return str(s)

    # Heuristic fallback based on EventID/type
    event_id = alert.get("EventID")
    a_type = str(alert.get("type", "")).lower()

    if event_id == 4625 and int(alert.get("count", 1)) >= 5:
        return "Critical"
    if event_id == 4720:
        return "Critical"
    if event_id == 4672:
        return "High"
    if "unusual logon time" in a_type:
        return "Medium"
    if "account lockout" in a_type:
        return "High"
    return "Low"


def _group_alerts_fallback(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    If the caller did not pass grouped_alerts, we compute groups here.
    Group by (type, user, severity). Track count, first_seen, last_seen, EventID.
    """
    grouped = defaultdict(lambda: {
        "type": None,
        "user": None,
        "severity": None,
        "count": 0,
        "first_seen": None,
        "last_seen": None,
        "EventID": None
    })

    for alert in alerts or []:
        if not isinstance(alert, dict):
            continue

        a_type = alert.get("type", "Alert")
        user = alert.get("user") or alert.get("TargetUserName") or "Unknown"
        sev = _infer_severity(alert)
        event_id = alert.get("EventID")
        ts = _normalize_timestamp(alert)

        key = (a_type, user, sev)
        g = grouped[key]
        if g["count"] == 0:
            g["type"] = a_type
            g["user"] = user
            g["severity"] = sev
            g["EventID"] = event_id

        g["count"] += 1
        if ts is not None:
            if g["first_seen"] is None or ts < g["first_seen"]:
                g["first_seen"] = ts
            if g["last_seen"] is None or ts > g["last_seen"]:
                g["last_seen"] = ts

    # ISOify timestamps
    out = []
    for g in grouped.values():
        if isinstance(g["first_seen"], pd.Timestamp):
            g["first_seen"] = g["first_seen"].isoformat()
        if isinstance(g["last_seen"], pd.Timestamp):
            g["last_seen"] = g["last_seen"].isoformat()
        out.append(g)
    return out


def _compute_severity_counts(grouped_alerts: List[Dict[str, Any]], raw_alerts: Optional[List[Dict[str, Any]]]) -> Dict[str, int]:
    """
    Severity counts:
    - Prefer grouped_alerts (count-weighted).
    - Fallback to raw_alerts (per-alert).
    """
    counts: Dict[str, int] = {}
    if grouped_alerts:
        for g in grouped_alerts:
            sev = str(g.get("severity", "Unknown"))
            counts[sev] = counts.get(sev, 0) + int(g.get("count", 1))
        return counts

    # fallback if no groups provided
    for a in raw_alerts or []:
        sev = str(a.get("severity") or _infer_severity(a))
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# -----------------------
# Summary builder
# -----------------------
def _build_summary(
    df: pd.DataFrame,
    detectors_results: Optional[List[Any]] = None,
    stats: Optional[Dict[str, Any]] = None,
    grouped_alerts: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Build a concise executive summary (dict) from the parsed DataFrame and detector outputs.""" 
    summary: Dict[str, Any] = {}

    summary["total_logs"] = int(len(df) if df is not None else 0)

    # Timespan
    if df is not None and "TimeCreated" in df.columns:
        times = pd.to_datetime(df["TimeCreated"], errors="coerce").dropna()
        if len(times) > 0:
            summary["start_time"] = times.min().isoformat()
            summary["end_time"] = times.max().isoformat()
            summary["duration_seconds"] = int((times.max() - times.min()).total_seconds())
        else:
            summary["start_time"] = None
            summary["end_time"] = None
            summary["duration_seconds"] = 0
    else:
        summary["start_time"] = None
        summary["end_time"] = None
        summary["duration_seconds"] = 0

    # Hosts
    for host_col in ("Computer", "Host", "Hostname"):
        if df is not None and host_col in df.columns:
            summary["unique_hosts"] = int(df[host_col].nunique(dropna=True))
            break
    else:
        summary["unique_hosts"] = 0

    # Top EventIDs
    if df is not None and "EventID" in df.columns:
        ev_counts = df["EventID"].value_counts().head(10)
        summary["top_event_ids"] = {int(k): int(v) for k, v in ev_counts.to_dict().items()}
    else:
        summary["top_event_ids"] = {}

    # Top Users (common columns)
    user_cols = [c for c in ("TargetUserName", "SubjectUserName", "AccountName", "TargetUser", "UserName") if df is not None and c in df.columns]
    if user_cols and df is not None:
        uc = user_cols[0]
        vc = df[uc].value_counts().head(10)
        # normalize to str keys
        summary["top_users"] = {str(k): int(v) for k, v in vc.to_dict().items()}
    else:
        summary["top_users"] = {}

    # Detections
    total_alerts = len(detectors_results or [])
    summary["alerts_count"] = total_alerts

    # Severity counts (prefer grouped)
    sev_counts = _compute_severity_counts(grouped_alerts or [], detectors_results or [])
    summary["alerts_by_severity"] = sev_counts

    # pass-through stats if provided
    if stats:
        summary["stats"] = stats

    return summary


# -----------------------
# HTML rendering helpers
# -----------------------
def _severity_badge_html(sev: str) -> str:
    """Small colored badge for severity."""
    s = (sev or "").lower()
    color = "#9ca3af"  # gray (Unknown/Info)
    if s in ("critical",):
        color = "#dc2626"  # red-600
    elif s in ("high",):
        color = "#ea580c"  # orange-600
    elif s in ("medium",):
        color = "#d97706"  # amber-600
    elif s in ("low",):
        color = "#2563eb"  # blue-600
    return f"<span style='display:inline-block;padding:2px 8px;border-radius:12px;background:{color};color:white;font-size:12px'>{sev}</span>"


def _generate_html_report(
    summary: Dict[str, Any],
    charts_data_uris: List[Dict[str, str]],
    metadata: Dict[str, Any],
    detectors_results: Optional[List[Dict[str, Any]]] = None,
    grouped_alerts: Optional[List[Dict[str, Any]]] = None,
    generated_at: Optional[str] = None,
    report_type: str = "analyst",
) -> str:
    """Return HTML string for the report. Respects report_type: 'exec', 'analyst', 'raw'."""
    if not generated_at:
        generated_at = datetime.utcnow().isoformat() + "Z"

    # Basic CSS (unchanged)
    css = """
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; margin: 20px; color: #111; }
    .container { max-width: 1100px; margin: 0 auto; }
    h1 { font-size: 24px; margin-bottom: 0; }
    h2 { margin-top: 22px; }
    .meta { color: #666; margin-top: 4px; margin-bottom: 20px; }
    .kpis { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:18px; }
    .kpi { background:#f7f9fc; padding:12px; border-radius:8px; min-width:140px; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }
    table { border-collapse: collapse; width:100%; margin-bottom:18px; }
    th, td { text-align:left; padding:8px; border-bottom:1px solid #eee; vertical-align: top; }
    .muted { color:#666; }
    .chart { margin:16px 0; text-align:center; }
    img.chart-img { width:100%; max-width:900px; height:auto; display:block; margin:0 auto; }
    .footer { margin-top:30px; font-size:12px; color:#666; }
    .grid-2 { display:grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .pill { display:inline-block; padding:4px 10px; border-radius:999px; background:#eef2ff; }
    pre { background:#0b1020; color:#d1e7ff; padding:10px; border-radius:6px; overflow:auto; }
    """

    html_parts = [
        "<!doctype html>",
        "<html>",
        "<head>",
        "<meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<title>SOC Log Analysis Report</title>",
        f"<style>{css}</style>",
        "</head>",
        "<body>",
        "<div class='container'>",
        "<h1>SOC Log Analysis Report</h1>",
        f"<div class='meta'>Generated: {generated_at} • Source: SOC-Log-Analyzer</div>",
        "<div class='kpis'>",
        f"<div class='kpi'><strong>Total logs</strong><div>{summary.get('total_logs', 0)}</div></div>",
        f"<div class='kpi'><strong>Time range</strong><div>{_safe_str(summary.get('start_time'))} → {_safe_str(summary.get('end_time'))}</div></div>",
        f"<div class='kpi'><strong>Unique hosts</strong><div>{summary.get('unique_hosts', 0)}</div></div>",
        f"<div class='kpi'><strong>Alerts</strong><div>{summary.get('alerts_count', 0)}</div></div>",
        "</div>",
    ]

    # Severity breakdown (same for all)
    sev_counts = summary.get("alerts_by_severity", {}) or {}
    if sev_counts:
        html_parts.append("<h2>Severity Breakdown</h2>")
        html_parts.append("<table>")
        html_parts.append("<thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>")
        order = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]
        seen = set()
        for sev in order:
            if sev in sev_counts:
                html_parts.append(f"<tr><td>{_severity_badge_html(sev)}</td><td>{_safe_str(sev_counts[sev])}</td></tr>")
                seen.add(sev)
        for sev, cnt in sev_counts.items():
            if sev not in seen:
                html_parts.append(f"<tr><td>{_severity_badge_html(sev)}</td><td>{_safe_str(cnt)}</td></tr>")
        html_parts.append("</tbody></table>")

    # Top event IDs and Top users side by side
    top_evs = summary.get("top_event_ids", {})
    top_users = summary.get("top_users", {})
    if top_evs or top_users:
        html_parts.append("<div class='grid-2'>")
        # Top Event IDs
        html_parts.append("<div>")
        if top_evs:
            html_parts.append("<h2>Top Event IDs</h2><table><thead><tr><th>Event ID</th><th>Count</th></tr></thead><tbody>")
            for ev, cnt in top_evs.items():
                html_parts.append(f"<tr><td>{_safe_str(ev)}</td><td>{_safe_str(cnt)}</td></tr>")
            html_parts.append("</tbody></table>")
        else:
            html_parts.append("<h2>Top Event IDs</h2><div class='muted'>No data</div>")
        html_parts.append("</div>")

        # Top Accounts
        html_parts.append("<div>")
        if top_users:
            html_parts.append("<h2>Top Accounts</h2><table><thead><tr><th>Account</th><th>Count</th></tr></thead><tbody>")
            for u, cnt in top_users.items():
                html_parts.append(f"<tr><td>{_safe_str(u)}</td><td>{_safe_str(cnt)}</td></tr>")
            html_parts.append("</tbody></table>")
        else:
            html_parts.append("<h2>Top Accounts</h2><div class='muted'>No data</div>")
        html_parts.append("</div>")
        html_parts.append("</div>")  # grid-2

    # Grouped Alerts Summary handling by report_type
    if grouped_alerts:
        html_parts.append("<h2>Grouped Alerts Summary</h2>")
        html_parts.append("<table>")
        html_parts.append("<thead><tr><th>Alert Type</th><th>User</th><th>Severity</th><th>Count</th><th>First Seen</th><th>Last Seen</th></tr></thead>")
        html_parts.append("<tbody>")

        # Exec: show only top N relevant alerts (by severity then count)
        if report_type == "exec":
            weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
            rows = sorted(
                grouped_alerts,
                key=lambda g: (
                    -weight.get(str(g.get("severity", "Unknown")).title(), 0),
                    -int(g.get("count", 0) or 0)
                )
            )
            top_rows = rows[:7]
            for g in top_rows:
                html_parts.append(
                    "<tr>"
                    f"<td>{_safe_str(g.get('type','Alert'))}</td>"
                    f"<td>{_safe_str(g.get('user','Unknown'))}</td>"
                    f"<td>{_severity_badge_html(_safe_str(g.get('severity','Unknown')))}</td>"
                    f"<td>{_safe_str(g.get('count',1))}</td>"
                    f"<td>{_safe_str(g.get('first_seen','N/A'))}</td>"
                    f"<td>{_safe_str(g.get('last_seen','N/A'))}</td>"
                    "</tr>"
                )
            html_parts.append("</tbody></table>")
            html_parts.append("<div class='muted'>Showing top alerts only for executive summary. Full details in analyst report or appendix.</div>")
        elif report_type == "raw":
            # Raw: just dump all grouped rows plainly (for forensics)
            for g in grouped_alerts:
                html_parts.append(
                    "<tr>"
                    f"<td>{_safe_str(g.get('type','Alert'))}</td>"
                    f"<td>{_safe_str(g.get('user','Unknown'))}</td>"
                    f"<td>{_safe_str(g.get('severity','Unknown'))}</td>"
                    f"<td>{_safe_str(g.get('count',1))}</td>"
                    f"<td>{_safe_str(g.get('first_seen','N/A'))}</td>"
                    f"<td>{_safe_str(g.get('last_seen','N/A'))}</td>"
                    "</tr>"
                )
            html_parts.append("</tbody></table>")
        else:
            # Analyst: detailed table (same as previous behavior)
            for g in grouped_alerts:
                html_parts.append(
                    "<tr>"
                    f"<td>{_safe_str(g.get('type','Alert'))}</td>"
                    f"<td>{_safe_str(g.get('user','Unknown'))}</td>"
                    f"<td>{_severity_badge_html(_safe_str(g.get('severity','Unknown')))}</td>"
                    f"<td>{_safe_str(g.get('count',1))}</td>"
                    f"<td>{_safe_str(g.get('first_seen','N/A'))}</td>"
                    f"<td>{_safe_str(g.get('last_seen','N/A'))}</td>"
                    "</tr>"
                )
            html_parts.append("</tbody></table>")
    else:
        html_parts.append("<div class='muted'>No grouped alerts available.</div>")

    # Charts
    if charts_data_uris and report_type != "raw":
        html_parts.append("<h2>Visualizations</h2>")
        for c in charts_data_uris:
            title = c.get("title") or "Chart"
            data_uri = c.get("data_uri")
            html_parts.append(f"<div class='chart'><h3>{_safe_str(title)}</h3>")
            if data_uri:
                html_parts.append(f"<img class='chart-img' src='{data_uri}' alt='{_safe_str(title)}' />")
            else:
                html_parts.append("<div class='muted'>Chart unavailable</div>")
            html_parts.append("</div>")

    # Appendix (raw alerts) - only for analyst and raw (raw expects appendix)
    if detectors_results and report_type == "analyst":
        html_parts.append("<h2>Appendix: Full Raw Alerts</h2>")
        for i, alert in enumerate(detectors_results, 1):
            if not isinstance(alert, dict):
                html_parts.append(f"<div><strong>{i}. Alert</strong><br><pre>{_safe_str(alert)}</pre></div><hr>")
                continue
            html_parts.append(f"<div><strong>{i}. {_safe_str(alert.get('type','Alert'))}</strong><br>")
            for key, val in alert.items():
                if key == 'type':
                    continue
                if isinstance(val, (list, dict)):
                    try:
                        val_str = json.dumps(val, indent=2, default=str)
                    except Exception:
                        val_str = _safe_str(val)
                    html_parts.append(f"<strong>{_safe_str(key)}:</strong><pre>{val_str}</pre>")
                else:
                    html_parts.append(f"<strong>{_safe_str(key)}:</strong> {_safe_str(val)}<br>")
            html_parts.append("</div><hr>")
    elif detectors_results and report_type == "raw":
        # Raw: compact JSON appendix for download/forensics
        html_parts.append("<h2>Appendix: Raw Alerts (compact)</h2>")
        try:
            compact = json.dumps(detectors_results, indent=2, default=str)
            html_parts.append(f"<pre>{_safe_str(compact)}</pre>")
        except Exception:
            html_parts.append("<div class='muted'>Unable to render raw alerts.</div>")

    # Footer / metadata
    html_parts.append("<div class='footer'>")
    html_parts.append(f"Generated by SOC-Log-Analyzer • {_safe_str(metadata.get('project', 'unknown'))}")
    html_parts.append("</div>")

    html_parts.append("</div>")  # container
    html_parts.append("</body></html>")

    return "\n".join(html_parts)


# -----------------------
# Public API
# -----------------------
def generate_full_report(
    parsed_df: pd.DataFrame,
    detectors_results: Optional[List[Dict[str, Any]]] = None,
    stats: Optional[Dict[str, Any]] = None,
    chart_paths: Optional[List[str]] = None,
    output_dir: Optional[Path] = Path("output"),
    anonymize: bool = False,
    wkhtmltopdf_path: Optional[str] = None,
    html_report_name: str = "log_analysis_report.html",
    pdf_report_name: str = "log_analysis_report.pdf",
    text_report_name: str = "log_summary.txt",
    grouped_alerts: Optional[List[Dict[str, Any]]] = None,  # NEW: optional, but backward-compatible
    report_type: str = "analyst",
) -> Dict[str, Any]:
    """
    Main entrypoint to produce a template-free HTML (and optional PDF) report.

    Returns a dict with keys: out_dir, html_path, pdf_path (or None), text_report_path, summary, charts_included
    """
    report_type = (report_type or "analyst").lower()

    output_dir = Path(output_dir)
    _ensure_dir(output_dir)

    # Prepare chart data URIs
    charts_data_uris: List[Dict[str, str]] = []
    if chart_paths:
        for p in chart_paths:
            try:
                ppath = Path(p)
                if not ppath.exists():
                    logger.warning("Chart path does not exist: %s", p)
                    continue
                data_uri = _file_to_data_uri(ppath)
                charts_data_uris.append({"title": ppath.name, "data_uri": data_uri, "path": str(ppath)})
            except Exception as e:
                logger.exception("Failed to include chart %s: %s", p, e)

    # If grouped_alerts not supplied, build them from detectors_results
    if grouped_alerts is None and detectors_results:
        try:
            grouped_alerts = _group_alerts_fallback(detectors_results)
        except Exception:
            logger.exception("Failed to group alerts; proceeding without groups.")
            grouped_alerts = []

    # Build executive summary (uses grouped_alerts for severity counts)
    summary = _build_summary(parsed_df, detectors_results, stats, grouped_alerts)

    # Optional anonymization (top_users + grouped_alerts user field)
    if anonymize:
        alias_map: Dict[str, str] = {}
        summary["top_users"] = _anonymize_top_users(summary.get("top_users", {}), alias_map)
        grouped_alerts = _anonymize_grouped_alerts(grouped_alerts or [], alias_map)

    # HTML assembly (respect report_type)
    metadata = {"project": "SOC-Log-Analyzer", "generated_at": datetime.utcnow().isoformat() + "Z"}
    html_str = _generate_html_report(
        summary=summary,
        charts_data_uris=charts_data_uris,
        metadata=metadata,
        detectors_results=detectors_results,
        grouped_alerts=grouped_alerts,
        generated_at=metadata["generated_at"],
        report_type=report_type,
    )

    # Write HTML
    html_path = output_dir / html_report_name
    try:
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_str)
        logger.info("HTML report written: %s", html_path)
    except Exception as e:
        logger.exception("Failed to write HTML report: %s", e)
        raise

    # Write text summary (kept machine-readable for compatibility)
    summary_path = output_dir / (Path(text_report_name).name)
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("SOC Log Analysis Summary\n")
            f.write(json.dumps(summary, indent=2, default=str))
        logger.info("Text summary written: %s", summary_path)
    except Exception:
        logger.exception("Failed to write text summary")

    # Optionally produce PDF
    pdf_path = None
    if _HAS_PDFKIT:
        try:
            config = None
            if wkhtmltopdf_path:
                try:
                    config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
                except Exception:
                    logger.exception("Failed to configure pdfkit with wkhtmltopdf_path=%s", wkhtmltopdf_path)

            pdf_path = output_dir / pdf_report_name
            options = {"quiet": ""}
            pdfkit.from_file(str(html_path), str(pdf_path), options=options, configuration=config)
            logger.info("PDF report generated: %s", pdf_path)
        except Exception as e:
            logger.exception("Failed to generate PDF (pdfkit/wkhtmltopdf): %s", e)
            pdf_path = None
    else:
        logger.warning("pdfkit not available - skipping PDF generation. To enable PDF export, install pdfkit and wkhtmltopdf.")

    result = {
        "out_dir": str(output_dir),
        "html_path": str(html_path),
        "pdf_path": str(pdf_path) if pdf_path else None,
        "text_report_path": str(summary_path) if summary_path else None,
        "summary": summary,
        "charts_included": [c.get("path") for c in charts_data_uris],
        "report_type": report_type,
    }

    return result


# -----------------------
# Local ad-hoc test
# -----------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sample_csv = Path("output/parsed_security_logs.csv")
    if not sample_csv.exists():
        logger.error("Sample CSV not found: %s. Please run the parser first.", sample_csv)
    else:
        try:
            df = pd.read_csv(sample_csv)
        except Exception:
            df = pd.read_csv(sample_csv, low_memory=False)
        out = generate_full_report(df, chart_paths=[], output_dir=Path("output/reports/test"))
        logger.info("Generated resources: %s", out)
