# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""
src/report/report_generator.py

Template-free report generator for SOC-Log-Analyzer.
- Generates an HTML report (no Jinja2 templates)
- Embeds chart images as Base64 so the HTML/PDF is self-contained
- Optionally generates a PDF using pdfkit/wkhtmltopdf (if installed)
- Produces a small JSON/text summary and returns metadata for downstream use

Design goals:
- Production-ready: clear logging, robust error handling, minimal external deps
- Safe defaults: skip PDF generation if pdfkit or wkhtmltopdf not available
- Flexible: accepts raw pandas DataFrame, detector results, and chart paths

Usage:
from report.report_generator import generate_full_report
result = generate_full_report(parsed_df=df, detectors_results=detectors_results, chart_paths=chart_paths, output_dir=Path('output'))

"""

import os
import base64
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any
import json

import pandas as pd

try:
    import pdfkit
    _HAS_PDFKIT = True
except Exception:
    pdfkit = None
    _HAS_PDFKIT = False

logger = logging.getLogger("report_generator")


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
        return str(v)
    except Exception:
        return ""


def _build_summary(df: pd.DataFrame, detectors_results: Optional[List[Any]] = None, stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a concise executive summary (dict) from the parsed DataFrame and detectors results."""
    summary: Dict[str, Any] = {}

    summary["total_logs"] = int(len(df))

    # Timespan
    if "TimeCreated" in df.columns:
        times = pd.to_datetime(df["TimeCreated"], errors="coerce")
        times = times.dropna()
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
        if host_col in df.columns:
            summary["unique_hosts"] = int(df[host_col].nunique(dropna=True))
            break
    else:
        summary["unique_hosts"] = 0

    # Top EventIDs
    if "EventID" in df.columns:
        ev_counts = df["EventID"].value_counts().head(10)
        summary["top_event_ids"] = ev_counts.to_dict()
    else:
        summary["top_event_ids"] = {}

    # Top Users (try common column names)
    user_cols = [c for c in ("TargetUserName", "SubjectUserName", "AccountName", "TargetUser", "UserName") if c in df.columns]
    if user_cols:
        # prefer TargetUserName then SubjectUserName
        uc = user_cols[0]
        summary["top_users"] = df[uc].value_counts().head(10).to_dict()
    else:
        summary["top_users"] = {}

    # Detection summary
    if detectors_results:
        # detectors_results is expected to be a list of dict-like alerts or strings
        summary["alerts_count"] = len(detectors_results)
        # try to build severity counts if alerts expose 'severity' key
        sev_counts: Dict[str, int] = {}
        for a in detectors_results:
            if isinstance(a, dict) and a.get("severity"):
                sev = str(a.get("severity"))
            else:
                # fallback - put all into 'info' bucket
                sev = "info"
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        summary["alerts_by_severity"] = sev_counts
    else:
        summary["alerts_count"] = 0
        summary["alerts_by_severity"] = {}

    # pass-through stats if provided
    if stats:
        summary["stats"] = stats

    return summary


def _generate_html_report(summary: Dict[str, Any], charts_data_uris: List[Dict[str, str]], metadata: Dict[str, Any], generated_at: Optional[str] = None) -> str:
    """Return HTML string for the report. charts_data_uris: list of {'title': str, 'data_uri': str} dicts."""
    if not generated_at:
        generated_at = datetime.utcnow().isoformat() + "Z"

    # Minimal, clean CSS for readability (responsive images)
    css = """
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; margin: 20px; color: #111; }
    .container { max-width: 1100px; margin: 0 auto; }
    h1 { font-size: 24px; margin-bottom: 0; }
    .meta { color: #666; margin-top: 4px; margin-bottom: 20px; }
    .kpis { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:18px; }
    .kpi { background:#f7f9fc; padding:12px; border-radius:8px; min-width:140px; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }
    table { border-collapse: collapse; width:100%; margin-bottom:18px; }
    th, td { text-align:left; padding:8px; border-bottom:1px solid #eee; }
    .chart { margin:16px 0; text-align:center; }
    img.chart-img { width:100%; max-width:900px; height:auto; display:block; margin:0 auto; }
    .footer { margin-top:30px; font-size:12px; color:#666; }
    """

    # Build HTML
    html_parts = [
        "<!doctype html>",
        "<html>",
        "<head>",
        f"<meta charset='utf-8'>",
        f"<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>SOC Log Analysis Report</title>",
        f"<style>{css}</style>",
        "</head>",
        "<body>",
        "<div class='container'>",
        f"<h1>SOC Log Analysis Report</h1>",
        f"<div class='meta'>Generated: {generated_at} • Source: SOC-Log-Analyzer</div>",
        "<div class='kpis'>",
        f"<div class='kpi'><strong>Total logs</strong><div>{summary.get('total_logs', 0)}</div></div>",
        f"<div class='kpi'><strong>Time range</strong><div>{_safe_str(summary.get('start_time'))} → {_safe_str(summary.get('end_time'))}</div></div>",
        f"<div class='kpi'><strong>Unique hosts</strong><div>{summary.get('unique_hosts', 0)}</div></div>",
        f"<div class='kpi'><strong>Alerts</strong><div>{summary.get('alerts_count', 0)}</div></div>",
        "</div>",
    ]

    # Top event IDs
    top_evs = summary.get("top_event_ids", {})
    if top_evs:
        html_parts.append("<h2>Top Event IDs</h2>")
        html_parts.append("<table>")
        html_parts.append("<thead><tr><th>Event ID</th><th>Count</th></tr></thead>")
        html_parts.append("<tbody>")
        for ev, cnt in top_evs.items():
            html_parts.append(f"<tr><td>{_safe_str(ev)}</td><td>{_safe_str(cnt)}</td></tr>")
        html_parts.append("</tbody></table>")

    # Top users
    top_users = summary.get("top_users", {})
    if top_users:
        html_parts.append("<h2>Top Accounts</h2>")
        html_parts.append("<table>")
        html_parts.append("<thead><tr><th>Account</th><th>Count</th></tr></thead>")
        html_parts.append("<tbody>")
        for u, cnt in top_users.items():
            html_parts.append(f"<tr><td>{_safe_str(u)}</td><td>{_safe_str(cnt)}</td></tr>")
        html_parts.append("</tbody></table>")

    # Alerts summary
    if summary.get("alerts_count", 0) > 0:
        html_parts.append("<h2>Alerts Summary</h2>")
        html_parts.append("<table>")
        html_parts.append("<thead><tr><th>Severity</th><th>Count</th></tr></thead>")
        html_parts.append("<tbody>")
        for sev, cnt in summary.get("alerts_by_severity", {}).items():
            html_parts.append(f"<tr><td>{_safe_str(sev)}</td><td>{_safe_str(cnt)}</td></tr>")
        html_parts.append("</tbody></table>")

    # Charts
    if charts_data_uris:
        html_parts.append("<h2>Visualizations</h2>")
        for c in charts_data_uris:
            title = c.get("title") or "Chart"
            data_uri = c.get("data_uri")
            html_parts.append(f"<div class='chart'><h3>{title}</h3>")
            if data_uri:
                html_parts.append(f"<img class='chart-img' src='{data_uri}' alt='{title}' />")
            else:
                html_parts.append(f"<div>Chart unavailable</div>")
            html_parts.append("</div>")

    # Footer / metadata
    html_parts.append("<div class='footer'>")
    html_parts.append(f"Generated by SOC-Log-Analyzer • {_safe_str(metadata.get('project', 'unknown'))} \n")
    html_parts.append("</div>")

    html_parts.append("</div>")
    html_parts.append("</body></html>")

    return "\n".join(html_parts)


def generate_full_report(
    parsed_df: pd.DataFrame,
    detectors_results: Optional[List[Any]] = None,
    stats: Optional[Dict[str, Any]] = None,
    chart_paths: Optional[List[str]] = None,
    output_dir: Optional[Path] = Path("output"),
    anonymize: bool = False,
    wkhtmltopdf_path: Optional[str] = None,
    html_report_name: str = "log_analysis_report.html",
    pdf_report_name: str = "log_analysis_report.pdf",
    text_report_name: str = "log_summary.txt",
) -> Dict[str, Any]:
    """
    Main entrypoint to produce a template-free HTML (and optional PDF) report.

    Returns a dict with keys: out_dir, html_path, pdf_path (or None), text_report_path, summary
    """

    output_dir = Path(output_dir)
    _ensure_dir(output_dir)

    # Build executive summary
    summary = _build_summary(parsed_df, detectors_results, stats)

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

    # Build HTML
    metadata = {"project": "SOC-Log-Analyzer", "generated_at": datetime.utcnow().isoformat() + "Z"}
    html_str = _generate_html_report(summary, charts_data_uris, metadata, generated_at=metadata["generated_at"])

    html_path = output_dir / html_report_name
    try:
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_str)
        logger.info("HTML report written: %s", html_path)
    except Exception as e:
        logger.exception("Failed to write HTML report: %s", e)
        raise

    # Write JSON summary and text summary
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
            # Using the html string via a temp file is more robust for wkhtmltopdf
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
    }

    return result


if __name__ == "__main__":
    # Quick local smoke test when executed directly (non-production)
    logging.basicConfig(level=logging.INFO)
    sample_csv = Path("output/parsed_security_logs.csv")
    if not sample_csv.exists():
        logger.error("Sample CSV not found: %s. Please run the parser first.", sample_csv)
    else:
        df = pd.read_csv(sample_csv)
        out = generate_full_report(df, chart_paths=[], output_dir=Path("output/reports/test"))
        logger.info("Generated resources: %s", out)
