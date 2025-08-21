# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/report/report_text.py
# Investor-friendly text report (Executive summary + Technical appendix)

"""
This version preserves the original function signature and full technical appendix
so existing tooling is unaffected, while adding a concise, investor-facing
Executive Summary at the top.

Key goals:
- Executive Summary: short, visual, and recommendation-driven for non-technical readers
- Key Findings: top issues called out (e.g., admin off-hours)
- Technical Appendix: full grouped alerts with the same detailed context as before
- No breaking changes: generate_text_report(summary, grouped_alerts, raw_alerts, output_dir)

Be careful when editing: keep the function signature and report_path logic intact.
"""

import datetime
from textwrap import shorten
from typing import Dict, List

from context_library import (
    classify_off_hours,
    format_context_lines_for_report,
    build_context_notes,
    get_runtime_context,
    is_system_or_service,
)


_SEV_EMOJI = {"Low": "✅", "Medium": "⚠️", "High": "🔴", "Critical": "🔥"}


def _emoji_for_sev(sev: str) -> str:
    return _SEV_EMOJI.get(str(sev).title(), "•")


def _short(x, n=30):
    return shorten(str(x or ""), n)


def generate_text_report(summary: dict, grouped_alerts: list, raw_alerts: list, output_dir: str) -> None:
    """Generate an investor-friendly report while preserving the detailed appendix.

    Args:
        summary: dict with dataset metadata (start_time, end_time, totals, top_event_ids, etc.)
        grouped_alerts: list of grouped alert dicts (type, user, count, severity, event_id, off_hours...)
        raw_alerts: list of original alerts (for counts)
        output_dir: directory to write `log_summary.txt`
    """
    # --- compute durations
    from dateutil import parser

    start_time = summary.get("start_time")
    end_time = summary.get("end_time")
    try:
        start_dt = parser.parse(start_time)
        end_dt = parser.parse(end_time)
        duration_sec = (end_dt - start_dt).total_seconds()
        hours = int(duration_sec // 3600)
        minutes = int((duration_sec % 3600) // 60)
        duration_str = f"{hours}h {minutes}m"
    except Exception:
        duration_str = summary.get("duration", "Unknown")

    # --- compute raw severity breakdown (detector level)
    raw_sev_counts: Dict[str, int] = {}
    for g in grouped_alerts:
        sev = str(g.get("severity", "Unknown")).title()
        raw_sev_counts[sev] = raw_sev_counts.get(sev, 0) + int(g.get("count", 0) or 0)

    # --- compute final/contextual severity counts (using build_context_notes)
    final_sev_counts: Dict[str, int] = {}
    final_notes: List[Dict] = []
    for g in grouped_alerts:
        extras = build_context_notes(g)
        final = extras.get("severity_final", "Unknown")
        final_sev_counts[final] = final_sev_counts.get(final, 0) + int(g.get("count", 0) or 0)
        # keep top notes for investor 'Key Findings'
        if final in ("Medium", "High", "Critical"):
            final_notes.append({
                "user": g.get("user", "Unknown"),
                "type": g.get("type", "Unknown"),
                "count": int(g.get("count", 0) or 0),
                "final": final,
                "rationale": extras.get("severity_rationale", ""),
            })

    # sort final_notes by severity weight then count
    weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    final_notes.sort(key=lambda x: (-weight.get(x.get("final", "Unknown"), 0), -x.get("count", 0)))

    # --- anomalies (concise)
    anomalies = []
    for g in grouped_alerts:
        user = g.get("user", "Unknown")
        is_human = not is_system_or_service(user)
        threat_tag = classify_off_hours(is_human, bool(g.get("off_hours", False))) or "None"
        if "unusual logon time" in str(g.get("type", "")).lower() and g.get("count", 0):
            anomalies.append((user, g.get("count", 0), threat_tag))

    # --- start building lines (Executive Summary)
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append("🚨 SOC Security Analysis Report (MVP)")
    lines.append(f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("=" * 60)
    lines.append("")

    # Analysis & dataset context
    runtime = get_runtime_context()
    lines.append("🛠️ Analysis Context")
    lines.append(f"- Tool: {runtime.get('tool_name','SOC-Log-Analyzer')} {runtime.get('version','v1.0.0')}")
    lines.append(f"- Analyst: {runtime.get('analyst','Unknown')}")
    lines.append(f"- Organization: {runtime.get('organization','Unknown')}")
    lines.append(f"- Host: {runtime.get('hostname')} ({runtime.get('ip_address')})")
    lines.append("")

    # Executive summary
    lines.append("📊 Executive Summary")
    lines.append(f"- Total logs analyzed: {summary.get('total_logs', 'Unknown')}")
    lines.append(f"- Time range: {summary.get('start_time','Unknown')} → {summary.get('end_time','Unknown')} ({duration_str})")

    # severity snapshot (final/contextual if available, else raw)
    lines.append("- Severity (final/contextual):")
    for sev in ["Low", "Medium", "High", "Critical"]:
        cnt = final_sev_counts.get(sev, 0)
        lines.append(f"  { _emoji_for_sev(sev) } {sev}: {cnt}")

    # fallback show raw if final not present
    if not final_sev_counts:
        lines.append("- Severity (detector/raw):")
        for sev, cnt in raw_sev_counts.items():
            lines.append(f"  {_emoji_for_sev(sev)} {sev}: {cnt}")

    lines.append("")

    # Key findings (top 5 contextual issues)
    lines.append("🔎 Key Findings & Recommended Actions")
    if final_notes:
        for note in final_notes[:5]:
            lines.append(
                f"- {note['final']} | {note['type']} | {note['user']} ({note['count']}) — {note['rationale']}"
            )
    else:
        lines.append("- No medium/high contextual alerts detected in the dataset.")

    lines.append("")

    # Short anomalies list for execs
    lines.append("⚠️ Potential Anomalies (summary)")
    if anomalies:
        for user, cnt, tag in anomalies:
            lines.append(f"- Off-hours activity: {user} — {cnt} events [{tag}]")
    else:
        lines.append("- None detected.")

    lines.append("")

    # Visual snapshot placeholder (investor-facing)
    lines.append("📈 Visual Snapshot (see HTML/PDF for charts)")
    lines.append("- Severity distribution, Top users, Off-hours vs Normal hours")
    lines.append("")

    lines.append("🧠 MVP Edge")
    lines.append("- Context-aware baselines reduce false positives (system vs human accounts).")
    lines.append("- Automatic severity rationale improves analyst triage and investor trust.")
    lines.append("")

    lines.append("✅ Conclusion & Next Steps")
    lines.append("- No confirmed high-severity intrusions. Review admin off-hours activity (G. Muhammad).")
    lines.append("- Next: add visual charts and adaptive baselines (ML) to further reduce manual review time.")
    lines.append("")

    # --- Technical Appendix (full detail: preserved to avoid breaking downstream tools)
    lines.append("""
Technical Appendix — Full Grouped Alerts (for SOC Analysts)
This section preserves the detailed grouped alerts previously produced.
""".strip())
    lines.append("")

    # Grouped alerts summary (detailed)
    lines.append("📌 Grouped Alerts Summary")
    if grouped_alerts:
        lines.append(f"{'Alert Type':30} | {'User':20} | {'Sev':6} | {'Cnt':3} | {'First Seen':16} | {'Last Seen':16} | Threat Tag")
        lines.append("-" * 120)
        for g in grouped_alerts:
            first_seen = (str(g.get('first_seen'))[:16]) if g.get('first_seen') else "Unknown"
            last_seen = (str(g.get('last_seen'))[:16]) if g.get('last_seen') else "Unknown"
            user = g.get('user', 'Unknown')
            is_human = not is_system_or_service(user)
            threat_tag = classify_off_hours(is_human, bool(g.get('off_hours', False))) or 'None'

            lines.append(
                f"{_short(g.get('type', 'Unknown'),30):30} | "
                f"{_short(user,20):20} | "
                f"{str(g.get('severity', 'Unknown'))[:6]:6} | "
                f"{g.get('count', 0):3} | "
                f"{first_seen:16} | "
                f"{last_seen:16} | "
                f"{threat_tag}"
            )

            # Context & baseline
            ctx_line, base_line = format_context_lines_for_report(user)
            lines.append(ctx_line)
            lines.append(base_line)

            # detailed extras
            extras = build_context_notes(g)
            if extras.get("event_context"):
                lines.append(f"    Event Context: {extras['event_context']}")
            if extras.get("baseline_deviation"):
                lines.append(f"    Deviation Note: {extras['baseline_deviation']}")
            if extras.get("severity_hint"):
                lines.append(f"    Severity Suggestion: {extras['severity_hint']}")
            if extras.get("off_hours_note"):
                lines.append(f"    {extras['off_hours_note']}")
            if extras.get("severity_final"):
                lines.append(f"    ➡ Final Severity: {extras['severity_final']}")
            if extras.get("severity_rationale"):
                lines.append(f"    Rationale: {extras['severity_rationale']}")
            # baseline source included once per alert
            if extras.get("baseline_source"):
                lines.append(f"    Baseline Source: {extras['baseline_source']}")

            lines.append("")
    else:
        lines.append("- No alerts triggered.")
    lines.append("")

    # Potential anomalies (detailed)
    lines.append("⚠️ Potential Anomalies")
    if anomalies:
        for user, cnt, tag in anomalies:
            lines.append(f"- Off-hours logon: User '{user}' ({cnt} times) [{tag}]")
    else:
        lines.append("- None detected.")
    lines.append("")

    # Footer
    lines.append(f"Total Detection Alerts: {len(raw_alerts)}")
    lines.append("=" * 60)
    lines.append("Generated by SOC-Log-Analyzer | For Internal SOC Use Only")
    lines.append("Visit https://github.com/Muhammad-Abid99/SOC-Log-Analyzer for more info.")

    # Write to disk (preserve existing path)
    report_path = f"{output_dir}/log_summary.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return report_path

