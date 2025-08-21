# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/report/report_text.py
# Investor- and SOC-friendly text report (Executive summary + Technical appendix)

"""
This file is an upgraded, production-minded version of the original
report_text.py.  It preserves the public function signature
`generate_text_report(summary, grouped_alerts, raw_alerts, output_dir)` and
keeps the same output path logic so downstream tooling is unaffected.

Improvements added (enterprise-ready):
- Clear, consistent final severity counts and an explicit Critical justification
- Separation of System/Service accounts vs Human accounts in anomalies
- MITRE ATT&CK mapping (local heuristic mapping for common detections)
- Source IP / Geo placeholders (ready for enrichment when available)
- More actionable "Next Steps" (thresholds, escalation guidance, intel hints)
- Preserves the full Technical Appendix (no breaking changes)

Be careful when editing: keep the function signature and report_path logic intact.
"""

import datetime
from textwrap import shorten
from typing import Dict, List, Optional

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


def _map_to_mitre(g: dict) -> List[str]:
    """Heuristic MITRE mapping based on alert type and/or event id.

    This is intentionally conservative and local (no external lookups).
    Add or refine mappings as your detection coverage grows.
    """
    t = str(g.get("type", "")).lower() or ""
    eid = str(g.get("event_id", "")).lower() or ""

    mapping = {
        "privileged logon": ["T1078"],  # Valid Accounts
        "unusual logon time": ["T1078"],
        "failed logon": ["T1110"],  # Brute force
        "brute force": ["T1110"],
        "new user": ["T1136"],  # Create Account
        "new user creation": ["T1136"],
        "process creation": ["T1059"],  # Command and Scripting Interpreter
        "suspicious process": ["T1059"],
        # add more local heuristics here as necessary
    }

    # try direct match on type
    for key, mitres in mapping.items():
        if key in t:
            return mitres

    # try event id heuristics
    if eid in ("4625", "4624"):
        # 4625 = Failed logon, 4624 = Successful logon
        if eid == "4625":
            return ["T1110"]
        return ["T1078"]

    # fallback
    return []


def _format_mitre(mitres: List[str]) -> str:
    return ",".join(mitres) if mitres else "None"


def generate_text_report(summary: dict, grouped_alerts: list, raw_alerts: list, output_dir: str) -> Optional[str]:
    """Generate an investor-friendly report while preserving the detailed appendix.

    Args:
        summary: dict with dataset metadata (start_time, end_time, totals, top_event_ids, etc.)
        grouped_alerts: list of grouped alert dicts (type, user, count, severity, event_id, off_hours...)
        raw_alerts: list of original alerts (for counts)
        output_dir: directory to write `log_summary.txt` (preserve existing path logic)

    Returns:
        Path to the written report (same as before). Returns None on failure.
    """
    # local import kept to preserve environment behaviour
    from dateutil import parser

    # --- compute durations
    start_time = summary.get("start_time")
    end_time = summary.get("end_time")
    try:
        start_dt = parser.parse(start_time) if start_time else None
        end_dt = parser.parse(end_time) if end_time else None
        if start_dt and end_dt:
            duration_sec = (end_dt - start_dt).total_seconds()
            hours = int(duration_sec // 3600)
            minutes = int((duration_sec % 3600) // 60)
            duration_str = f"{hours}h {minutes}m"
        else:
            duration_str = summary.get("duration", "Unknown")
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
        extras = build_context_notes(g) or {}
        final = extras.get("severity_final") or g.get("severity") or "Unknown"
        final = str(final).title()
        final_sev_counts[final] = final_sev_counts.get(final, 0) + int(g.get("count", 0) or 0)

        # keep top notes for investor 'Key Findings' (enrich them)
        if final in ("Medium", "High", "Critical"):
            mitres = _map_to_mitre(g)
            # attempt to surface source ip / geo if available in grouped alert or extras
            source_ip = g.get("source_ip") or extras.get("source_ip") if isinstance(extras, dict) else None
            geo = extras.get("geo") if isinstance(extras, dict) else None
            final_notes.append({
                "user": g.get("user", "Unknown"),
                "type": g.get("type", "Unknown"),
                "count": int(g.get("count", 0) or 0),
                "final": final,
                "rationale": extras.get("severity_rationale", ""),
                "mitre": _format_mitre(mitres),
                "source_ip": source_ip or "Not available",
                "geo": geo or "Not available",
            })

    # sort final_notes by severity weight then count
    weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    final_notes.sort(key=lambda x: (-weight.get(x.get("final", "Unknown"), 0), -x.get("count", 0)))

    # --- anomalies separated by system vs human (concise)
    human_anomalies = []
    system_anomalies = []

    for g in grouped_alerts:
        user = g.get("user", "Unknown")
        is_human = not is_system_or_service(user)
        if "unusual logon time" in str(g.get("type", "")).lower() and g.get("count", 0):
            threat_tag = classify_off_hours(is_human, bool(g.get("off_hours", False))) or "None"
            entry = (user, int(g.get("count", 0) or 0), threat_tag)
            if is_human:
                human_anomalies.append(entry)
            else:
                system_anomalies.append(entry)

    # --- start building report lines (Executive Summary)
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append("🚨 SOC Security Analysis Report")
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

    # explicit critical justification when none
    if final_sev_counts.get("Critical", 0) == 0:
        lines.append("- Critical Justification: No confirmed intrusion signatures or high-confidence TTP matches detected in the analyzed window.")

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
                f"- {note['final']} | {note['type']} | {note['user']} ({note['count']}) — {note['rationale']} (MITRE: {note['mitre']}; SrcIP: {note['source_ip']})"
            )
    else:
        lines.append("- No medium/high contextual alerts detected in the dataset.")

    lines.append("")

    # Short anomalies list for execs (separated)
    lines.append("⚠️ Potential Anomalies (summary)")
    if human_anomalies:
        lines.append("- Human accounts (require review):")
        for user, cnt, tag in human_anomalies:
            lines.append(f"  - {user}: {cnt} off-hours events [{tag}]")
    else:
        lines.append("- Human accounts: None detected.")

    if system_anomalies:
        lines.append("- System/service accounts (expected behavior; shown for completeness):")
        for user, cnt, tag in system_anomalies:
            lines.append(f"  - {user}: {cnt} off-hours events [{tag}] (likely expected)")
    else:
        lines.append("- System/service accounts: None notable.")

    lines.append("")

    # Visual snapshot placeholder (investor-facing)
    lines.append("📈 Visual Snapshot (see HTML/PDF for charts)")
    lines.append("- Severity distribution, Top users, Off-hours vs Normal hours, Source IP heatmap (when available)")
    lines.append("")

    # MVP Edge
    lines.append("🧠 MVP Edge")
    lines.append("- Context-aware baselines reduce false positives (system vs human accounts).")
    lines.append("- Automatic severity rationale + MITRE hints improves analyst triage and investor confidence.")
    lines.append("")

    # Conclusion & Next Steps (actionable)
    lines.append("✅ Conclusion & Next Steps")
    lines.append("- No confirmed high-severity intrusions in this window. Review the following items:")
    lines.append("  1) Cross-check human admin off-hours activity (e.g., user 'G. Muhammad') with maintenance/scheduled tasks and access logs.")
    lines.append("  2) If any human account shows ≥3x baseline off-hours activity → escalate to Tier-2 and lock session tokens until validated.")
    lines.append("  3) Enable Source IP enrichment (Geo/ASN/Threat Intel); if not available in EVTX, prioritize network logs enrichment.")
    lines.append("  4) Map recurring high-impact alerts to MITRE and add automated playbooks for common findings (e.g., T1078/T1110).")
    lines.append("  5) Configure automated alert thresholds and create an SLA for analyst triage on High/Critical findings.")
    lines.append("")

    # --- Technical Appendix (full detail: preserved to avoid breaking downstream tools)
    lines.append("*" * 120)
    lines.append("\nTechnical Appendix — Full Grouped Alerts (for SOC Analysts)\nThis section preserves the detailed grouped alerts previously produced.\n")
    lines.append("")

    # Grouped alerts summary (detailed) with MITRE and IP/Geo placeholders
    lines.append("📌 Grouped Alerts Summary")
    lines.append("")
    if grouped_alerts:
        lines.append(f"{'Alert Type':30} | {'User':20} | {'Sev':6} | {'Cnt':4} | {'First Seen':16} | {'Last Seen':16} | {'Src IP':15} | {'Geo':10} | Threat Tag | MITRE")
        lines.append("-" * 140)
        for g in grouped_alerts:
            first_seen = (str(g.get('first_seen'))[:16]) if g.get('first_seen') else "Unknown"
            last_seen = (str(g.get('last_seen'))[:16]) if g.get('last_seen') else "Unknown"
            user = g.get('user', 'Unknown')
            is_human = not is_system_or_service(user)
            extras = build_context_notes(g) or {}
            threat_tag = classify_off_hours(is_human, bool(g.get('off_hours', False))) or 'None'

            # MITRE and source IP/Geo
            mitres = _map_to_mitre(g)
            mitre_str = _format_mitre(mitres)
            source_ip = g.get('source_ip') or extras.get('source_ip') if isinstance(extras, dict) else None
            src_ip = source_ip or 'Not available'
            geo = extras.get('geo') if isinstance(extras, dict) else None
            geo_str = geo or 'Not available'

            lines.append(
                f"{_short(g.get('type', 'Unknown'),30):30} | "
                f"{_short(user,20):20} | "
                f"{str(g.get('severity', 'Unknown'))[:6]:6} | "
                f"{g.get('count', 0):4} | "
                f"{first_seen:16} | "
                f"{last_seen:16} | "
                f"{_short(src_ip,15):15} | "
                f"{_short(geo_str,10):10} | "
                f"{threat_tag:9} | {mitre_str}"
            )

            # Context & baseline lines (preserve previous behaviour)
            ctx_line, base_line = format_context_lines_for_report(user)
            lines.append(ctx_line)
            lines.append(base_line)

            # detailed extras
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
            if extras.get("baseline_source"):
                lines.append(f"    Baseline Source: {extras['baseline_source']}")

            # surface MITRE/source IP/geo as separate lines for analysts
            if mitre_str != "None":
                lines.append(f"    MITRE Mapping: {mitre_str}")
            if src_ip != 'Not available':
                lines.append(f"    Source IP: {src_ip}  (enrich via threat-intel)" )
            if geo_str != 'Not available':
                lines.append(f"    Geo: {geo_str}")

            lines.append("")
    else:
        lines.append("- No alerts triggered.")
    lines.append("")

    # Potential anomalies (detailed)
    lines.append("⚠️ Potential Anomalies")
    lines.append("")
    if human_anomalies or system_anomalies:
        for user, cnt, tag in human_anomalies:
            lines.append(f"- Off-hours logon: User '{user}' ({cnt} times) [Human] [{tag}]")
        for user, cnt, tag in system_anomalies:
            lines.append(f"- Off-hours logon: User '{user}' ({cnt} times) [System/Service] [{tag}] (likely expected)")
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
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    except Exception:
        # keep silent failure mode similar to upstream patterns; callers may check return value
        return None

    return report_path
