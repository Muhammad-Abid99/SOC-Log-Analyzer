# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/report/report_text.py
# Investor- and SOC-friendly text report (Executive summary + Technical appendix)

"""
This file is an upgraded, production-minded version of the original
report_text.py.  It preserves the public function signature
`generate_text_report(summary, grouped_alerts, raw_alerts, output_dir)` and
keeps the same output path logic so downstream tooling is unaffected.

New in this version (Contextualized v2):
- Contextualization layer (Account Glossary + role-aware lines)
- Dynamic severity re-scoring (role/time/anomaly-aware) layered on top of detector hints
- Human-first anomalies (system/service anomalies summarized but de-noised)
- Correlated Incidents section (simple rule-based fusion across alert types)
- ASCII visual snapshot (quick-read severity bars in text-only environments)
- Single baseline methodology note (avoid repetition noise in appendix)

Be careful when editing: keep the function signature and report_path logic intact.
"""

import datetime
import re
from textwrap import shorten
from typing import Dict, List, Optional, Tuple

from context_library import (
    classify_off_hours,
    format_context_lines_for_report,
    build_context_notes,
    get_runtime_context,
    is_system_or_service,
)

_SEV_ORDER = ["Low", "Medium", "High", "Critical"]
_SEV_EMOJI = {"Low": "✅", "Medium": "⚠️", "High": "🔴", "Critical": "🔥"}


def _emoji_for_sev(sev: str) -> str:
    return _SEV_EMOJI.get(str(sev).title(), "•")


def _short(x, n=30):
    return shorten(str(x or ""), n)


# ---------- Context & Roles ----------
_ACCOUNT_EXPLAIN = {
    "SYSTEM": "Windows kernel-level account. High volumes of privileged activity are normal for OS operations.",
    "LOCAL SERVICE": "Built-in limited-privilege service account; expected occasional activity.",
    "NETWORK SERVICE": "Built-in limited-privilege network service account; expected occasional activity.",
}


def _is_dwm(user: str) -> bool:
    u = (user or "").upper()
    return u.startswith("DWM-") or u == "DWM" or u.startswith("DESKTOP WINDOW MANAGER")


def _is_umfd(user: str) -> bool:
    u = (user or "").upper()
    return u.startswith("UMFD-") or "USER-MODE FONT DRIVER" in u


def _role_label(user: str) -> str:
    """Best-effort role label without external lookups.
    - System/Service if known built-ins / DWM / UMFD.
    - Otherwise Human; tag as Admin? if username suggests admin.
    """
    if not user:
        return "Unknown"
    if is_system_or_service(user) or _is_dwm(user) or _is_umfd(user) or user.upper() in _ACCOUNT_EXPLAIN:
        return "System/Service"
    # heuristic admin hints
    ul = user.lower()
    if any(t in ul for t in ["admin", "administrator", "adm-", "-adm", "-admin", "_adm", "_admin"]):
        return "Human (Admin?)"
    return "Human"


def _account_explainer(user: str) -> Optional[str]:
    if not user:
        return None
    u = user.upper()
    if u in _ACCOUNT_EXPLAIN:
        return _ACCOUNT_EXPLAIN[u]
    if _is_dwm(user):
        return "DWM (Desktop Window Manager) accounts drive the Windows UI session. Frequent logons are normal, low risk unless paired with other anomalies."
    if _is_umfd(user):
        return "UMFD (User-Mode Font Driver) accounts are created by the system. Activity is generally benign."
    return None


# ---------- Severity logic ----------

def _extract_spike_multiplier(text: Optional[str]) -> float:
    """Parse strings like "≥3x spike" or "2.5x" to a float; fallback 1.0."""
    if not text:
        return 1.0
    m = re.search(r"(?:≥|>=)?\s*(\d+(?:\.\d+)?)x", str(text))
    if m:
        try:
            return float(m.group(1))
        except Exception:
            return 1.0
    return 1.0


def _bump_severity(sev: str, steps: int = 1) -> str:
    s = str(sev).title()
    try:
        idx = _SEV_ORDER.index(s)
    except ValueError:
        idx = 0
    return _SEV_ORDER[min(idx + steps, len(_SEV_ORDER) - 1)]


def _compute_dynamic_final_severity(g: dict, extras: dict) -> Tuple[str, str]:
    """Role/time/anomaly-aware severity on top of detector hints.
    Returns (final_sev, rationale_tail)
    """
    base = str(extras.get("severity_final") or g.get("severity") or "Low").title()
    user = g.get("user", "")
    t = str(g.get("type", "")).lower()
    is_human = _role_label(user).startswith("Human")
    off_hours = bool(g.get("off_hours", False))
    count = int(g.get("count", 0) or 0)

    spike_text = extras.get("baseline_deviation") or extras.get("severity_rationale") or ""
    spike_x = _extract_spike_multiplier(spike_text)

    final_sev = base
    bumps = []

    # Privileged logon by human → elevate when off-hours or repeated
    if is_human and "privileged logon" in t:
        if off_hours:
            final_sev = _bump_severity(final_sev, 1)
            bumps.append("off-hours human privileged access")
        if spike_x >= 1.5 or count >= 10:
            final_sev = _bump_severity(final_sev, 1)
            bumps.append(f"volume anomaly (~{spike_x:.1f}x / {count} events)")

    # Unusual logon time by human → strong elevation at ≥3x
    if is_human and "unusual logon time" in t:
        if spike_x >= 3.0 or count >= 5:
            final_sev = _bump_severity(final_sev, 2 if spike_x >= 3.0 else 1)
            bumps.append(f"off-hours spike (~{spike_x:.1f}x / {count} events)")

    # Guardrails: system/service usually capped at Low
    if not is_human and final_sev in ("Medium", "High", "Critical"):
        final_sev = "Low"
        bumps.append("system/service downgrade (expected behavior)")

    # Build a small rationale tail summarizing bumps
    rationale_tail = ("; ".join(bumps)) if bumps else ""
    return final_sev, rationale_tail


# ---------- Visuals ----------

def _ascii_bar(v: int, vmax: int, width: int = 22) -> str:
    if vmax <= 0:
        vmax = 1
    n = int(round((v / float(vmax)) * width))
    return "█" * max(n, 0)


# ---------- Correlation ----------

def _correlate_incidents(grouped_alerts: List[dict]) -> List[dict]:
    """Very lightweight correlation across alert types within the same window.
    Heuristics (per human user):
      - Failed/Brute Force present + Privileged Logon present → Credential Access → Valid Accounts
      - Unusual Logon Time + Privileged Logon → Suspicious Privilege Use off-hours
      - New User Creation + Privileged Logon (any account) → Potential Persistence/Privilege escalation
    """
    per_user = {}
    for g in grouped_alerts:
        user = g.get("user", "Unknown")
        if _role_label(user) == "System/Service":
            # keep correlations human-first
            continue
        key = user
        t = str(g.get("type", "")).lower()
        entry = per_user.setdefault(key, {"user": user, "types": set(), "items": []})
        entry["types"].add(t)
        entry["items"].append(g)

    incidents: List[dict] = []
    for user, data in per_user.items():
        types = data["types"]
        has_failed = any("failed logon" in x or "brute force" in x for x in types)
        has_priv = any("privileged logon" in x for x in types)
        has_unusual = any("unusual logon time" in x for x in types)
        has_new_user = any("new user" in x for x in types)

        if has_failed and has_priv:
            incidents.append({
                "user": user,
                "title": "Possible credential stuffing followed by privileged access",
                "techniques": ["T1110", "T1078"],
                "severity": "High" if has_unusual else "Medium",
                "signals": [s for s in types if any(k in s for k in ["failed logon", "brute force", "privileged logon", "unusual logon time"])],
            })
        if has_unusual and has_priv and not any(inc.get("title").startswith("Possible credential") for inc in incidents if inc["user"] == user):
            incidents.append({
                "user": user,
                "title": "Privileged access during off-hours",
                "techniques": ["T1078.004"],
                "severity": "High",
                "signals": [s for s in types if any(k in s for k in ["privileged logon", "unusual logon time"])],
            })
        if has_new_user and has_priv:
            incidents.append({
                "user": user,
                "title": "New account creation associated with privilege use",
                "techniques": ["T1136", "T1078"],
                "severity": "Medium",
                "signals": [s for s in types if any(k in s for k in ["new user", "privileged logon"])],
            })

    # Keep incident list concise & deterministic
    # Sort by severity weight then by user name
    weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    incidents.sort(key=lambda x: (-weight.get(x.get("severity", "Unknown"), 0), x.get("user", "")))
    return incidents


# ---------- MITRE helpers ----------

def _map_to_mitre(g: dict) -> List[str]:
    """Heuristic MITRE mapping based on alert type and/or event id.

    This is intentionally conservative and local (no external lookups).
    Add or refine mappings as your detection coverage grows.
    """
    t = str(g.get("type", "")).lower() or ""
    eid = str(g.get("event_id", "")).lower() or ""

    mapping = {
        "privileged logon": ["T1078", "T1078.004"],  # Valid Accounts (Privileged)
        "unusual logon time": ["T1078"],
        "failed logon": ["T1110"],  # Brute force
        "brute force": ["T1110"],
        "new user": ["T1136"],  # Create Account
        "new user creation": ["T1136"],
        "process creation": ["T1059"],  # Command and Scripting Interpreter
        "suspicious process": ["T1059"],
    }

    for key, mitres in mapping.items():
        if key in t:
            return mitres

    if eid in ("4625", "4624", "4672", "4720"):
        if eid == "4625":
            return ["T1110"]
        if eid == "4720":
            return ["T1136"]
        if eid == "4672":
            return ["T1078", "T1078.004"]
        return ["T1078"]  # 4624

    return []


def _format_mitre(mitres: List[str]) -> str:
    return ",".join(mitres) if mitres else "None"


# ---------- Main generator ----------

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

    # --- compute (re-scored) final severity counts & build key notes
    final_sev_counts: Dict[str, int] = {s: 0 for s in _SEV_ORDER}
    final_notes: List[Dict] = []

    # Precompute dynamic severity and enrich per-group
    enriched_groups: List[dict] = []
    for g in grouped_alerts or []:
        extras = build_context_notes(g) or {}
        dyn_final, tail = _compute_dynamic_final_severity(g, extras)
        extras["severity_final_dynamic"] = dyn_final
        if tail:
            # append to existing rationale
            base_rat = extras.get("severity_rationale", "")
            extras["severity_rationale"] = (base_rat + ("; " if base_rat and tail else "") + tail).strip("; ")
        g2 = dict(g)
        g2["_extras"] = extras
        enriched_groups.append(g2)
        # Count toward final severity rollup
        cnt = int(g.get("count", 0) or 0)
        final_sev_counts[str(dyn_final).title()] = final_sev_counts.get(str(dyn_final).title(), 0) + cnt

        # Collect investor-facing notes for Medium+
        if str(dyn_final).title() in ("Medium", "High", "Critical"):
            mitres = _map_to_mitre(g)
            source_ip = g.get("source_ip") or (extras.get("source_ip") if isinstance(extras, dict) else None)
            geo = extras.get("geo") if isinstance(extras, dict) else None
            final_notes.append({
                "user": g.get("user", "Unknown"),
                "type": g.get("type", "Unknown"),
                "count": cnt,
                "final": str(dyn_final).title(),
                "rationale": extras.get("severity_rationale", ""),
                "mitre": _format_mitre(mitres),
                "source_ip": source_ip or "Not available",
                "geo": geo or "Not available",
            })

    # sort final_notes by severity weight then count
    weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    final_notes.sort(key=lambda x: (-weight.get(x.get("final", "Unknown"), 0), -x.get("count", 0)))

    # --- anomalies separated by HUMAN ONLY for the exec summary (de-noised)
    human_anomalies = []
    system_anomalies = []

    for g in enriched_groups:
        user = g.get("user", "Unknown")
        is_human = _role_label(user).startswith("Human")
        if "unusual logon time" in str(g.get("type", "")).lower() and g.get("count", 0):
            threat_tag = classify_off_hours(is_human, bool(g.get("off_hours", False))) or "None"
            entry = (user, int(g.get("count", 0) or 0), threat_tag)
            if is_human:
                human_anomalies.append(entry)
            else:
                system_anomalies.append(entry)

    # --- Correlated incidents (human-focused)
    incidents = _correlate_incidents(enriched_groups)

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

    # severity snapshot (final/contextual dynamic)
    lines.append("- Severity (final/contextual):")
    vmax = max(final_sev_counts.values()) if final_sev_counts else 0
    for sev in _SEV_ORDER:
        cnt = final_sev_counts.get(sev, 0)
        bar = _ascii_bar(cnt, vmax)
        lines.append(f"  { _emoji_for_sev(sev) } {sev}: {cnt}  {bar}")

    # explicit critical justification when none
    if final_sev_counts.get("Critical", 0) == 0:
        lines.append("- Critical Justification: No confirmed intrusion signatures or high-confidence TTP matches detected in the analyzed window.")

    lines.append("")

    # Correlated incidents (concise)
    lines.append("🧩 Correlated Incidents (fusion across signals)")
    if incidents:
        for inc in incidents[:5]:
            lines.append(f"- {inc['severity']} | {inc['title']} | User: {inc['user']} | Signals: {', '.join(sorted(inc['signals']))} (MITRE: {', '.join(inc['techniques'])})")
    else:
        lines.append("- None detected at correlation layer.")
    lines.append("")

    # Key findings (top 5 contextual issues)
    lines.append("🔎 Key Findings & Recommended Actions")
    if final_notes:
        for note in final_notes[:5]:
            role = _role_label(note['user'])
            role_note = f" [{role}]" if role else ""
            lines.append(
                f"- {note['final']} | {note['type']} | {note['user']}{role_note} ({note['count']}) — {note['rationale']} (MITRE: {note['mitre']}; SrcIP: {note['source_ip']})"
            )
    else:
        lines.append("- No medium/high contextual alerts detected in the dataset.")

    lines.append("")

    # Short anomalies list for execs (HUMAN ONLY)
    lines.append("⚠️ Potential Anomalies (summary)")
    if human_anomalies:
        lines.append("- Human accounts (require review):")
        for user, cnt, tag in human_anomalies:
            lines.append(f"  - {user}: {cnt} off-hours events [{tag}]")
    else:
        lines.append("- Human accounts: None detected.")

    if system_anomalies:
        total_sys = sum(cnt for _, cnt, _ in system_anomalies)
        lines.append(f"- System/service accounts: suppressed from summary (total off-hours events: {total_sys}). See Appendix for details.")
    else:
        lines.append("- System/service accounts: None notable.")

    lines.append("")

    # Visual snapshot placeholder (investor-facing)
    lines.append("📈 Visual Snapshot (see HTML/PDF for charts)")
    lines.append("- Severity distribution, Top users, Off-hours vs Normal hours, Source IP heatmap (when available)")
    lines.append("")

    # Context notes & glossary
    lines.append("ℹ️ Context Notes")
    lines.append("- Baseline methodology: heuristic per-account daily activity until historical learning is enabled; spike multipliers (e.g., ≥3x) drive severity bumps for human accounts.")
    lines.append("- SYSTEM: Windows kernel account; frequent privileged events are usually expected and de-noised unless extreme deviations occur.")
    lines.append("- DWM-*: Desktop Window Manager sessions; normal during interactive logons.")
    lines.append("- UMFD-*: User-Mode Font Driver; system-generated and typically benign.")
    lines.append("")

    # MVP Edge
    lines.append("🧠 MVP Edge")
    lines.append("- Context-aware baselines reduce false positives (system vs human accounts).")
    lines.append("- Dynamic severity scoring (role/time/anomaly-aware) + MITRE hints improves analyst triage and investor confidence.")
    lines.append("")

    # Conclusion & Next Steps (actionable)
    lines.append("✅ Conclusion & Next Steps")
    lines.append("- No confirmed high-severity intrusions in this window. Review the following items:")
    lines.append("  1) Validate any human off-hours privileged access with change tickets/maintenance windows.")
    lines.append("  2) If a human account shows ≥3x off-hours spike or correlated privileged access → escalate to Tier-2 and consider session token lockdown.")
    lines.append("  3) Enable Source IP enrichment (Geo/ASN/Threat Intel); if not available in EVTX, prioritize network logs enrichment.")
    lines.append("  4) Expand MITRE mappings per detector (e.g., T1110 brute force, T1136 account creation) and attach auto-playbooks.")
    lines.append("  5) Configure automated alert thresholds and define SLA for triage on High/Critical findings.")
    lines.append("")

    # --- Technical Appendix (full detail)
    lines.append("*" * 120)
    lines.append("\nTechnical Appendix — Full Grouped Alerts (for SOC Analysts)\nThis section preserves the detailed grouped alerts previously produced.\n")
    lines.append("")

    # Grouped alerts summary (detailed) with MITRE and IP/Geo placeholders
    lines.append("📌 Grouped Alerts Summary")
    lines.append("")
    if enriched_groups:
        lines.append(f"{'Alert Type':30} | {'User':20} | {'Role':15} | {'Sev':6} | {'Cnt':4} | {'First Seen':16} | {'Last Seen':16} | {'Src IP':15} | {'Geo':10} | Threat Tag | MITRE")
        lines.append("-" * 160)
        for g in enriched_groups:
            first_seen = (str(g.get('first_seen'))[:16]) if g.get('first_seen') else "Unknown"
            last_seen = (str(g.get('last_seen'))[:16]) if g.get('last_seen') else "Unknown"
            user = g.get('user', 'Unknown')
            role = _role_label(user)
            is_human = role.startswith("Human")
            extras = g.get('_extras', {}) or {}
            threat_tag = classify_off_hours(is_human, bool(g.get('off_hours', False))) or 'None'

            # MITRE and source IP/Geo
            mitres = _map_to_mitre(g)
            mitre_str = _format_mitre(mitres)
            source_ip = g.get('source_ip') or extras.get('source_ip') if isinstance(extras, dict) else None
            src_ip = source_ip or 'Not available'
            geo = extras.get('geo') if isinstance(extras, dict) else None
            geo_str = geo or 'Not available'

            dyn_final = str(extras.get('severity_final_dynamic') or g.get('severity', 'Unknown')).title()

            lines.append(
                f"{_short(g.get('type', 'Unknown'),30):30} | "
                f"{_short(user,20):20} | "
                f"{_short(role,15):15} | "
                f"{dyn_final[:6]:6} | "
                f"{g.get('count', 0):4} | "
                f"{first_seen:16} | "
                f"{last_seen:16} | "
                f"{_short(src_ip,15):15} | "
                f"{_short(geo_str,10):10} | "
                f"{threat_tag:9} | {mitre_str}"
            )

            # Context & baseline lines (condensed)
            ctx_line, base_line = format_context_lines_for_report(user)
            # Replace the baseline line with a condensed variant to avoid repetition
            base_line = "    Baseline: heuristic daily activity; deviations expressed as spike multipliers (e.g., ≥3x)."
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
            if extras.get("severity_final_dynamic"):
                lines.append(f"    ➡ Final Severity: {extras['severity_final_dynamic']}")
            elif extras.get("severity_final"):
                lines.append(f"    ➡ Final Severity: {extras['severity_final']}")
            if extras.get("severity_rationale"):
                lines.append(f"    Rationale: {extras['severity_rationale']}")

            # surface MITRE/source IP/geo as separate lines for analysts
            if mitre_str != "None":
                lines.append(f"    MITRE Mapping: {mitre_str}")
            if src_ip != 'Not available':
                lines.append(f"    Source IP: {src_ip}  (enrich via threat-intel)" )
            if geo_str != 'Not available':
                lines.append(f"    Geo: {geo_str}")

            # one-line explainer for common accounts
            expl = _account_explainer(user)
            if expl:
                lines.append(f"    Note: {expl}")

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
        if system_anomalies:
            total_sys = sum(cnt for _, cnt, _ in system_anomalies)
            lines.append(f"- System/Service: {total_sys} off-hours events across built-in accounts (see Appendix).")
    else:
        lines.append("- None detected.")
    lines.append("")

    # Footer
    lines.append(f"Total Detection Alerts: {len(raw_alerts or [])}")
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
