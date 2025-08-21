# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/context_library.py

"""
context_library.py (single-file knowledge base)

Investor-grade contextual knowledge base for Windows Security Event logs.
- Loads optional user/account & event context from config.yaml
- Provides built-in context for common Windows system/service accounts
- Adds event metadata (common Event IDs) with recommendations
- Exposes helper functions used by reports/detectors for
  contextualization, baseline reasoning, and severity rationale.

Design notes:
- Zero hard dependency on pandas; plain dicts in/out.
- Safe to import from any module (report_text, report_generator, detectors).
- If config.yaml is missing, sensible defaults are used.
- **Backward compatible** with previous version (keeps existing public API),
  and adds `final_severity()` + richer event coverage and accounts.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
import socket
import yaml
import os
import logging

# -----------------------------
# Logging
# -----------------------------
logger = logging.getLogger(__name__)

# -----------------------------
# Config loading helpers
# -----------------------------

_DEF_CONFIG_BASENAME = "config.yaml"


def _find_config_path() -> Optional[Path]:
    """Try to locate config.yaml starting from CWD, then project root guesses."""
    # 1) Explicit env var override
    env_path = os.getenv("SOC_CONFIG")
    if env_path:
        p = Path(env_path).expanduser()
        if p.is_file():
            return p

    # 2) Current working directory
    cwd = Path.cwd()
    cand = cwd / _DEF_CONFIG_BASENAME
    if cand.is_file():
        return cand

    # 3) Try parent of src/ if running from within src
    # e.g., project_root/src/context_library.py -> project_root/config.yaml
    here = Path(__file__).resolve()
    # Walk up a few levels just in case of different launch points
    for up in [here.parent, here.parent.parent, here.parent.parent.parent]:
        cand = up.parent / _DEF_CONFIG_BASENAME if up.name == "src" else up / _DEF_CONFIG_BASENAME
        if cand.is_file():
            return cand

    # 4) Try project root heuristic (two levels up)
    root_guess = here.parents[2] if len(here.parents) >= 3 else here.parent
    cand = root_guess / _DEF_CONFIG_BASENAME
    if cand.is_file():
        return cand

    return None


def load_config() -> Dict[str, Any]:
    """Load YAML config if available; otherwise return defaults.
    Safe for import-time usage.
    """
    path = _find_config_path()
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
            if not isinstance(cfg, dict):
                logger.warning("config.yaml did not parse to a dict; ignoring.")
                return {}
            return cfg
    except Exception as e:
        logger.debug("Failed to load config.yaml: %s", e)
        return {}


# -----------------------------
# Context data structures
# -----------------------------

@dataclass
class AccountContext:
    type: str = "Unknown"
    description: str = "No context available. May require manual investigation."
    baseline: str = "No baseline established."


@dataclass
class EventContext:
    title: str
    description: str
    category: str
    default_severity: str
    recommendation: str


# Built-in account context (can be overridden/extended by config)
_DEFAULT_ACCOUNT_CONTEXT: Dict[str, AccountContext] = {
    # Windows Core Accounts
    "SYSTEM": AccountContext(
        type="System Account",
        description="Windows core account. High privileged logons are normal for OS operations.",
        baseline="Frequent privileged logons expected. Alert only if unusual deviation.",
    ),
    "NT AUTHORITY\\SYSTEM": AccountContext(
        type="System Account",
        description="Alias for SYSTEM on Windows. Privileged OS activity is expected.",
        baseline="Frequent privileged logons expected. Investigate only large spikes or anomalies.",
    ),
    "LOCAL SERVICE": AccountContext(
        type="Service Account",
        description="Built-in account with limited privileges used for local services.",
        baseline="Expected to log on occasionally for services. Rarely a threat.",
    ),
    "NETWORK SERVICE": AccountContext(
        type="Service Account",
        description="Built-in account used for network services with limited privileges.",
        baseline="Occasional logons are normal. Investigate if excessive.",
    ),
    "TrustedInstaller": AccountContext(
        type="Service Account",
        description="Windows Modules Installer service; modifies system files during updates.",
        baseline="Activity spikes during updates/patching windows. Unusual outside maintenance windows.",
    ),
    "DefaultAccount": AccountContext(
        type="Built-in Account",
        description="Disabled by default. Used for system services in some scenarios.",
        baseline="Normally idle. Any activity should be verified.",
    ),
    "WDAGUtilityAccount": AccountContext(
        type="System Account",
        description="Used by Windows Defender Application Guard sandbox.",
        baseline="Occasional activity when WDAG features are used. Low risk by itself.",
    ),
    "ANONYMOUS LOGON": AccountContext(
        type="Special Identity",
        description="Represents access by an anonymous (unauthenticated) session.",
        baseline="Usually rare. Investigate occurrences, especially with network access.",
    ),

    # Windows Background Accounts (use wildcard matching)
    "DWM-*": AccountContext(
        type="System Account",
        description="Desktop Window Manager accounts used for graphical sessions.",
        baseline="Frequent logons expected. Not usually suspicious.",
    ),
    "UMFD-*": AccountContext(
        type="System Account",
        description="User-Mode Font Driver accounts created by the system.",
        baseline="Normal behavior. Investigate only if paired with anomalies.",
    ),
    "IIS APPPOOL\\*": AccountContext(
        type="Service Account",
        description="Application pool identities for IIS-hosted web apps.",
        baseline="Activity follows web traffic patterns. Investigate privilege elevation or lateral movement.",
    ),

    # Example Named Account (customizable in config.yaml)
    "G Muhammad": AccountContext(
        type="Administrator",
        description="Human administrator account.",
        baseline="Privileged logons and off-hours activity may be normal, but require review.",
    ),
}


# Common Windows Security Event IDs (extend as needed)
_EVENT_CONTEXT: Dict[int, EventContext] = {
    4624: EventContext(
        title="An account was successfully logged on",
        description=(
            "Successful logon event. Review logon type, source IP, and account role to assess risk."
        ),
        category="Authentication",
        default_severity="Low",
        recommendation=(
            "Baseline per account. Flag unusual sources, geolocation anomalies, or off-hours for humans."
        ),
    ),
    4625: EventContext(
        title="An account failed to log on",
        description=(
            "Failed logon event. Bursts may indicate brute force or password spraying."
        ),
        category="Authentication",
        default_severity="Medium",
        recommendation=(
            "Group by source IP and account. Alert on rapid repeats, many accounts, or rare usernames."
        ),
    ),
    4634: EventContext(
        title="An account was logged off",
        description="Logoff event. Usually benign and paired with 4624.",
        category="Authentication",
        default_severity="Low",
        recommendation="Correlate with preceding 4624, check for short sessions of privileged accounts.",
    ),
    4648: EventContext(
        title="A logon was attempted using explicit credentials",
        description="Often seen in lateral movement (runas/alternate creds).",
        category="Authentication",
        default_severity="Medium",
        recommendation="Validate source/target pair and operator intent. Investigate on admin endpoints.",
    ),
    4672: EventContext(
        title="Special privileges assigned to new logon",
        description=(
            "Account logged on with elevated privileges (Admin-equivalent token)."
        ),
        category="Privilege Escalation",
        default_severity="Medium",
        recommendation=(
            "Expected for SYSTEM/service accounts. For human accounts, verify task/change ticket."
        ),
    ),
    4688: EventContext(
        title="A new process has been created",
        description="Process creation. High volume baseline for active systems.",
        category="Execution",
        default_severity="Medium",
        recommendation="Enable command-line logging. Flag suspicious parents (e.g., Office->cmd, WMI, PS remoting).",
    ),
    4719: EventContext(
        title="System audit policy was changed",
        description="Audit policy modifications; could be defense evasion.",
        category="Defense Evasion",
        default_severity="High",
        recommendation="Verify change window and actor. Investigate unauthorized policy downgrades immediately.",
    ),
    4720: EventContext(
        title="A user account was created",
        description="New local user created.",
        category="Account Management",
        default_severity="High",
        recommendation=(
            "Validate creator, time, and machine. Ensure ticket/change record. Is the account disabled by default?"
        ),
    ),
    1102: EventContext(
        title="The audit log was cleared",
        description="Security event log was cleared, potentially anti-forensic.",
        category="Defense Evasion",
        default_severity="High",
        recommendation="Treat as high severity. Identify actor, scope, and contain if unauthorized.",
    ),
}


# -----------------------------
# Runtime config & merges
# -----------------------------

_cfg_cache: Optional[Dict[str, Any]] = None
_account_ctx_cache: Optional[Dict[str, AccountContext]] = None
_event_ctx_cache: Optional[Dict[int, EventContext]] = None


def _ensure_cfg() -> Dict[str, Any]:
    global _cfg_cache
    if _cfg_cache is None:
        _cfg_cache = load_config()
    return _cfg_cache


def _merge_account_context() -> Dict[str, AccountContext]:
    """Merge built-ins with optional config overrides.

    Supported config formats:
    user_context:
      "Alice Admin":
        type: "Administrator"
        description: "Privileged human account"
        baseline: "Off-hours may be normal."
    """
    global _account_ctx_cache
    if _account_ctx_cache is not None:
        return _account_ctx_cache

    merged: Dict[str, AccountContext] = dict(_DEFAULT_ACCOUNT_CONTEXT)

    cfg = _ensure_cfg()
    user_ctx = cfg.get("user_context") or {}
    if isinstance(user_ctx, dict):
        for name, data in user_ctx.items():
            if not isinstance(data, dict):
                continue
            prev = merged.get(name)
            merged[name] = AccountContext(
                type=str(data.get("type", prev.type if prev else "Unknown")),
                description=str(data.get("description", prev.description if prev else AccountContext().description)),
                baseline=str(data.get("baseline", prev.baseline if prev else AccountContext().baseline)),
            )
            logger.debug("Account context override: %s", name)

    _account_ctx_cache = merged
    return merged


def _merge_event_context() -> Dict[int, EventContext]:
    """Merge built-ins with optional config overrides.

    Supported config formats:
    event_context:
      "4624":
        title: "An account was successfully logged on"
        description: "..."
        category: "Authentication"
        default_severity: "Low"
        recommendation: "..."
    """
    global _event_ctx_cache
    if _event_ctx_cache is not None:
        return _event_ctx_cache

    merged: Dict[int, EventContext] = dict(_EVENT_CONTEXT)

    cfg = _ensure_cfg()
    ecfg = cfg.get("event_context") or {}
    if isinstance(ecfg, dict):
        for k, data in ecfg.items():
            try:
                eid = int(k)
            except Exception:
                logger.debug("Ignoring non-integer event_context key: %r", k)
                continue
            if not isinstance(data, dict):
                continue
            prev = merged.get(eid)
            merged[eid] = EventContext(
                title=str(data.get("title", prev.title if prev else f"Event {eid}")),
                description=str(data.get("description", prev.description if prev else "")),
                category=str(data.get("category", prev.category if prev else "Unknown")),
                default_severity=str(data.get("default_severity", prev.default_severity if prev else "Low")),
                recommendation=str(data.get("recommendation", prev.recommendation if prev else "")),
            )
            logger.debug("Event context override: %s", eid)

    _event_ctx_cache = merged
    return merged


# -----------------------------
# Public API — Runtime & Lookups
# -----------------------------


def get_runtime_context() -> Dict[str, Any]:
    """Return basic runtime context (tool name, version, analyst, host/ip) from config.
    Auto-fills hostname/IP when null.
    """
    cfg = _ensure_cfg()
    ctx = (cfg.get("context") or {}).copy()

    # Auto-fill host and IP if missing
    try:
        if not ctx.get("hostname"):
            ctx["hostname"] = socket.gethostname()
        if not ctx.get("ip_address"):
            try:
                ctx["ip_address"] = socket.gethostbyname(socket.gethostname())
            except Exception:
                ctx["ip_address"] = None
    except Exception:
        pass

    # Fill defaults if totally missing
    ctx.setdefault("tool_name", "SOC-Log-Analyzer")
    ctx.setdefault("version", "v1.0.0")
    ctx.setdefault("analyst", "Unknown Analyst")
    ctx.setdefault("organization", "Unknown Org")
    ctx.setdefault("environment", "Unknown")

    return ctx


def get_account_context(account_name: str) -> Dict[str, str]:
    """Return contextual info for account (supports simple trailing-wildcard patterns)."""
    if not account_name:
        return AccountContext().__dict__

    merged = _merge_account_context()

    # Exact match first
    if account_name in merged:
        return merged[account_name].__dict__

    # Wildcard patterns — only trailing '*' supported for simplicity
    for pattern, ctx in merged.items():
        if pattern.endswith("*") and account_name.startswith(pattern[:-1]):
            return ctx.__dict__

    return AccountContext().__dict__


def get_event_context(event_id: Optional[int]) -> Optional[Dict[str, str]]:
    if event_id is None:
        return None
    ec = _merge_event_context().get(int(event_id))
    return ec.__dict__ if ec else None


# -----------------------------
# Baseline & Severity Utilities
# -----------------------------

_SEV_TO_WEIGHT = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_WEIGHT_TO_SEV = {v: k for k, v in _SEV_TO_WEIGHT.items()}


def _clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def severity_from_deviation(observed: int, typical: Optional[float]) -> Tuple[str, str]:
    """Simple deviation-to-severity mapping with human-readable rationale.

    Note: `typical` is a heuristic *per-day* baseline in this module.
    """
    if not typical or typical <= 0:
        return "Low", "No baseline available; defaulting to Low unless corroborated by other signals."

    ratio = observed / typical
    if ratio >= 3.0:
        return "High", f"Observed {observed} vs baseline {typical:.1f} (≥3x spike)."
    if ratio >= 1.5:
        return "Medium", f"Observed {observed} vs baseline {typical:.1f} (≥1.5x increase)."
    return "Low", f"Observed {observed} near baseline {typical:.1f}."


def typical_baseline_for_account(account_name: str) -> Optional[float]:
    """Return a heuristic baseline count-per-day for known accounts.
    In production this should come from historical data; here we use sane defaults.
    """
    name = account_name or ""
    if name in ("SYSTEM", "NT AUTHORITY\\SYSTEM"):
        return 800.0  # privileged + routine activity
    if name.startswith("DWM-") or name.startswith("UMFD-"):
        return 20.0
    if name.startswith("IIS APPPOOL\\"):
        return 50.0
    if name in ("LOCAL SERVICE", "NETWORK SERVICE"):
        return 30.0
    if name in ("TrustedInstaller",):
        return 40.0  # bursts during update cycles
    if name in ("DefaultAccount", "ANONYMOUS LOGON", "WDAGUtilityAccount"):
        return 2.0
    # Human accounts: assume lower routine activity
    return 10.0


def explain_baseline_source(account_name: str) -> str:
    """Return a short note about where the baseline came from."""
    # Later we can enrich with learned/historical metadata from config or a DB.
    return (
        "Baseline derived from heuristic defaults (approx. per-day activity). Historical learning not enabled."
    )


def final_severity(
    account_name: str,
    event_id: Optional[int],
    observed: int,
    typical: Optional[float] = None,
    off_hours: bool = False,
) -> Tuple[str, str]:
    """Compute a blended severity using event default severity + deviation + context.

    Returns (severity, rationale_text)
    """
    acct_ctx = get_account_context(account_name)
    is_system = is_system_or_service(account_name)

    evt = get_event_context(event_id) or {
        "title": f"Event {event_id}",
        "category": "Unknown",
        "default_severity": "Low",
        "recommendation": "",
    }

    # 1) Base weight from event default
    base_w = _SEV_TO_WEIGHT.get(str(evt.get("default_severity", "Low")), 1)
    rationale_parts = [f"Base={evt.get('default_severity','Low')} ({evt.get('title','')})"]

    # 2) Deviation weight
    typical = typical if typical is not None else typical_baseline_for_account(account_name)
    dev_sev, dev_text = severity_from_deviation(observed, typical)
    dev_w = _SEV_TO_WEIGHT[dev_sev]
    rationale_parts.append(f"Deviation={dev_sev} ({dev_text})")

    # 3) Off-hours modifier
    if off_hours and not is_system:
        base_w = max(base_w, 2)  # ensure at least Medium baseline for humans off-hours
        rationale_parts.append("Off-hours human activity → escalate")
    elif off_hours and is_system:
        rationale_parts.append("Off-hours system activity → usually normal")

    # 4) Event-specific floors/ceilings
    high_floor_events = {1102, 4719, 4720}
    if event_id in high_floor_events:
        base_w = max(base_w, 3)
        rationale_parts.append("High-risk event type floor (≥High)")

    # 5) Account role influence
    role = (acct_ctx.get("type") or "").lower()
    if any(x in role for x in ["admin", "administrator"]):
        base_w = max(base_w, 2)  # admin actions are rarely Low by default
        rationale_parts.append("Admin role → ensure ≥Medium if anomalous")

    # Combine: take the max of base & deviation as primary signal
    combined_w = max(base_w, dev_w)

    # 6) System/service damping for benign events
    if is_system and event_id in {4624, 4672, 4634}:
        combined_w = _clamp(combined_w - 1, 1, 4)
        rationale_parts.append("System/service benign pattern → damp one level")

    sev = _WEIGHT_TO_SEV[_clamp(combined_w, 1, 4)]
    return sev, "; ".join(rationale_parts)


def classify_off_hours(is_human: bool, off_hours: bool) -> Optional[str]:
    """Return a short rationale for off-hours behavior."""
    if not off_hours:
        return None
    if is_human:
        return "Human account active outside working hours. Validate business justification."
    return "System/service account activity outside working hours is often normal. Check for deviation."


def estimate_role_from_context(account_name: str) -> str:
    ctx = get_account_context(account_name)
    return ctx.get("type", "Unknown")


def is_system_or_service(account_name: str) -> bool:
    role = estimate_role_from_context(account_name).lower()
    return any(k in role for k in ["system", "service"])


# -----------------------------
# High-level note builder for reports/detectors
# -----------------------------

def build_context_notes(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Given a grouped alert dict, return added context & rationale fields.

    Expected keys in `alert`: type, user, count, event_id (optional), off_hours (optional)
    Returns a dict with: account_context, event_context, context_note, baseline_note,
    baseline_deviation, severity_hint, off_hours_note (optional), severity_final, severity_rationale,
    baseline_source
    """
    user = str(alert.get("user", "Unknown"))
    event_id = alert.get("event_id")
    count = int(alert.get("count", 0) or 0)
    off_hours = bool(alert.get("off_hours", False))

    acct_ctx = get_account_context(user)
    evt_ctx = get_event_context(event_id)

    # Baseline reasoning
    typical = typical_baseline_for_account(user)
    sev_hint, dev_text = severity_from_deviation(count, typical)

    off_hours_text = classify_off_hours(is_human=not is_system_or_service(user), off_hours=off_hours)

    # Final severity
    sev_final, sev_rationale = final_severity(user, event_id, count, typical=typical, off_hours=off_hours)

    context_note = acct_ctx.get("description", "")
    baseline_note = acct_ctx.get("baseline", "")

    extras = {
        "account_context": acct_ctx,
        "event_context": evt_ctx,
        "context_note": context_note,
        "baseline_note": baseline_note,
        "baseline_deviation": dev_text,
        "severity_hint": sev_hint,
        "severity_final": sev_final,
        "severity_rationale": sev_rationale,
        "baseline_source": explain_baseline_source(user),
    }

    if off_hours_text:
        extras["off_hours_note"] = off_hours_text

    return extras


def format_context_lines_for_report(user: str) -> Tuple[str, str]:
    """Convenience for report_text.py: returns (context_line, baseline_line)."""
    ctx = get_account_context(user)
    return (f"    Context: {ctx['description']}", f"    Baseline: {ctx['baseline']}")


__all__ = [
    "load_config",
    "get_runtime_context",
    "get_account_context",
    "get_event_context",
    "severity_from_deviation",
    "typical_baseline_for_account",
    "build_context_notes",
    "format_context_lines_for_report",
    "final_severity",
    "explain_baseline_source",
    "estimate_role_from_context",
    "is_system_or_service",
]

