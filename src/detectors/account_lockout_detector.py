# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""
src/detectors/account_lockout_detector.py

Detect account lockout events (Event ID 4740).
It returns a list of structured alerts (dict) to match the style of `brute_force_detector.py`.
Also attempts to correlate recent failed logons (Event ID 4625) for context.
"""

import os
import yaml
from datetime import datetime, timedelta
import pandas as pd

DEFAULT_CONFIG = {
    "account_lockout": {
        "correlation_window_minutes": 10,
        "failed_attempts_threshold": 5
    }
}

def load_config():
    """
    Load config.yaml from repository root if available, otherwise use defaults.
    """
    try:
        config_path = os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml")
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
            # Merge defaults if keys missing
            merged = DEFAULT_CONFIG.copy()
            merged.update(cfg.get("account_lockout", {}))
            # ensure keys exist
            return {
                "correlation_window_minutes": cfg.get("account_lockout", {}).get(
                    "correlation_window_minutes",
                    DEFAULT_CONFIG["account_lockout"]["correlation_window_minutes"],
                ),
                "failed_attempts_threshold": cfg.get("account_lockout", {}).get(
                    "failed_attempts_threshold",
                    DEFAULT_CONFIG["account_lockout"]["failed_attempts_threshold"],
                ),
            }
    except Exception:
        # If config missing or unreadable, return defaults
        return {
            "correlation_window_minutes": DEFAULT_CONFIG["account_lockout"]["correlation_window_minutes"],
            "failed_attempts_threshold": DEFAULT_CONFIG["account_lockout"]["failed_attempts_threshold"],
        }

def parse_time(ts):
    """
    Parse ISO-like timestamps in TimeCreated column.
    Returns a datetime or None.
    """
    if not ts:
        return None
    try:
        # handle "Z" suffix (UTC) and other ISO variants
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        # fallback: try pandas parsing (slower but forgiving)
        try:
            return pd.to_datetime(ts, utc=True).to_pydatetime()
        except Exception:
            return None

def detect(df):
    """
    Detect account lockout events (EventID 4740).
    Returns list of dict alerts:
      {
        "type": "Account Lockout",
        "user": <TargetUserName or TargetUserSid>,
        "locked_on": <ISO timestamp string or None>,
        "machine": <Workstation/Computer who reported the lockout>,
        "correlated_failed_attempts": <int or 0>,
        "description": <human-readable>
      }
    """
    alerts = []
    if df is None or df.empty:
        return alerts

    cfg = load_config()
    window = timedelta(minutes=int(cfg["correlation_window_minutes"]))
    threshold = int(cfg["failed_attempts_threshold"])

    # Filter lockout events
    lockout_df = df[df["EventID"] == 4740].copy()
    if lockout_df.empty:
        return alerts

    # Precompute failed logons (EventID 4625) for correlation
    failed_df = df[df["EventID"] == 4625].copy()
    # parse times for both dataframes (create new column _ts)
    for frame in (lockout_df, failed_df):
        if "_ts" not in frame.columns:
            frame["_ts"] = frame["TimeCreated"].apply(parse_time)

    # Iterate lockouts and try to find nearby failed attempts
    for _, row in lockout_df.iterrows():
        locked_on_dt = row.get("_ts")
        user = row.get("TargetUserName") or row.get("TargetUserSid") or "UnknownUser"
        machine = row.get("Computer") or row.get("Workstation") or row.get("IpAddress") or "UnknownHost"

        correlated_count = 0
        correlated_examples = []

        if locked_on_dt and not failed_df.empty:
            window_start = locked_on_dt - window
            window_end = locked_on_dt

            # Look for failed logons for same user within window
            # Prefer matching TargetUserName; if missing, try SubjectUserName or TargetUserSid
            user_mask = failed_df["TargetUserName"].fillna("").str.lower() == str(user).lower()
            time_mask = failed_df["_ts"].notnull() & (failed_df["_ts"] >= window_start) & (failed_df["_ts"] <= window_end)
            matched = failed_df[user_mask & time_mask]

            correlated_count = int(matched.shape[0])
            if correlated_count > 0:
                # collect up to 3 examples for context
                for _, frow in matched.head(3).iterrows():
                    f_ip = frow.get("IpAddress") or frow.get("Workstation") or "UnknownIP"
                    f_time = frow.get("_ts")
                    correlated_examples.append({
                        "time": f_time.isoformat() if f_time else None,
                        "ip": f_ip,
                        "status": frow.get("Status", None)
                    })

        # Build description
        desc = f"Account lockout for '{user}' on host '{machine}' at {locked_on_dt.isoformat() if locked_on_dt else 'unknown time'}."
        if correlated_count >= threshold:
            desc += f" Correlated {correlated_count} failed logon(s) within last {int(window.total_seconds()/60)} minute(s)."
        elif correlated_count > 0:
            desc += f" Correlated {correlated_count} failed logon(s) within last {int(window.total_seconds()/60)} minute(s) (below threshold)."
            
        alert = {
            "type": "Account Lockout",
            "user": user,
            "time": locked_on_dt.isoformat() if locked_on_dt else None,  # Added
            "locked_on": locked_on_dt.isoformat() if locked_on_dt else None,
            "machine": machine,
            "correlated_failed_attempts": correlated_count,
            "correlated_examples": correlated_examples,
            "description": desc
        }


        alerts.append(alert)

    return alerts
