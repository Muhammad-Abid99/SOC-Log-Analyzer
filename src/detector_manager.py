# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/detector_manager.py

import logging
from collections import defaultdict
import pandas as pd
from detectors import (
    brute_force_detector,
    new_user_creation_detector,
    privileged_logon_detector,
    unusual_logon_time_detector,
    account_lockout_detector
)

logger = logging.getLogger(__name__)

# Map detector keys to modules for easy lookup
DETECTOR_MAP = {
    "brute_force": brute_force_detector,
    "new_user_creation": new_user_creation_detector,
    "privileged_logon": privileged_logon_detector,
    "unusual_logon_time": unusual_logon_time_detector,
    "account_lockout": account_lockout_detector,
}

# -----------------------------
#  Severity Assignment Function
# -----------------------------
def assign_severity(alert: dict) -> str:
    """
    Assign severity based on event ID, alert type, or custom logic.
    """
    event_id = alert.get("EventID")
    count = alert.get("count", 1)
    alert_type = alert.get("type", "").lower()

    if event_id == 4625 and count >= 5:
        return "Critical"  # Brute force attempt
    elif event_id == 4720:
        return "Critical"  # New user creation
    elif event_id == 4672:
        return "High"      # Privileged logon
    elif "unusual logon time" in alert_type:
        return "Medium"
    elif "account lockout" in alert_type:
        return "High"
    else:
        return "Low"


# -----------------------------
#  Alert Grouping Function
# -----------------------------
def group_alerts(alerts: list) -> list:
    """
    Groups alerts by type, user, and severity.
    Returns a list of grouped alerts with counts and first/last seen timestamps.
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

    for alert in alerts:
        # Normalize keys
        alert_type = alert.get("type", "Unknown")
        user = alert.get("user") or alert.get("TargetUserName") or "Unknown"
        ts = alert.get("timestamp")
        event_id = alert.get("EventID")

        # Assign severity if not already set
        severity = alert.get("severity") or assign_severity(alert)

        key = (alert_type, user, severity)

        if grouped[key]["count"] == 0:
            grouped[key]["type"] = alert_type
            grouped[key]["user"] = user
            grouped[key]["severity"] = severity
            grouped[key]["EventID"] = event_id

        grouped[key]["count"] += 1

        # Update first_seen / last_seen
        try:
            ts_dt = pd.to_datetime(ts)
            if grouped[key]["first_seen"] is None or ts_dt < grouped[key]["first_seen"]:
                grouped[key]["first_seen"] = ts_dt
            if grouped[key]["last_seen"] is None or ts_dt > grouped[key]["last_seen"]:
                grouped[key]["last_seen"] = ts_dt
        except Exception:
            pass

    # Convert timestamps to ISO strings for reporting
    for g in grouped.values():
        if isinstance(g["first_seen"], pd.Timestamp):
            g["first_seen"] = g["first_seen"].isoformat()
        if isinstance(g["last_seen"], pd.Timestamp):
            g["last_seen"] = g["last_seen"].isoformat()

    return list(grouped.values())


# -----------------------------
#  Detector Execution Functions
# -----------------------------
def run_all_detectors(df):
    """Run all detectors on the dataframe, assign severity, and group alerts."""
    all_alerts = []
    for name, detector in [
        ("Brute Force Detector", brute_force_detector),
        ("New User Creation Detector", new_user_creation_detector),
        ("Privileged Logon Detector", privileged_logon_detector),
        ("Unusual Logon Time Detector", unusual_logon_time_detector),
        ("Account Lockout Detector", account_lockout_detector),
    ]:
        try:
            alerts = detector.detect(df)
            if alerts:
                # Assign severity to each alert
                for a in alerts:
                    a["severity"] = assign_severity(a)
                logger.info(f"{name} found {len(alerts)} alert(s).")
                all_alerts.extend(alerts)
            else:
                logger.info(f"{name} found no alerts.")
        except Exception as e:
            logger.error(f"Error running {name}: {e}", exc_info=True)

    grouped = group_alerts(all_alerts)
    return all_alerts, grouped


def run_selected_detectors(df, detector_keys):
    """
    Run only the specified detectors by keys on the dataframe.
    Returns (all_alerts, grouped_alerts)
    """
    all_alerts = []
    for key in detector_keys:
        detector = DETECTOR_MAP.get(key)
        if not detector:
            logger.warning(f"Detector key '{key}' not recognized.")
            continue
        try:
            alerts = detector.detect(df)
            if alerts:
                for a in alerts:
                    a["severity"] = assign_severity(a)
                logger.info(f"{key} detector found {len(alerts)} alert(s).")
                all_alerts.extend(alerts)
            else:
                logger.info(f"{key} detector found no alerts.")
        except Exception as e:
            logger.error(f"Error running {key} detector: {e}", exc_info=True)

    grouped = group_alerts(all_alerts)
    return all_alerts, grouped
