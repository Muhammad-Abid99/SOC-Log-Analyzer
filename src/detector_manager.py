# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/detector_manager.py
# Loads and manages all threat detection modules

from detectors import brute_force_detector
from detectors import new_user_creation_detector
from detectors import privileged_logon_detector
from detectors import unusual_logon_time_detector

def run_all_detectors(df):
    """
    Run all registered detection modules on the parsed log DataFrame.

    Args:
        df (pd.DataFrame): Parsed event log data

    Returns:
        list of str: Collected alert messages from all detectors
    """
    all_alerts = []

    # Brute Force Detection (Event ID 4625)
    brute_force_alerts = brute_force_detector.detect(df)
    all_alerts.extend(brute_force_alerts)

    # New User Account Creation (Event ID 4720)
    user_creation_alerts = new_user_creation_detector.detect(df)
    all_alerts.extend(user_creation_alerts)

    # Privileged Logon Detection (Event ID 4672)
    privileged_alerts = privileged_logon_detector.detect(df)
    all_alerts.extend(privileged_alerts)

    # Unusual Logon Times (Event ID 4624)
    unusual_time_alerts = unusual_logon_time_detector.detect(df)
    all_alerts.extend(unusual_time_alerts)

    return all_alerts
