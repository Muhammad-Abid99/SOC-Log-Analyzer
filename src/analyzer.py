# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

from detector_manager import run_all_detectors, run_selected_detectors

def run_threat_detection(df, detectors=None):
    """
    Run threat detection on given DataFrame.
    Args:
        df (pd.DataFrame): Parsed event log data
        detectors (list or None): List of detector keys to run, or None for all
    Returns:
        list: alerts from detectors
    """
    print(f"📊 Loaded {len(df)} log entries from DataFrame")

    if detectors is None or "all" in detectors:
        alerts = run_all_detectors(df)
    else:
        alerts = run_selected_detectors(df, detectors)

    return alerts

