# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

import logging

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

def run_all_detectors(df):
    """Run all detectors on the dataframe."""
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
                logger.info(f"{name} found {len(alerts)} alert(s).")
                all_alerts.extend(alerts)
            else:
                logger.info(f"{name} found no alerts.")
        except Exception as e:
            logger.error(f"Error running {name}: {e}", exc_info=True)
    return all_alerts

def run_selected_detectors(df, detector_keys):
    """
    Run only the specified detectors by keys on the dataframe.
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
                logger.info(f"{key} detector found {len(alerts)} alert(s).")
                all_alerts.extend(alerts)
            else:
                logger.info(f"{key} detector found no alerts.")
        except Exception as e:
            logger.error(f"Error running {key} detector: {e}", exc_info=True)
    return all_alerts
