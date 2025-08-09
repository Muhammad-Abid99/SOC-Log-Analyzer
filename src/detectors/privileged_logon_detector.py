# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/detectors/privileged_logon_detector.py

def detect(df):
    """
    Detect privileged logons (Event ID 4672).
    Returns a list of alert messages.
    """
    alerts = []
    privileged_df = df[df["EventID"] == 4672]

    for _, row in privileged_df.iterrows():
        user = row.get("SubjectUserName", "UnknownUser")
        alerts.append(f"Privileged Logon: Detected special privileges used by '{user}' at {row.get('TimeCreated')}.")

    return alerts
