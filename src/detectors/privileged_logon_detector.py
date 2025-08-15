# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/detectors/privileged_logon_detector.py

def detect(df):
    alerts = []
    privileged_df = df[df["EventID"] == 4672]

    for _, row in privileged_df.iterrows():
        user = row.get("SubjectUserName", "UnknownUser")
        time_created = row.get("TimeCreated", "UnknownTime")
        alerts.append({
            "type": "Privileged Logon",
            "user": user,
            "time": time_created,  # Added
            "time_created": time_created,
            "description": f"Privileged Logon: Detected special privileges used by '{user}' at {time_created}."
        })

    return alerts
