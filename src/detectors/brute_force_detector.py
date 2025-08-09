# src/detectors/brute_force_detector.py

# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""
Detects brute-force login attempts based on multiple failed logons (Event ID 4625).
"""

import pandas as pd

def detect(df):
    alerts = []
    failed_logons = df[df["EventID"] == 4625]

    grouped = (
        failed_logons.groupby(["IpAddress", "TargetUserName"])
        .size()
        .reset_index(name="Count")
    )

    for _, row in grouped.iterrows():
        ip = row["IpAddress"]
        user = row["TargetUserName"]
        count = row["Count"]

        if pd.notna(ip) and count >= 5:
            alerts.append({
                "type": "Brute Force Attack",
                "ip": ip,
                "user": user,
                "attempts": count,
                "description": f"Multiple failed logon attempts for user '{user}' from IP {ip}."
            })

    return alerts
