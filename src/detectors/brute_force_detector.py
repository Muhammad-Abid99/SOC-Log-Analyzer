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
        .reset_index(name="count")
    )
    
    for _, row in grouped.iterrows():
        ip = row["IpAddress"]
        user = row["TargetUserName"]
        count = row["count"]

        if pd.notna(ip) and count >= 5:
            # Get earliest attempt time
            subset = failed_logons[(failed_logons["IpAddress"] == ip) & (failed_logons["TargetUserName"] == user)]
            first_time = subset["TimeCreated"].min() if not subset.empty else None

            alerts.append({
                "type": "Brute Force Attack",
                "user": user,
                "ip": ip,
                "time": first_time,  # Added
                "attempts": count,
                "description": f"Multiple failed logon attempts for user '{user}' from IP {ip}."
            })

    return alerts
