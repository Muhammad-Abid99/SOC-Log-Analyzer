# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/detectors/unusual_logon_time_detector.py

import yaml
from datetime import datetime
import os

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml")
    with open(config_path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)

def detect(df):
    alerts = []
    config = load_config()
    working_start = datetime.strptime(config["working_hours"]["start"], "%H:%M").time()
    working_end = datetime.strptime(config["working_hours"]["end"], "%H:%M").time()

    logon_df = df[df["EventID"] == 4624]

    for _, row in logon_df.iterrows():
        time_str = row.get("TimeCreated")
        if not time_str:
            continue
        try:
            logon_time = datetime.fromisoformat(time_str.replace("Z", "+00:00")).time()
        except Exception:
            continue

        if logon_time < working_start or logon_time > working_end:
            user = row.get("TargetUserName", "UnknownUser")
            alerts.append({
                "type": "Unusual Logon Time",
                "user": user,
                "time": time_str,  # Added
                "logon_time": logon_time.isoformat(),
                "description": f"Unusual Logon Time: User '{user}' logged in at {logon_time}, outside working hours."
            })

    return alerts
