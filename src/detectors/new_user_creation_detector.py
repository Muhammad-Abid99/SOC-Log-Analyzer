# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

def detect(df):
    alerts = []
    new_user_df = df[df["EventID"] == 4720]

    for _, row in new_user_df.iterrows():
        account_name = row.get("TargetUserName", "UnknownUser")
        creator = row.get("SubjectUserName", "UnknownActor")
        time_created = row.get("TimeCreated", "UnknownTime")

        alerts.append({
            "type": "New User Creation",
            "account_name": account_name,
            "creator": creator,
            "time_created": time_created,
            "description": f"New User Created: '{account_name}' by '{creator}' at {time_created}."
        })

    return alerts
