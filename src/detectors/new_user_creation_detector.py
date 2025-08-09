# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/detectors/new_user_creation_detector.py

def detect(df):
    """
    Detect new user account creations (Event ID 4720).
    Returns a list of alert messages.
    """
    alerts = []
    new_user_df = df[df["EventID"] == 4720]

    for _, row in new_user_df.iterrows():
        account_name = row.get("TargetUserName", "UnknownUser")
        creator = row.get("SubjectUserName", "UnknownActor")
        alerts.append(f"New User Created: '{account_name}' by '{creator}' at {row.get('TimeCreated')}.")

    return alerts
