# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/analyzer.py
# Central module for managing all threat detection logic

import pandas as pd
from detector_manager import run_all_detectors

def run_threat_detection(csv_path):
    """
    Load parsed log data and apply all active detection rules.
    """
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"❌ Log file not found at: {csv_path}")
        return
    except Exception as e:
        print(f"❌ Failed to load logs: {e}")
        return

    print(f"📊 Loaded {len(df)} log entries from {csv_path}")
    
    # Run all registered detection modules
    alerts = run_all_detectors(df)

    if not alerts:
        print("✅ No threats detected.")
    else:
        print(f"⚠️ {len(alerts)} potential threat(s) detected:\n")
        for idx, alert in enumerate(alerts, 1):
            print(f"{idx}. {alert}")
