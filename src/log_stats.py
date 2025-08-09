# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/log_stats.py
"""
Generates basic statistics from parsed CSV log files.
Useful for quick insights before deep threat analysis.
"""

import pandas as pd
from tabulate import tabulate

def generate_log_stats(parsed_csv_path):
    """Generate and print basic statistics about parsed logs."""
    try:
        df = pd.read_csv(parsed_csv_path)
    except FileNotFoundError:
        print(f"❌ CSV file not found: {parsed_csv_path}")
        return
    except Exception as e:
        print(f"❌ Error reading CSV: {e}")
        return

    if df.empty:
        print("⚠️ Parsed CSV is empty, no stats to show.")
        return

    # Basic stats
    total_logs = len(df)
    unique_event_ids = df["EventID"].nunique() if "EventID" in df.columns else 0
    top_event_ids = (
        df["EventID"].value_counts().head(5) if "EventID" in df.columns else None
    )

    # Time range
    if "TimeCreated" in df.columns and not df["TimeCreated"].isnull().all():
        time_min = df["TimeCreated"].min()
        time_max = df["TimeCreated"].max()
    else:
        time_min = time_max = "N/A"

    # Display results
    print("\n📊 LOG FILE STATISTICS 📊")
    stats_table = [
        ["Total Log Entries", total_logs],
        ["Unique Event IDs", unique_event_ids],
        ["Time Range Start", time_min],
        ["Time Range End", time_max],
    ]
    print(tabulate(stats_table, headers=["Metric", "Value"], tablefmt="grid"))

    if top_event_ids is not None:
        print("\n🔥 Top 5 Event IDs by Frequency:")
        print(tabulate(top_event_ids.reset_index().values,
                       headers=["EventID", "Count"], tablefmt="grid"))
