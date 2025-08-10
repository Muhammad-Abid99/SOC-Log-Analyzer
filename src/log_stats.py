# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

import os
import logging
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from tabulate import tabulate

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def generate_log_stats(csv_path):
    """Generate textual log stats summary + charts with logging."""
    if not os.path.exists(csv_path):
        logging.error(f"CSV file not found: {csv_path}")
        return {}, {}

    df = pd.read_csv(csv_path)
    logging.info(f"✅ Loaded {len(df)} events from {csv_path}")

    # Convert timestamp columns to datetime
    if "TimeCreated" in df.columns:
        df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], errors="coerce")
    elif "Timestamp" in df.columns:
        df["TimeCreated"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    else:
        df["TimeCreated"] = pd.NaT

    # --- Print textual stats summary ---
    total_logs = len(df)
    unique_event_ids = df["EventID"].nunique() if "EventID" in df.columns else 0
    top_event_ids = df["EventID"].value_counts().head(5) if "EventID" in df.columns else None

    time_min = df["TimeCreated"].min() if not df["TimeCreated"].isnull().all() else "N/A"
    time_max = df["TimeCreated"].max() if not df["TimeCreated"].isnull().all() else "N/A"

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
        print(tabulate(top_event_ids.reset_index().values, headers=["EventID", "Count"], tablefmt="grid"))

    # --- Generate charts ---
    # For plots, use "TimeCreated" and "EventID"
    df["Hour"] = df["TimeCreated"].dt.hour
    df["Weekday"] = df["TimeCreated"].dt.day_name()

    # Event ID distribution plot
    plt.figure(figsize=(10, 5))
    event_counts = df["EventID"].value_counts()
    sns.barplot(x=event_counts.index.astype(str), y=event_counts.values, palette="viridis", hue=event_counts.index.astype(str), legend=False)
    plt.title("Top Event IDs")
    plt.xlabel("Event ID")
    plt.ylabel("Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    os.makedirs("output", exist_ok=True)
    plt.savefig("output/event_id_distribution.png")
    plt.close()
    logging.info("Saved plot: output/event_id_distribution.png")

    # Logons by hour
    plt.figure(figsize=(10, 5))
    hourly_counts = df["Hour"].value_counts().sort_index()
    sns.barplot(x=hourly_counts.index, y=hourly_counts.values, palette="Blues", hue=hourly_counts.index, legend=False)
    plt.title("Logon Events by Hour")
    plt.xlabel("Hour of Day")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig("output/logons_by_hour.png")
    plt.close()
    logging.info("Saved plot: output/logons_by_hour.png")

    # Logons by weekday
    plt.figure(figsize=(10, 5))
    weekday_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    weekday_counts = df["Weekday"].value_counts().reindex(weekday_order).fillna(0)
    sns.barplot(x=weekday_counts.index, y=weekday_counts.values, palette="coolwarm", hue=weekday_counts.index, legend=False)
    plt.title("Events by Weekday")
    plt.xlabel("Day of Week")
    plt.ylabel("Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("output/logons_by_weekday.png")
    plt.close()
    logging.info("Saved plot: output/logons_by_weekday.png")

    # Logon success vs failure (Event IDs 4624 vs 4625)
    plt.figure(figsize=(8, 4))
    logon_subset = df[df["EventID"].isin([4624, 4625])]
    counts = logon_subset["EventID"].value_counts().sort_index()
    labels = {4624: "Success (4624)", 4625: "Failure (4625)"}
    sns.barplot(x=[labels[e] for e in counts.index], y=counts.values, palette="Set2", hue=[labels[e] for e in counts.index], legend=False)
    plt.title("Logon Success vs Failure")
    plt.xlabel("Logon Type")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig("output/success_vs_failed_logons.png")
    plt.close()
    logging.info("Saved plot: output/success_vs_failed_logons.png")

    # User activity heatmap
    df["AccountName"] = df.get("SubjectUserName", pd.Series()).combine_first(df.get("TargetUserName", pd.Series()))
    df.dropna(subset=["AccountName", "Hour"], inplace=True)
    heatmap_data = df.pivot_table(index="AccountName", columns="Hour", aggfunc="size", fill_value=0)
    plt.figure(figsize=(12, 8))
    sns.heatmap(heatmap_data, cmap="YlGnBu", linewidths=0.3)
    plt.title("User Activity by Hour")
    plt.xlabel("Hour of Day")
    plt.ylabel("Account Name")
    plt.tight_layout()
    plt.savefig("output/user_activity_heatmap.png")
    plt.close()
    logging.info("Saved plot: output/user_activity_heatmap.png")

    # Logon spike timeseries
    df["DateHour"] = df["TimeCreated"].dt.floor("h")
    timeseries = df.groupby("DateHour").size()
    plt.figure(figsize=(12, 5))
    timeseries.plot(marker='o', linestyle='-', color='red')
    plt.title("Logon Events Over Time")
    plt.xlabel("Time (Hourly)")
    plt.ylabel("Number of Events")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("output/logon_spike_timeseries.png")
    plt.close()
    logging.info("Saved plot: output/logon_spike_timeseries.png")

    logging.info("✅ Log statistics complete.")

    # Return summary dict + image paths for reports if needed
    return {
        "total_logs": total_logs,
        "unique_event_ids": unique_event_ids,
        "top_event_ids": top_event_ids.to_dict() if top_event_ids is not None else {},
        "time_range": {"start": str(time_min), "end": str(time_max)},
    }, {
        "event_id_distribution": "output/event_id_distribution.png",
        "logons_by_hour": "output/logons_by_hour.png",
        "logons_by_weekday": "output/logons_by_weekday.png",
        "success_vs_failed_logons": "output/success_vs_failed_logons.png",
        "user_activity_heatmap": "output/user_activity_heatmap.png",
        "logon_spike_timeseries": "output/logon_spike_timeseries.png",
    }


if __name__ == "__main__":
    generate_log_stats("output/parsed_security_logs.csv")
