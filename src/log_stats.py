# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

import os
import logging
import warnings
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from tabulate import tabulate

# --- Logging setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("log_stats")

# Suppress FutureWarnings and Seaborn/Matplotlib info logs
warnings.filterwarnings("ignore", category=FutureWarning)
logging.getLogger("matplotlib").setLevel(logging.WARNING)
logging.getLogger("seaborn").setLevel(logging.WARNING)

def generate_log_stats(csv_path):
    """Generate textual log stats summary + charts with clean logging."""

    if not os.path.exists(csv_path):
        logger.error(f"CSV file not found: {csv_path}")
        return {}, {}

    df = pd.read_csv(csv_path)
    logger.info(f"✅ Loaded {len(df)} events from {csv_path}")

    # Convert timestamp columns to datetime
    if "TimeCreated" in df.columns:
        df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], errors="coerce")
    elif "Timestamp" in df.columns:
        df["TimeCreated"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    else:
        df["TimeCreated"] = pd.NaT

    # --- Textual stats summary ---
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

    # --- Prepare charts ---
    df["Hour"] = df["TimeCreated"].dt.hour
    df["Weekday"] = df["TimeCreated"].dt.day_name()
    os.makedirs("output", exist_ok=True)

    # Helper to save plots cleanly
    def save_plot(fig, filename):
        fig.tight_layout()
        fig.savefig(filename)
        plt.close(fig)
        logger.info(f"Saved plot: {filename}")

    # Event ID distribution
    fig = plt.figure(figsize=(10, 5))
    sns.barplot(x=df["EventID"].value_counts().index.astype(str),
                y=df["EventID"].value_counts().values,
                palette="viridis")
    plt.title("Top Event IDs")
    plt.xlabel("Event ID")
    plt.ylabel("Count")
    save_plot(fig, "output/event_id_distribution.png")

    # Hourly logons
    fig = plt.figure(figsize=(10, 5))
    sns.barplot(x=df["Hour"].value_counts().sort_index().index,
                y=df["Hour"].value_counts().sort_index().values,
                palette="Blues")
    plt.title("Logon Events by Hour")
    plt.xlabel("Hour of Day")
    plt.ylabel("Count")
    save_plot(fig, "output/logons_by_hour.png")

    # Weekday distribution
    weekday_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    weekday_counts = df["Weekday"].value_counts().reindex(weekday_order).fillna(0)
    fig = plt.figure(figsize=(10, 5))
    sns.barplot(x=weekday_counts.index, y=weekday_counts.values, palette="coolwarm")
    plt.title("Events by Weekday")
    plt.xlabel("Day of Week")
    plt.ylabel("Count")
    save_plot(fig, "output/logons_by_weekday.png")

    # Success vs failure logons
    logon_subset = df[df["EventID"].isin([4624, 4625])]
    counts = logon_subset["EventID"].value_counts().sort_index()
    labels = {4624: "Success (4624)", 4625: "Failure (4625)"}
    fig = plt.figure(figsize=(8, 4))
    sns.barplot(x=[labels[e] for e in counts.index], y=counts.values, palette="Set2")
    plt.title("Logon Success vs Failure")
    plt.xlabel("Logon Type")
    plt.ylabel("Count")
    save_plot(fig, "output/success_vs_failed_logons.png")

    # User activity heatmap
    df["AccountName"] = df.get("SubjectUserName", pd.Series()).combine_first(df.get("TargetUserName", pd.Series()))
    df.dropna(subset=["AccountName", "Hour"], inplace=True)
    heatmap_data = df.pivot_table(index="AccountName", columns="Hour", aggfunc="size", fill_value=0)
    fig = plt.figure(figsize=(12, 8))
    sns.heatmap(heatmap_data, cmap="YlGnBu", linewidths=0.3)
    plt.title("User Activity by Hour")
    plt.xlabel("Hour of Day")
    plt.ylabel("Account Name")
    save_plot(fig, "output/user_activity_heatmap.png")

    # Logon timeseries
    df["DateHour"] = df["TimeCreated"].dt.floor("h")
    timeseries = df.groupby("DateHour").size()
    fig = plt.figure(figsize=(12, 5))
    timeseries.plot(marker='o', linestyle='-', color='red')
    plt.title("Logon Events Over Time")
    plt.xlabel("Time (Hourly)")
    plt.ylabel("Number of Events")
    plt.grid(True)
    save_plot(fig, "output/logon_spike_timeseries.png")

    logger.info("✅ Log statistics complete.")

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

# --- For testing only ---
if __name__ == "__main__":
    generate_log_stats("output/parsed_security_logs.csv")

