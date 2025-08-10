# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""
src/log_stats.py

Generates detailed statistics and visualizations from parsed CSV logs.
Designed for Real-world SOC-Log-Analyzer tool with investor-ready quality.
"""

import os
import logging
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

logger = logging.getLogger("log_stats")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

OUTPUT_DIR = Path("output")


def load_logs(csv_path: str) -> pd.DataFrame | None:
    """Load parsed CSV logs into a pandas DataFrame.

    Returns None if file missing or error occurs.
    """
    if not os.path.exists(csv_path):
        logger.error(f"CSV file not found: {csv_path}")
        logger.info("➡️ Please run '--parse' first to generate parsed logs.")
        return None

    try:
        df = pd.read_csv(csv_path)
        logger.info(f"✅ Loaded {len(df)} events from {csv_path}")

        # Normalize timestamp column (handle multiple possible names)
        for col in ["Timestamp", "TimeCreated", "TimeCreatedUTC"]:
            if col in df.columns:
                df["Timestamp"] = pd.to_datetime(df[col], errors="coerce")
                break
        else:
            logger.warning("No timestamp column found; 'Timestamp' set to NaT for all entries.")
            df["Timestamp"] = pd.NaT

        df.dropna(subset=["Timestamp"], inplace=True)

        # Create unified AccountName column from common user columns
        df["AccountName"] = df.get("SubjectUserName")
        if "TargetUserName" in df.columns:
            df["AccountName"] = df["AccountName"].fillna(df["TargetUserName"])

        return df
    except Exception as e:
        logger.error(f"Failed to load or process CSV: {e}")
        return None


def save_plot(fig, filename: str):
    """Helper to save matplotlib figure with tight layout."""
    output_path = OUTPUT_DIR / filename
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)
    logger.info(f"Saved plot: {output_path}")


def event_id_distribution(df: pd.DataFrame):
    """Generate and save plot for top 10 EventID counts."""
    dist = df["EventID"].value_counts()
    logger.info("\n📊 Event ID Distribution:\n%s", dist.head(10))

    fig, ax = plt.subplots(figsize=(10, 5))
    sns.countplot(data=df, x="EventID", order=dist.index[:10], hue=None)
    ax.set_title("Top 10 Event IDs")
    ax.set_xlabel("Event ID")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=45)

    save_plot(fig, "event_id_distribution.png")


def logons_by_hour(df: pd.DataFrame):
    """Generate and save plot of logon events by hour of day."""
    df["Hour"] = df["Timestamp"].dt.hour
    hourly_counts = df["Hour"].value_counts().sort_index()

    fig, ax = plt.subplots(figsize=(10, 4))
    sns.barplot(x=hourly_counts.index, y=hourly_counts.values, palette="Blues", hue=None)
    ax.set_title("Logon Events by Hour")
    ax.set_xlabel("Hour of Day")
    ax.set_ylabel("Count")

    save_plot(fig, "logons_by_hour.png")


def logons_by_weekday(df: pd.DataFrame):
    """Generate and save plot of logon events by weekday."""
    df["Weekday"] = df["Timestamp"].dt.day_name()
    weekday_counts = df["Weekday"].value_counts().reindex(
        ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    )

    fig, ax = plt.subplots(figsize=(10, 4))
    sns.barplot(x=weekday_counts.index, y=weekday_counts.values, palette="coolwarm", hue=None)
    ax.set_title("Events by Weekday")
    ax.set_xlabel("Day of Week")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=45)

    save_plot(fig, "logons_by_weekday.png")


def plot_success_vs_failed_logons(df: pd.DataFrame):
    """Plot and save successful vs failed logon events."""
    relevant_events = df[df["EventID"].isin([4624, 4625])]
    counts = relevant_events["EventID"].value_counts().sort_index()
    labels = {4624: "Successful (4624)", 4625: "Failed (4625)"}

    fig, ax = plt.subplots(figsize=(6, 4))
    sns.barplot(
        x=[labels[eid] for eid in counts.index],
        y=counts.values,
        palette="Set2",
        hue=None,
    )
    ax.set_title("Logon Success vs Failure")
    ax.set_xlabel("Logon Type")
    ax.set_ylabel("Count")

    save_plot(fig, "success_vs_failed_logons.png")


def user_activity_heatmap(df: pd.DataFrame):
    """Generate and save heatmap of user activity by hour."""
    df["Hour"] = df["Timestamp"].dt.hour
    df = df.dropna(subset=["AccountName"])
    user_hour_matrix = df.pivot_table(index="AccountName", columns="Hour", aggfunc="size", fill_value=0)

    fig, ax = plt.subplots(figsize=(12, 6))
    sns.heatmap(user_hour_matrix, cmap="YlGnBu", linewidths=0.5, ax=ax)
    ax.set_title("User Account Activity by Hour")
    ax.set_xlabel("Hour of Day")
    ax.set_ylabel("Account Name")

    save_plot(fig, "user_activity_heatmap.png")


def logon_spike_timeseries(df: pd.DataFrame):
    """Generate and save time series plot of logon event spikes."""
    df["DateHour"] = df["Timestamp"].dt.floor("h")
    time_series = df.groupby("DateHour").size()

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(time_series.index, time_series.values, marker="o", color="red")
    ax.set_title("Logon Events Over Time")
    ax.set_xlabel("Time (Hourly)")
    ax.set_ylabel("Number of Events")
    ax.grid(True)

    save_plot(fig, "logon_spike_timeseries.png")


def generate_log_stats(csv_path: str) -> tuple[dict, dict]:
    """Generate all statistics and visualizations, return summary data and image paths.

    Returns:
        summary_dict: dict with top event counts
        image_paths: dict mapping plot titles to their saved file paths
    """
    df = load_logs(csv_path)
    if df is None:
        return {}, {}

    event_id_distribution(df)
    logons_by_hour(df)
    logons_by_weekday(df)
    plot_success_vs_failed_logons(df)
    user_activity_heatmap(df)
    logon_spike_timeseries(df)

    logger.info("📈 All stats and visualizations saved to /output")

    summary_dict = {"event_id_counts": df["EventID"].value_counts().to_dict()}
    image_paths = {
        "Event ID Distribution": str(OUTPUT_DIR / "event_id_distribution.png"),
        "Logons by Hour": str(OUTPUT_DIR / "logons_by_hour.png"),
        "Events by Weekday": str(OUTPUT_DIR / "logons_by_weekday.png"),
        "Logon Success vs Failure": str(OUTPUT_DIR / "success_vs_failed_logons.png"),
        "User Activity Heatmap": str(OUTPUT_DIR / "user_activity_heatmap.png"),
        "Logon Spike Time Series": str(OUTPUT_DIR / "logon_spike_timeseries.png"),
    }

    return summary_dict, image_paths


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        logger.error("Usage: python log_stats.py <parsed_csv_path>")
        sys.exit(1)

    csv_file = sys.argv[1]
    generate_log_stats(csv_file)
