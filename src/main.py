# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/main.py
# CLI entry point for SOC-Log-Analyzer

import argparse
import sys
import os
from pathlib import Path
import yaml
import logging
import pandas as pd

from windows_parser import parse_evtx_to_csv
from analyzer import run_threat_detection
from log_stats import generate_log_stats
from report.report_generator import generate_full_report
from report.report_text import generate_text_report  # Optional: fallback text report

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("SOC-Log-Analyzer")


# --- Load Configuration ---
def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
    if not os.path.exists(config_path):
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


# --- Main CLI ---
def main():
    parser = argparse.ArgumentParser(description="SOC Log Analyzer - Real-World SOC Tool")
    parser.add_argument('--parse', action='store_true', help='Parse EVTX log to CSV')
    parser.add_argument('--analyze', action='store_true', help='Run threat detection')
    parser.add_argument('--report', action='store_true', help='Generate all reports')
    parser.add_argument('--stats', action='store_true', help='Show log statistics from parsed CSV')
    parser.add_argument('--all', action='store_true', help='Run full pipeline: parse + analyze + report + stats')

    args = parser.parse_args()
    config = load_config()

    # --- Paths from config ---
    input_evtx = config.get("input_evtx")
    parsed_csv = config.get("parsed_csv")
    report_output_dir = Path(config.get("report_output_dir", "output/reports"))
    chart_paths = config.get("chart_paths", [])
    wkhtmltopdf_path = config.get("wkhtmltopdf_path", None)

    # --- Step 1: Parse EVTX ---
    if args.parse or args.all:
        logger.info("📥 Parsing EVTX log file...")
        parse_evtx_to_csv(input_evtx, parsed_csv)
        logger.info("✅ Parsing complete.\n")

    # --- Step 2: Log Statistics ---
    stats = None
    if args.stats or args.all:
        logger.info("📊 Generating Log Statistics...")
        stats, charts = generate_log_stats(parsed_csv)
        # No duplicate "Log statistics complete" logging
        logger.info("📊 Log statistics generated successfully.\n")

    # --- Step 3: Threat Detection ---
    detectors_results = None
    if args.analyze or args.all:
        if not os.path.exists(parsed_csv):
            logger.error(f"Parsed CSV not found: {parsed_csv}. Please parse logs first.")
            sys.exit(1)

        logger.info("🔍 Running Threat Detection Rules...")
        df = pd.read_csv(parsed_csv)
        detectors_results = run_threat_detection(df)

        alert_count = len(detectors_results) if detectors_results else 0
        if alert_count == 0:
            print("✅ No threats detected.")
        else:
            print(f"⚠️ {alert_count} potential threat(s) detected:\n")
            for idx, alert in enumerate(detectors_results, 1):
                print(f"{idx}. {alert}")
        logger.info("✅ Threat detection complete.\n")

    # --- Step 4: Report Generation ---
    if args.report or args.all:
        if not os.path.exists(parsed_csv):
            logger.error(f"Parsed CSV not found: {parsed_csv}. Cannot generate report.")
            sys.exit(1)

        logger.info("📝 Generating Reports...")
        df = pd.read_csv(parsed_csv)

        result = generate_full_report(
            parsed_df=df,
            detectors_results=detectors_results,
            stats=stats,  # pass stats to report generator
            chart_paths=chart_paths,
            output_dir=report_output_dir,
            wkhtmltopdf_path=wkhtmltopdf_path
        )
        logger.info(f"✅ Report generation complete. Files saved at: {result['out_dir']}\n")

        # Optional: generate plain text report
        generate_text_report(
            result.get("summary", {}),
            detectors_results or [],
            result["out_dir"]
        )

    # --- No Arguments ---
    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

