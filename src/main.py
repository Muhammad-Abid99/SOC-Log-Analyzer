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

from windows_parser import parse_evtx_to_csv
from analyzer import run_threat_detection
from log_stats import generate_log_stats
from report.report_generator import generate_full_report
from report.report_text import generate_text_report  # Optional: to generate text report fallback

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("main")

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
    with open(config_path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)

def main():
    parser = argparse.ArgumentParser(description="SOC Log Analyzer - Real-World SOC Tool")
    parser.add_argument('--parse', action='store_true', help='Parse EVTX log to CSV')
    parser.add_argument('--analyze', action='store_true', help='Run threat detection')
    parser.add_argument('--report', action='store_true', help='Generate all reports')
    parser.add_argument('--stats', action='store_true', help='Show log statistics from parsed CSV')
    parser.add_argument('--all', action='store_true', help='Run full pipeline: parse + analyze + report + stats')

    args = parser.parse_args()
    config = load_config()

    # Paths from config
    input_evtx = config.get("input_evtx")
    parsed_csv = config.get("parsed_csv")
    report_output_dir = Path(config.get("report_output_dir", "output/reports"))
    chart_paths = config.get("chart_paths", [])
    wkhtmltopdf_path = config.get("wkhtmltopdf_path", None)

    if args.parse or args.all:
        logger.info("📥 Parsing EVTX log file...")
        parse_evtx_to_csv(input_evtx, parsed_csv)
        logger.info("✅ Parsing complete.\n")

    if args.stats or args.all:
        logger.info("📊 Generating Log Statistics...")
        generate_log_stats(parsed_csv)
        logger.info("✅ Log statistics complete.\n")

    if args.analyze or args.all:
        logger.info("🔍 Running Threat Detection Rules...")
        run_threat_detection(parsed_csv)
        logger.info("✅ Threat detection complete.\n")

    if args.report or args.all:
        logger.info("📝 Generating Reports...")
        import pandas as pd
        df = pd.read_csv(parsed_csv)

        detectors_results = None  # Placeholder until detection results are integrated

        result = generate_full_report(
            parsed_df=df,
            detectors_results=detectors_results,
            stats=None,  # Auto-compute stats inside the report generator
            chart_paths=chart_paths,
            output_dir=report_output_dir,
            wkhtmltopdf_path=wkhtmltopdf_path
        )
        logger.info(f"✅ Report generation complete. Files saved at: {result['out_dir']}\n")

        generate_text_report(
            result.get("summary", {}),
            detectors_results or [],
            result["out_dir"]
        )

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
