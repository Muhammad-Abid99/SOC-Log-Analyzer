# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/main.py
# CLI entry point for SOC-Log-Analyzer
import argparse
import sys
from windows_parser import parse_evtx_to_csv
from analyzer import run_threat_detection
from report.report_generator import generate_html_report, generate_pdf_from_html
from report.report_text import generate_text_report
import yaml
import os

# Load config
def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
    with open(config_path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)

def main():
    parser = argparse.ArgumentParser(description="SOC Log Analyzer - Real-World SOC Tool")
    parser.add_argument('--parse', action='store_true', help='Parse EVTX log to CSV')
    parser.add_argument('--analyze', action='store_true', help='Run threat detection')
    parser.add_argument('--report', action='store_true', help='Generate all reports')
    parser.add_argument('--all', action='store_true', help='Run full pipeline: parse + analyze + report')

    args = parser.parse_args()
    config = load_config()

    if args.parse or args.all:
        print("📥 Parsing EVTX log file...")
        parse_evtx_to_csv(config["input_evtx"], config["parsed_csv"])
        print("✅ Parsing complete.\n")

    if args.analyze or args.all:
        print("🔍 Running Threat Detection Rules...")
        run_threat_detection(config["parsed_csv"])
        print("✅ Threat detection complete.\n")

    if args.report or args.all:
        print("📝 Generating Reports...")
        generate_text_report(config["parsed_csv"])
        generate_html_report(config["parsed_csv"], config["html_report"])
        generate_pdf_from_html(config["html_report"], config["pdf_report"])
        print("✅ Report generation complete.\n")

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
