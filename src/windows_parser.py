# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/windows_parser.py
# Parser for Windows EVTX logs

from Evtx.Evtx import Evtx
import pandas as pd
import xml.etree.ElementTree as ET
from tqdm import tqdm
import yaml

# 📥 Load config.yaml
def load_config(config_path="config.yaml"):
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def extract_event_fields(xml_str, ns):
    """Extract relevant fields from a single EVTX XML string"""
    root = ET.fromstring(xml_str)

    system = root.find("ns:System", ns)
    event_id = system.find("ns:EventID", ns).text if system is not None else None
    time_created = system.find("ns:TimeCreated", ns).attrib.get("SystemTime") if system is not None else None
    computer = system.find("ns:Computer", ns).text if system is not None else None
    provider = system.find("ns:Provider", ns).attrib.get("Name") if system is not None else None

    event_data = root.find("ns:EventData", ns)
    data_dict = {}
    if event_data is not None:
        for data in event_data.findall("ns:Data", ns):
            name = data.attrib.get("Name")
            value = data.text
            data_dict[name] = value

    return {
        "EventID": event_id,
        "TimeCreated": time_created,
        "Computer": computer,
        "Provider": provider,
        **data_dict
    }

def parse_evtx_to_csv(evtx_path, output_csv_path):
    """Parse EVTX log file and save extracted data to CSV"""
    config = load_config()
    parse_limit = config.get("parse_limit", 0)  # 0 means no limit

    namespace = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
    records = []

    with Evtx(evtx_path) as log:
        for i, record in enumerate(tqdm(log.records(), desc="Parsing EVTX Logs")):
            if parse_limit > 0 and i >= parse_limit:
                break
            try:
                xml_str = record.xml()
                extracted = extract_event_fields(xml_str, namespace)
                records.append(extracted)
            except Exception as e:
                print(f"⚠️ Skipping malformed record: {e}")
                continue

    df = pd.DataFrame(records)
    df.to_csv(output_csv_path, index=False)
    print(f"✅ Parsed {len(records)} logs saved to: {output_csv_path}")
