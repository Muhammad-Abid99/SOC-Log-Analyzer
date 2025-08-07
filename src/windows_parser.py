# SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
# SPDX-License-Identifier: Apache-2.0

# src/windows_parser.py
# Parser for Windows EVTX logs
from Evtx.Evtx import Evtx
import pandas as pd
import xml.etree.ElementTree as ET
from tqdm import tqdm

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
    namespace = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
    records = []

    with Evtx(evtx_path) as log:
        for record in tqdm(log.records(), desc="Parsing EVTX Logs"):
            try:
                xml_str = record.xml()
                extracted = extract_event_fields(xml_str, namespace)
                records.append(extracted)
            except Exception as e:
                print(f"⚠️ Skipping malformed record: {e}")
                continue

    df = pd.DataFrame(records)
    df.to_csv(output_csv_path, index=False)
    print(f"✅ Parsed logs saved to: {output_csv_path}")
