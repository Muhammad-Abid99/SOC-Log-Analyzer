<!--
SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# **SOC Log Analyzer**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![REUSE Compliance](https://img.shields.io/badge/REUSE-Compliant-brightgreen)](https://reuse.software/)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![Status](https://img.shields.io/badge/Stage-MVP--Ready-brightgreen.svg)
![Made With Love](https://img.shields.io/badge/Made%20With-%E2%9D%A4-red)

---

## 📌 Overview

**SOC Log Analyzer** is a **real-world SOC (Security Operations Center) tool**, developed to help cybersecurity analysts **rapidly detect, investigate, and report** on suspicious activity in Windows Event Logs.

Unlike portfolio/demo projects, this tool is **production-oriented** — designed to handle real-world datasets, meet SOC operational needs, and generate **professional, investor-ready reports**.

It is currently in the **MVP stage**, with complete core features and a roadmap for **ML/DL-driven anomaly detection**.

**Author:** *G. Mohammad* — Cybersecurity & Data Science Developer
📧 [ghmuhammad324@gmail.com](mailto:ghmuhammad324@gmail.com)

---

## 🔍 Real-World Problem It Solves

SOC teams often face:

* **High volume** of raw log data that’s hard to parse manually.
* **Delayed threat detection** due to scattered log sources.
* **Inefficient reporting** for management or compliance.

**SOC Log Analyzer** addresses this by:

* Parsing `.evtx` files directly to structured CSV.
* Running multiple **modular threat detectors** in seconds.
* Producing **actionable, multi-format reports** with severity scoring and timestamps.

---

## 🧩 Current MVP Capabilities

### **1. Data Parsing**

* Converts Windows **Security Event Logs (.evtx)** into clean, analysis-ready CSV.
* Configurable **parse limits** to handle both large datasets and quick tests.

### **2. Integrated Threat Detectors**

Fully modular detectors in `src/detectors/`:

1. **Brute Force Attack Detector** (multiple failed logons, Event ID 4625)
2. **New User Creation Detector** (Event ID 4720)
3. **Privileged Logon Detector** (Event ID 4672)
4. **Unusual Logon Time Detector** (off-hours logons, Event ID 4624)
5. **Account Lockout Detector** (Event ID 4740 with failed logon correlation)

---

### **3. Detection Manager**

* Coordinates multiple detectors.
* Groups alerts by type & user.
* Assigns **severity levels** (`Low`, `Medium`, `High`).
* Tracks **first seen / last seen timestamps** for every alert group.

---

### **4. Professional Reporting**

Multi-format output in `src/report/`:

* **Text Summary (`report_text.py`)**

  * Now includes accurate **First Seen / Last Seen** timestamps in Grouped Alerts Summary.
* **HTML Report (`report_generator.py`)**

  * Styled with **Jinja2 templates** for clean readability.
* **PDF Report**

  * Generated from HTML via `wkhtmltopdf`.
  * Suitable for **board meetings, compliance reports, and investor demos**.

---

### **5. Statistical Analysis**

* Event count breakdowns.
* Severity distribution charts.
* Time-series visualizations for spikes in activity.

---

## 📂 Project Structure

```text
SOC-Log-Analyzer/
├── data/                   # Input EVTX files (sensitive, not in Git)
├── output/                 # CSV, charts, reports (sensitive)
├── src/
│   ├── main.py             # CLI entry point
│   ├── windows_parser.py   # EVTX parsing
│   ├── detector_manager.py # Runs all detectors + severity scoring
│   ├── detectors/          # All threat detection modules
│   ├── log_stats.py        # Visualization & stats
│   └── report/             # Report generation modules
├── config.yaml             # Centralized configuration for paths and parameters
├── requirements.txt        # Dependencies
├── LICENSE                 # Apache License 2.0
├── README.md
├── README_INVESTORS.md     # Business value & growth potential
└── CHANGELOG.md            # Version history and updates
```

---

## 🛠 Requirements

* **Python 3.10+**
* Packages (pinned versions):

```python
pandas==1.5.3
numpy==1.24.3
matplotlib==3.7.1
seaborn==0.12.2
pyyaml==6.0
pdfkit==1.0.0
python-dateutil==2.8.2
pywin32==305
```

**Note:**

* `wkhtmltopdf` binary must be installed for PDF generation.
* `pywin32` is required for Windows EVTX parsing.

---

## 🚀 How to Use

### 1. Clone the Repository

```bash
git clone https://github.com/Muhammad-Abid99/SOC-Log-Analyzer.git
cd SOC-Log-Analyzer
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Add Your Windows Event Logs

Place `.evtx` files in the `data/` folder, e.g.:

```bash
data/security_recent.evtx
```

### 4. Run via CLI Flags

```bash
python src/main.py --parse       # Convert EVTX to CSV
python src/main.py --analyze     # Run all detectors
python src/main.py --stats       # Generate charts
python src/main.py --report      # Generate Text, HTML & PDF reports
python src/main.py --all         # Full pipeline
```

---

## ⚠ Security & Confidentiality

* All logs and reports should be handled as **classified SOC material**.
* Do **not** share parsed data or reports publicly.

---

## 📈 Roadmap

* ✅ Core detection & reporting (MVP)
* 📌 Email alerts
* 📌 Interactive web dashboard (Streamlit/FastAPI)
* 📌 SIEM integration (Splunk, ELK)
* 📌 ML-based anomaly detection
* 📌 Agentic AI threat-hunting assistant

---

> 💡 **Not a toy. Not a portfolio project.**
> This is an operational SOC tool, built with ❤️ and security expertise,
> ready to scale with advanced detection and AI-driven analytics.
