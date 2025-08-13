<!--
SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# SOC Log Analyzer

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![REUSE Compliance](https://img.shields.io/badge/REUSE-Compliant-brightgreen)](https://reuse.software/)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![Status](https://img.shields.io/badge/Stage-MVP--In--Progress-orange.svg)
![Made With Love](https://img.shields.io/badge/Made%20With-%E2%9D%A4-red)

> **SOC Log Analyzer** is a production-oriented cybersecurity tool (MVP stage),
> designed for Security Operations Centers (SOC) to parse, analyze, detect threats,
> and generate comprehensive reports from Windows Event Logs using Python and Data Science.

---

## 🧠 Important Notes

🚨 This tool is in **active development (MVP phase)** for real-world SOC use.

- Place Windows Event Log files (`.evtx`) inside the `data/` directory.  
- The `output/` folder stores parsed CSVs, reports, and visualizations — **treat all output files as sensitive**.  
- Core features include EVTX parsing, five integrated threat detectors, statistics, and professional multi-format report generation.  

---

## 🌐 Project Structure

```text
SOC-Log-Analyzer/
├── data/                         ← User-provided Windows Event Log files (.evtx)
├── output/                       ← Generated CSVs, visualizations, and reports
├── src/
│   ├── main.py                   ← CLI entry point running full pipeline or selective modules
│   ├── windows_parser.py         ← EVTX to CSV parser
│   ├── analyzer.py               ← Threat detection engine
│   ├── detector_manager.py       ← Coordinates running multiple detectors
│   ├── detectors/                ← Modular detectors (brute force, new user, etc.)
│   ├── log_stats.py              ← Log statistics and visualization
│   └── report/                  ← Report generation modules
│       ├── report_generator.py  ← HTML and PDF report generation (uses wkhtmltopdf)
│       └── report_text.py       ← Text summary report
├── config.yaml                  ← Centralized configuration for paths and parameters
├── requirements.txt             ← Python dependencies (pinned versions)
├── .gitignore                   ← Ignores sensitive logs, caches, outputs
├── LICENSE                      ← Apache License 2.0
├── README.md                    ← This document
└── CHANGELOG.md                 ← Version history and updates
````

---

## ✅ Completed Features (MVP)

* ✅ Modular, production-quality Python codebase

* ✅ YAML-based centralized configuration

* ✅ CLI interface with flexible flags for all pipeline stages

* ✅ Parsing of Windows EVTX logs to CSV format

* ✅ Five functional threat detection modules:

  * Brute Force Attack detection
  * New User Account Creation detection
  * Privileged Logon detection
  * Unusual Logon Time detection
  * Account Lockout detection

* ✅ Detailed log statistics with visualizations saved as PNGs

* ✅ Professional multi-format report generation:

  * Plain text summary
  * Rich HTML report
  * PDF report generated from HTML using `wkhtmltopdf`

---

## 📦 Requirements

* **Python 3.10+**
* Packages (pinned versions):

```
pandas==1.5.3
numpy==1.24.3
matplotlib==3.7.1
seaborn==0.12.2
pyyaml==6.0
pdfkit==1.0.0
python-dateutil==2.8.2
pywin32==305
```

**Notes:**

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
python src/main.py --parse       # Parse EVTX logs to CSV
python src/main.py --analyze     # Run all threat detectors
python src/main.py --stats       # Generate statistics and visualizations
python src/main.py --report      # Generate full reports (text, HTML, PDF)
python src/main.py --all         # Run entire pipeline
```

---

## ⚠️ Warnings

* This is **not an end-user application**, but a **production SOC tool MVP**.
* Treat logs and output data with **strict confidentiality**.
* Ensure `wkhtmltopdf` is installed for PDF generation.

---

## 📄 License

Apache License 2.0, SPDX-compliant.
Maintained by **G. Mohammad** — [ghmuhammad324@gmail.com](mailto:ghmuhammad324@gmail.com)

---

## 🔮 Roadmap & Next Steps

* Advanced anomaly heatmaps and interactive visualizations
* Automated email alerts for detected threats
* Web dashboard (Streamlit or FastAPI) for SOC analysts
* Integration with enterprise SIEM systems (Splunk, ELK)
* Research ML-based anomaly detection for deeper threat hunting

---

> ⚠️ **Not a portfolio project** — a real-world SOC tool built with ❤️ and integrity.
