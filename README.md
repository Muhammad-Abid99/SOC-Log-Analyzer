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

> **SOC Log Analyzer** is a real-world cybersecurity tool, currently in MVP stage, designed to help SOC teams parse, analyze, detect, and report threats in Windows Event Logs using Python and Data Science.

---

## 🧠 Important Notes for Users

🚨 This tool is in **active development (MVP phase)**, designed for real-world SOC use.

- 🔐 Place your own Windows Event Log files (`.evtx`) inside the `data/` folder.  
- ⚠️ The `output/` folder contains parsed CSVs, reports, and visualizations — **handle sensitive data carefully**.  
- ✅ Core functionality includes robust parsing, multiple threat detectors, detailed statistics, and professional report generation (text, HTML, PDF).  
- ⚙️ Reporting is fully implemented inside `src/report/` — **the old `templates/` folder has been removed** to simplify project structure.

---

## 🌐 Project Structure

```text
SOC-Log-Analyzer/
├── data/                         ← Windows Event Log files (.evtx) — user-provided, sensitive data  
├── output/                       ← Generated CSVs, reports, and visualizations  
├── src/
│   ├── main.py                   ← CLI entry point for the entire pipeline  
│   ├── windows_parser.py         ← EVTX to CSV parser  
│   ├── analyzer.py               ← Threat detection engine  
│   ├── detector_manager.py       ← Manages detection modules coordination  
│   ├── detectors/                ← Detection modules (Brute Force, New User, etc.)  
│   ├── log_stats.py              ← Statistics and visualization  
│   └── report/                  ← Complete report generators (text, HTML, PDF)  
│       ├── report_generator.py  ← HTML & PDF report generation (using wkhtmltopdf)  
│       └── report_text.py       ← Professional text summary report  
├── config.yaml                  ← Centralized configuration for paths & settings  
├── requirements.txt             ← Python dependencies with pinned versions  
├── .gitignore                   ← Ignores sensitive logs, caches, and outputs as needed  
├── LICENSE                     ← Apache License 2.0  
├── README.md                   ← This document  
└── CHANGELOG.md                ← Version history and updates  
````

---

## ✅ Completed Features So Far

* ✅ Clean, production-ready modular codebase with a clear structure
* ✅ YAML-based configuration for all paths and settings
* ✅ CLI with flexible flags: `--parse`, `--analyze`, `--stats`, `--report`, `--all`
* ✅ Reliable EVTX parsing to CSV with limits
* ✅ Four key threat detection modules implemented and integrated:

  * Brute Force Attack detection
  * New User Account Creation detection
  * Privileged Logon detection
  * Unusual Logon Time detection
* ✅ Log statistics generation with meaningful insights and visualizations
* ✅ Fully functional professional report generation:

  * Plain text summary report (`report_text.py`)
  * Rich HTML report (`report_generator.py`)
  * PDF report from HTML using `wkhtmltopdf`

---

## 📦 Requirements

The project depends on the following Python packages (pinned tested versions):

```
# Requires Python 3.10+

pandas==1.5.3
numpy==1.24.3
matplotlib==3.7.1
seaborn==0.12.2
pyyaml==6.0
pdfkit==1.0.0
python-dateutil==2.8.2
pywin32==305
```

*Note:*

* `wkhtmltopdf` binary is required on your system path or specify its path in `main.py` or `report_generator.py` for PDF generation.
* `pywin32` is required for Windows EVTX parsing compatibility.

---

## 🚀 How to Use

### 1. Clone the Repository

```bash
git clone https://github.com/Muhammad-Abid99/SOC-Log-Analyzer.git
cd SOC-Log-Analyzer
```

### 2. Install all dependencies with:

```bash
pip install -r requirements.txt
```

### 3. Prepare Your Windows Event Logs Because

- This repository **does NOT include raw Windows Event Log files (`.evtx`) or parsed CSVs** due to privacy and sensitivity concerns.  
- The `data/` folder and `output/` folder contents are **excluded from version control** to protect sensitive information.  
- To fully test and use this tool, **please provide your own Windows Security Event Logs** from your machine’s Event Viewer and place them inside the `data/` folder.  
- All generated output files including parsed CSVs, reports (text, HTML, PDF), and visualizations will be saved in the `output/` folder during execution.

---


Place your `.evtx` log files inside the `data/` folder, e.g.:

```bash
data/security_recent.evtx
```

### 4. Run the Tool Using CLI Flags

Use CLI flags to run specific pipeline stages or full workflow:

```bash
python src/main.py --parse       # Parse EVTX logs into CSV format
python src/main.py --analyze     # Run threat detection on parsed CSV
python src/main.py --stats       # Generate log statistics report
python src/main.py --report      # Generate all reports (text, HTML, PDF)
python src/main.py --all         # Run entire pipeline: parse → analyze → stats → report
```

## ⚠️ Important Warnings

* This tool is **not** an end-user product but a real-world SOC analysis MVP under active development.
* **Handle sensitive logs and outputs carefully**. Do not commit raw logs or sensitive data to public repositories.
* `wkhtmltopdf` installation is required for PDF report generation. See [wkhtmltopdf.org](https://wkhtmltopdf.org/) for instructions.
* Contributions and SOC environment testing feedback are highly welcome.

---

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE) and complies with [REUSE](https://reuse.software/) standards.

---

## 🧑‍💻 Author

Developed and maintained by **G. Mohammad**
📫 Contact: [ghmuhammad324@gmail.com](mailto:ghmuhammad324@gmail.com)

---

## 🔮 Roadmap & Next Steps

* ⚙️ Complete advanced anomaly heatmaps and interactive data visualizations
* 📧 Implement automated email alerts for detected threats
* 🚀 Develop a web dashboard (Streamlit or FastAPI) for SOC analysts
* 🚫 Integrate with enterprise SIEM systems (Splunk, ELK)
* 🤖 Research and add ML-based anomaly detection for deeper threat hunting

---

> ⚠️ **Not a portfolio project** — a production-grade SOC tool under active development, built with ❤️ and integrity to make a real impact in cybersecurity.
