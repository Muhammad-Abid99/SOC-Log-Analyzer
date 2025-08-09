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

> **SOC Log Analyzer** is a real-world cybersecurity tool (currently MVP phase) built to help SOC teams parse, analyze, and detect threats in Windows Event Logs using Python and Data Science foundations.

---

## 🧠 Important Notes for Users

🚨 This tool is in **active development, early MVP stage**, designed for real-world SOC use.

* 🔐 Place your own Windows Event Log files (`.evtx`) inside the `data/` folder.  
* ⚠️ The `output/` folder stores parsed CSVs, reports, and visualizations — sensitive data must be managed carefully.  
* 📋 The `requirements.txt` file needs manual updates with required Python packages as the project evolves.  
* ✅ Core threat detectors (Brute Force, New User Creation, Privileged Logon, Unusual Logon Time) are functional.  
* 📊 Basic log statistics generation (`src/log_stats.py`) is implemented and integrated.  
* ⚙️ Report generation and visualization features are under active development (`src/report/` and `templates/`).  

---

## 🌐 Project Structure

```text
SOC-Log-Analyzer/
├── data/                          ← Your `.evtx` Windows Event Logs (tracked, but sensitive files must be handled carefully)
├── output/                        ← Parsed CSVs, generated reports, and visualizations (tracked except sensitive raw data)
├── src/
│   ├── main.py                    ← ✅ CLI entry point for full pipeline control
│   ├── windows_parser.py          ← ✅ Parses `.evtx` files into structured `.csv`
│   ├── analyzer.py                ← ✅ Runs threat detection rules on parsed logs
│   ├── detector_manager.py        ← ✅ Coordinates multiple detection modules
│   ├── detectors/                 ← ✅ Individual detection modules (Brute Force, New User, etc.)
│   ├── log_stats.py               ← ✅ Generates descriptive statistics and insights from logs
│   └── report/                   ← ⚙️ Report generators (text, HTML, PDF) — in progress
├── templates/                    ← ⚙️ Jinja2 templates for report generation — in progress
├── config.yaml                   ← ✅ Centralized configuration for input/output paths & settings
├── .gitignore                    ← ✅ Configured to exclude sensitive raw data but track important folders
├── .pre-commit-config.yaml       ← ⚙️ Optional linting and REUSE compliance setup
├── CHANGELOG.md                  ← Version history and updates
├── LICENSE                      ← Apache License 2.0
├── README.md                    ← Project overview and usage instructions
└── requirements.txt              ← Python dependencies (manually maintained)
````

---

## ✅ What Has Been Completed So Far

* ✅ Clean, production-ready project structure and modular codebase
* ✅ YAML-based global configuration system
* ✅ CLI with flexible flags: `--parse`, `--analyze`, `--report`, `--stats`, `--all`
* ✅ Reliable `.evtx` Windows Event Log parsing to CSV
* ✅ Four key detection modules implemented and integrated:

  * Brute Force Attack detection
  * New User Account Creation detection
  * Privileged Logon detection
  * Unusual Logon Time detection
* ✅ Log statistics generation with meaningful insights
* ✅ Basic report generation framework with text, HTML, and PDF outputs (work in progress)

---

## 🚀 How to Use (Command Line Interface)

### 1. Clone the Repository

```bash
git clone https://github.com/Muhammad-Abid99/SOC-Log-Analyzer.git
cd SOC-Log-Analyzer
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

*(Update `requirements.txt` manually as new dependencies are added)*

### 3. Add Your Logs

Place your `.evtx` Windows Event Log files inside the `data/` folder, for example:

```bash
data/security_recent.evtx
```

### 4. Run the Tool

Use the CLI flags to run specific pipeline stages or full workflow:

```bash
python src/main.py --parse       # Parse EVTX logs into CSV format
python src/main.py --analyze     # Run threat detection on parsed CSV
python src/main.py --stats       # Generate log statistics report
python src/main.py --report      # Generate all reports (text, HTML, PDF)
python src/main.py --all         # Run entire pipeline: parse → analyze → stats → report
```

---

## ⚠️ Important Warnings

* This tool is **not** a polished end-user product but a real-world SOC analysis tool under active development.
* Sensitive data **must be handled with care** — do not commit raw logs or parsed sensitive info to public repositories unless sanitized.
* Contributions, testing, and real SOC environment feedback are welcome to improve accuracy and robustness.

---

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE) and complies with [REUSE](https://reuse.software/) standards.

---

## 🧑‍💻 Author

Developed and maintained by **G. Mohammad**
📫 Contact: [ghmuhammad324@gmail.com](mailto:ghmuhammad324@gmail.com)

---

## 🔮 Roadmap & Next Steps

* ⚙️ Complete HTML + PDF reporting with rich visualizations and templates
* 📊 Add anomaly heatmaps and detailed data visualizations
* 📧 Implement automated email alerts for detected threats
* 🚀 Develop a web dashboard (Streamlit or FastAPI) for SOC analysts
* 🚫 Integrate with enterprise SIEM systems (Splunk, ELK)
* 🤖 Research and add ML-based anomaly detection for more sophisticated threat hunting

---

> ⚠️ **Not a portfolio project** — a production-grade SOC tool under active development, built with ❤️ and integrity to make a real impact in cybersecurity.
