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

> **SOC Log Analyzer** is a real-world cybersecurity tool (MVP ready) designed to help SOC teams parse and analyze Windows Event Logs using Python and Data Science foundations.

---

## 🧠 Important Note for Users

🚨 This tool is currently in **early MVP phase** and actively being improved.

* 🔐 **Provide your own `.evtx` Windows Event Log** files inside the `data/` folder.
* 📦 `requirements.txt` needs to be filled with required libraries.
* ✅ Basic detectors (Brute Force, New User, Privileged Logon, Unusual Time) are functional.
* 📊 Reports and visualization templates are under active development.

---

## 🌐 Project Structure

```text
SOC-Log-Analyzer/
├── data/                          ← Your `.evtx` logs go here (excluded from Git)
├── output/                        ← Parsed `.csv` and reports (excluded from Git)
├── src/
│   ├── main.py                    ← ✅ CLI entry point
│   ├── windows_parser.py          ← ✅ Parses `.evtx` → `.csv`
│   ├── analyzer.py                ← ✅ Analyzer logic
│   ├── detector_manager.py        ← ✅ Manages detection modules
│   ├── detectors/                 ← ✅ Brute Force, New User, Privileged Logon, Unusual Time detectors
│   └── report/                   ← ⚙️ In-progress (Text, PDF, HTML)
├── templates/                    ← ⚙️ In-progress Jinja2 templates for reports
├── config.yaml                   ← ✅ Centralized config for paths & settings
├── .gitignore                    ← ✅ Excludes sensitive data/output/env files
├── .pre-commit-config.yaml       ← ⚙️ (optional) REUSE/linting setup
├── CHANGELOG.md
├── LICENSE
├── README.md
└── requirements.txt              ← ⚙️ Add packages manually
````

---

## ✅ Completed So Far

* ✅ Clean, production-ready structure with config separation
* ✅ YAML-based global config
* ✅ CLI flags: `--parse`, `--analyze`, `--report`, `--all`
* ✅ Parser: `.evtx` to structured `.csv`
* ✅ Four core detection modules:

  * Brute Force Attack
  * New User Account Creation
  * Privileged Logon Detection
  * Unusual Logon Time
* ✅ Outputs clear alerts in console

---

## 🚀 How to Use (CLI)

### 1. Clone the Repository

```bash
git clone https://github.com/Muhammad-Abid99/SOC-Log-Analyzer.git
cd SOC-Log-Analyzer
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt  # Add required libraries manually
```

### 3. Add Your Logs

Place your `.evtx` file inside the `data/` folder, e.g., `data/security_recent.evtx`.

### 4. Run the CLI

```bash
python src/main.py --parse       # Only parse logs
python src/main.py --analyze     # Only run detection on parsed CSV
python src/main.py --all         # End-to-end: Parse → Analyze → Report (when ready)
```

---

## 📄 License

Licensed under the [Apache License 2.0](LICENSE).
All files follow [REUSE](https://reuse.software/) compliance.

---

## 🧑‍💻 Author

Developed with dedication by **G. Mohammad**
📫 Contact: [ghmuhammad324@gmail.com](mailto:ghmuhammad324@gmail.com)

---

## 🔮 Roadmap

* ✅ Core CLI + Threat detection logic
* ⚙️ HTML + PDF Reporting
* 📊 Data visualization & anomaly heatmaps
* 📧 Email alerting (SMTP)
* 🚀 Streamlit or FastAPI web dashboard
* 🚫 SIEM integration (e.g., Splunk, ELK)
* 🤖 ML-based anomaly detection (unsupervised)

---

> ⚠️ Not a portfolio — this is a real-world production-grade SOC project in progress. Built with ❤️, integrity, and purpose.
