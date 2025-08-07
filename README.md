<!--
SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# SOC Log Analyzer

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen)](https://pre-commit.com/)
[![REUSE Compliance](https://img.shields.io/badge/REUSE-Compliant-brightgreen)](https://reuse.software/)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![Status](https://img.shields.io/badge/Stage-MVP--Ready-yellow.svg)
![Made With Love](https://img.shields.io/badge/Made%20With-%E2%9D%A4-red)

> **SOC Log Analyzer** is a powerful real-world cybersecurity tool designed to help SOC teams parse, analyze, and detect threats from Windows Event Logs using Python and Data Science techniques.

---

## 🌐 Project Structure

```
SOC-Log-Analyzer/
├── data/                          ← Contains raw `.evtx` logs (ignored)
├── LICENSES
├── output/                        ← Contains reports & parsed CSVs (ignored)
├── src/
│   ├── main.py                    ← CLI entry point
│   ├── windows_parser.py          ← EVTX to CSV parser
│   ├── report/
│   │   ├── report_generator.py    ← HTML/PDF report using Jinja2
│   │   └── report_text.py         ← Text-only report
│   ├── analyzer.py                ← [Reserved for core logic integration]
│   ├── detector_manager.py        ← [Reserved for detector orchestration]
│   ├── detectors/                 ← Detection modules
│   │   ├── brute_force_detector.py
│   │   ├── new_user_creation_detector.py
│   │   ├── privileged_logon_detector.py
│   │   └── unusual_logon_time_detector.py
├── templates/                    ← (Empty) Jinja2 templates for HTML reports
├── .gitignore
├── .pre-commit-config.yaml       ← For code linting & REUSE compliance
├── CHANGELOG.md
├── config.yaml                   ← Global config for paths/settings
├── LICENSE
├── README.md
└── requirements.txt              ← Python dependencies
```

---

## 🚀 Features Implemented

* ✅ **EVTX Parsing** — Convert `.evtx` Windows logs into structured CSV using `windows_parser.py`
* ✅ **Threat Detection Modules**

  * Detect **Brute Force Attacks** from repeated failed logins (Event ID 4625)
  * Detect **New User Creation** (Event ID 4720)
  * Detect **Privileged Logons** (Event ID 4672)
  * Detect **Unusual Logon Times** (Event ID 4624 outside working hours)
* ✅ **Modular Detector System** — Easily extendable under `detectors/`
* ✅ **Multi-format Reports** — Generate detailed HTML, PDF, and Text reports with visualizations
* ✅ **Pre-commit + REUSE** — Enforced open-source licensing and clean code commits

---

## ⚙️ Getting Started

### 1. Clone the Repo

```bash
git clone https://github.com/Muhammad-Abid99/SOC-Log-Analyzer.git
cd SOC-Log-Analyzer
```

### 2. Install Requirements

```bash
pip install -r requirements.txt
```

### 3. Activate pre-commit Hooks (Optional but Recommended)

```bash
pre-commit install
pre-commit run --all-files
```

### 4. Run Analyzer

```bash
python src/main.py --all
```

---

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE).
All source files contain SPDX license and copyright headers.

---

## 🤝 Author

Developed with dedication and love by **G. Mohammad**.

Contact: [ghmuhammad324@gmail.com](mailto:ghmuhammad324@gmail.com)

---

## 📊 Future Enhancements

* ◻ Web dashboard using Flask / FastAPI
* ◻ Email alerting system
* ◻ Machine learning-based anomaly detection
* ◻ Real-time streaming log ingestion
* ◻ Integration with SIEM platforms (e.g., Splunk, ELK)

---

> This tool is not just a portfolio — it is a real-world, mission-critical SOC solution. Built with ❤️ and Python.

---
