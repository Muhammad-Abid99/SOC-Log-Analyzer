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

> **SOC Log Analyzer** is a real-world cybersecurity tool (MVP in progress) designed to help SOC teams parse and analyze Windows Event Logs using Python and Data Science foundations.

---

## 🧠 Important Note for Users

🚨 This tool is currently in **early development stage (MVP-in-progress)**.
If you're trying it out:

* 🔐 **Provide your own `.evtx` Windows Event Log** files inside the `data/` folder.
* 📦 The `requirements.txt` is created but not yet populated.
* ⚠️ Detection and reporting modules are planned but **not implemented yet**.

---

## 🌐 Project Structure

```text
SOC-Log-Analyzer/
├── data/                          ← Your `.evtx` logs go here (excluded from Git)
├── output/                        ← Parsed `.csv` and future reports (excluded from Git)
├── src/
│   ├── main.py                    ← CLI entry point (working ✅)
│   ├── windows_parser.py         ← Parses `.evtx` → `.csv` (working ✅)
│   ├── analyzer.py               ← [Reserved for future use]
│   ├── detector_manager.py       ← [Reserved for future use]
│   ├── detectors/                ← [Planned]
│   └── report/                   ← [Planned: text + PDF/HTML reports]
├── templates/                    ← [Planned: Jinja2 templates for reports]
├── config.yaml                   ← Global config file (working ✅)
├── .gitignore                    ← Excludes raw data and output
├── .pre-commit-config.yaml       ← [Planned for REUSE/linting]
├── CHANGELOG.md
├── LICENSE
├── README.md
└── requirements.txt              ← Created but currently empty
```

---

## ✅ Completed So Far

* ✅ Project initialized with clean, scalable folder structure
* ✅ `.gitignore` excludes sensitive raw logs and output
* ✅ `main.py` CLI interface added with flags (`--parse`, `--analyze`, `--report`, `--all`)
* ✅ `windows_parser.py` parses Windows `.evtx` to structured `.csv`
* ✅ `config.yaml` allows centralized path/settings config

---

## 🚀 How to Use (for current version)

### 1. Clone the Repository

```bash
git clone https://github.com/Muhammad-Abid99/SOC-Log-Analyzer.git
cd SOC-Log-Analyzer
```

### 2. Install Dependencies

> 📦 `requirements.txt` is currently **empty**. Add dependencies before running.

```bash
pip install -r requirements.txt
```

### 3. Add Your Logs

Place your `.evtx` file inside the `data/` folder. (e.g., `data/security_recent.evtx`)

### 4. Run the Parser

```bash
python src/main.py --parse
```

---

## 📄 License

Licensed under the [Apache License 2.0](LICENSE).
All future source files will follow [REUSE](https://reuse.software/) compliance.

---

## 🧑‍💻 Author

Developed with dedication by **G. Mohammad**
📫 Contact: [ghmuhammad324@gmail.com](mailto:ghmuhammad324@gmail.com)

---

## 🔮 Roadmap

* ⏳ Add detection modules (Brute Force, New User, etc.)
* ⏳ Add text, HTML, and PDF report generators
* ⏳ Add CLI integration for analysis and reporting
* ⏳ Add a Web Dashboard (Flask/FastAPI)
* ⏳ Add email alerting & ML anomaly detection
* ⏳ Integrate with SIEMs like Splunk / ELK

---

> ⚠️ This is not a showcase — it's a real-world, production-driven SOC project under active development. Built with ❤️, honesty, and vision.
