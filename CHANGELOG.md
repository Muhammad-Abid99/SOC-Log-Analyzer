<!--
SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# 📜 Changelog - SOC-Log-Analyzer

All notable changes to this real-world cybersecurity tool are documented in this file.  
This changelog follows the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format and is versioned using semantic versioning.

---

## [v0.3.0] - 2025-08-11
### Added
- 📝 Complete report generation modules with support for:
  - Enhanced **text summary reports** including dynamic timestamps, alerts, and anomaly info (`report_text.py`)
  - **HTML and PDF reports** generated via `report_generator.py` without separate templates folder
- ⚙️ Updated CLI (`main.py`) to support `--report` and `--all` flags for seamless report workflow
- 📄 Updated `README.md` with accurate usage instructions, project structure, and privacy notes
- 🛠️ Refined `config.yaml` for improved configuration of report paths and settings
- 📦 Updated `requirements.txt` with all necessary dependencies for current functionality
- 🔒 Strengthened `.gitignore` rules to exclude sensitive raw data, parsed CSVs, and report outputs

### Changed
- ♻️ Modularized and improved codebase structure under `src/report/` for maintainability and scalability
- 🧹 Cleaned up deprecated `templates/` folder references and removed Jinja2 dependency
- 📝 Enhanced text report formatting for better readability and professional output style

### Fixed
- 🐛 Resolved minor bugs and edge cases in report generation and CLI integration

---

## [v0.2.0] - 2025-08-09
### Added
- 🚀 **MVP Threat Detection CLI** now functional with following detection modules:
  - **Brute Force Logon Detection** (`brute_force_detector.py`, Event ID `4625`)
  - **New User Account Creation Detection** (`new_user_creation_detector.py`, Event ID `4720`)
  - **Privileged Logon Detection** (`privileged_logon_detector.py`, Event ID `4672`)
  - **Unusual Logon Time Detection** (`unusual_logon_time_detector.py`, Event ID `4624`)
- ✅ `detector_manager.py` to orchestrate multiple detection modules
- ✅ Integrated detection output into CLI via `--analyze` and `--all` flags
- ✅ Updated `.gitignore` to handle sensitive data and outputs
- ✅ Passed **REUSE lint** compliance for all source files
- 📂 Added `output/parsed_security_logs.csv` sample logs for testing

### Changed
- 🔄 Improved `analyzer.py` to delegate detection logic to modular detectors
- 🔄 Refined `config.yaml` for better path and settings management
- 🔄 Updated `report_text.py` and `report_generator.py` (initial integration phase)

---

## [v0.1.0] - 2025-08-07
### Added
- ✅ Initial project setup with professional folder structure
- ✅ `.gitignore` to protect sensitive logs and output
- ✅ `README.md` and Apache License 2.0 added
- ✅ `CHANGELOG.md` created
- ✅ `main.py` CLI entrypoint with flags:
  - `--parse`, `--analyze`, `--report`, `--all`
- ✅ `windows_parser.py` parses `.evtx` to `.csv`
- ✅ `config.yaml` with centralized paths/settings

---

## 💼 Project Stage

🔐 Real-World SOC Tool — **MVP Functional**  
📈 Goal: Investor-ready, sustainable cybersecurity solution
