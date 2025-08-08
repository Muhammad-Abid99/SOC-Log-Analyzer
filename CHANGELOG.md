<!--
SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# 📜 Changelog - SOC-Log-Analyzer

All notable changes to this real-world cybersecurity tool are documented in this file.  
This changelog follows the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format and is versioned using semantic versioning.

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

## [Upcoming - v0.2.0]
### Planned
- 🚧 Add `brute_force_detector.py` (Event ID 4625)
- 🚧 Add `detector_manager.py` to orchestrate detection modules
- 🚧 Begin integrating reporting (`report_text.py`, `report_generator.py`)
- 🚧 Add pre-commit hooks and REUSE linting
- 🚧 Begin implementing statistical and visual analysis

---

## 💼 Project Stage

🔐 Real-World SOC Tool — MVP In Progress  
📈 Goal: Investor-ready, sustainable security product
