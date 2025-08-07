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
- ✅ Project initialized with production-grade folder structure
- ✅ `README.md`, `.gitignore`, Apache License 2.0 added
- ✅ `requirements.txt` created (empty for now)

- ✅ `main.py` CLI entrypoint with flags:
  - `--parse`, `--analyze`, `--report`, `--all`

- ✅ `config.yaml` added for centralized config:
  - Input EVTX, output CSV/report paths, working hours

- ✅ `windows_parser.py` implemented to:
  - Parse `.evtx` logs using `Evtx`, `xml.etree`, and `pandas`
  - Extract system + event fields and save clean `.csv`

---

## [Upcoming - v0.2.0]
### Planned
- 🚧 Add `brute_force_detector.py` (detect Event ID 4625 failed logons)
- 🚧 Add `detector_manager.py` to aggregate all detection modules
- 🚧 Integrate reporting modules (`report_text.py`, `report_generator.py`)
- 🚧 Begin modular threat detection system

---

## 💼 Project Stage
🔐 Real-World SOC Tool in MVP Phase  
📈 Goal: Investor-ready, financially sustainable security product

---
