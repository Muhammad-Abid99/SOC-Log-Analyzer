<!--
SPDX-FileCopyrightText: 2025 G. Mohammad <ghmuhammad324@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# 📜 Changelog - SOC-Log-Analyzer

All notable changes to this real-world cybersecurity tool are documented in this file.  
This changelog follows the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format and uses semantic versioning.

---

## [v0.5.0] - 2025-08-22
### Added
- 🛠 Fully upgraded `report_text.py` with **Contextualized v2**:
  - Dynamic **role/time/anomaly-aware severity** scoring (human off-hours + volume spikes escalate)
  - **Correlated Incidents** fusion: failed logons + privileged logons → High severity
  - **Context Notes & Account Glossary** (SYSTEM, DWM, UMFD) for analyst clarity
  - **ASCII severity bars** for quick-read in text-only outputs
  - Expanded **MITRE ATT&CK mapping**: 4624/4625/4672/4720 → T1078.004, T1136
- Technical Appendix for baseline & deviation analysis
- Actionable SOC **Next Steps** section for analysts and decision-makers

### Fixed
- Severity inconsistency between system/service accounts vs human activity
- Duplicated or redundant anomaly listings in grouped alerts
- Improved clarity: de-noised system/service account anomalies in executive summary while preserving full detail in appendix

### Changed
- Refactored **Grouped Alerts Summary** into compact SOC-friendly table format
- Executive Summary remains concise while maintaining decision-critical insights
- Ensured backward compatibility of function signatures and report paths for downstream tools

---

## [v0.4.0] - 2025-08-15
### Added
- 🕒 Accurate First Seen & Last Seen timestamps for every grouped alert in all report formats
- 📈 Timestamp improvements fully synced across CLI output, HTML, PDF, and Text reports
- 🖋 Updated README.md to include real-world problem statement, business value, and growth potential
- 📄 Short investor-facing README version for funding/partnership outreach

### Changed
- 🔄 Enhanced grouped alert display for clarity and professionalism
- 🔄 Improved report formatting consistency between text, HTML, and PDF outputs

### Fixed
- 🐛 Resolved `N/A` timestamp issue in PDF & HTML reports
- 🐛 Fixed mismatched data between text and PDF reports

---

## [v0.3.0] - 2025-08-11
### Added
- 📝 Complete report generation modules with support for:
  - Enhanced **text summary reports** including dynamic timestamps, alerts, and anomaly info (`report_text.py`)
  - HTML and PDF reports via `report_generator.py`
- ⚙️ CLI (`main.py`) updated with `--report` and `--all` flags
- 📄 README.md updated with usage instructions and privacy notes
- 🛠 Refined `config.yaml` for report paths and parameters
- 📦 requirements.txt updated with all dependencies
- 🔒 `.gitignore` strengthened to exclude sensitive raw data, parsed CSVs, and report outputs

### Changed
- ♻️ Modularized and improved codebase structure under `src/report/`
- 🧹 Cleaned deprecated `templates/` references and removed Jinja2 dependency
- 📝 Enhanced text report formatting for readability and professional style

### Fixed
- 🐛 Minor bugs and edge cases in report generation and CLI integration

---

## [v0.2.0] - 2025-08-09
### Added
- 🚀 MVP Threat Detection CLI with modules:
  - Brute Force Logon Detection (`4625`)
  - New User Account Creation (`4720`)
  - Privileged Logon Detection (`4672`)
  - Unusual Logon Time Detection (`4624`)
  - Account Lockout Detection (`4740`)
- ✅ `detector_manager.py` orchestrates detection modules
- ✅ Integrated detection output in CLI via `--analyze` and `--all`
- ✅ Passed REUSE lint compliance

### Changed
- 🔄 `analyzer.py` delegates detection to modular detectors
- 🔄 Refined `config.yaml` for centralized path/settings
- 🔄 Initial integration of report modules

---

## [v0.1.0] - 2025-08-07
### Added
- ✅ Initial project setup: folder structure, `.gitignore`, README.md, Apache 2.0 License
- ✅ `main.py` CLI entrypoint with `--parse`, `--analyze`, `--report`, `--all`
- ✅ `windows_parser.py` parses `.evtx` → `.csv`
- ✅ `config.yaml` for centralized paths/settings
- ✅ CHANGELOG.md created

---

## 💼 Project Stage

🔐 Real-World SOC Tool — **MVP Functional**  
📈 Goal: Investor-ready, sustainable cybersecurity solution
