<div align="center">

# 📈 SRE & OSV Sentinel — Google SRE Burn-Rate Engine & Live OSV.dev Scanner

[![Live Web Console](https://img.shields.io/badge/🌐_Live_Web_Console-Run_OSV_&_SLO_Online-4285f4?style=for-the-badge)](https://wallisonws.github.io/sre-osv-sentinel/)
[![Powered by Google OSV](https://img.shields.io/badge/Supply--Chain-Google_OSV.dev_API-34a853?style=for-the-badge)](https://osv.dev)
[![Zero Dependencies](https://img.shields.io/badge/CLI-Zero_Dependencies_(Python_&_Pwsh)-38bdf8?style=for-the-badge)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge)](LICENSE)

**Zero-dependency Site Reliability Engineering (SRE) & Software Supply-Chain Security toolkit implementing Google SRE Workbook Multi-Burn-Rate SLO Alerting + real-time Google `OSV.dev` vulnerability auditing for `npm`, `PyPI`, `Go`, and `Flutter/Dart (Pub)`.**

[🌐 **Open Live Console**](https://wallisonws.github.io/sre-osv-sentinel/) • [🛡️ **Aegis LLM Guard**](https://github.com/WallisonWS/aegis-llm-guard) • [⚡ **DevSecOps Toolkit**](https://github.com/WallisonWS/devsecops-toolkit)

</div>

---

## ✨ Core Capabilities

1. **🔎 Live Google `OSV.dev` Supply-Chain Vulnerability Scanner (`scan-osv`)**
   * Parses `package.json` (**npm**), `requirements.txt` (**PyPI**), `go.mod` (**Go**), and `pubspec.yaml` (**Flutter/Dart Pub**) and queries Google's official Open Source Vulnerabilities batch API (`https://api.osv.dev/v1/querybatch`) with **zero external packages**.
2. **📈 Google SRE Multi-Window, Multi-Burn-Rate SLO Engine (`slo`)**
   * Implements **Chapter 5 of the Google SRE Workbook**: computes Error Budgets (`99.9%`, `99.95%`, `99.99%`), allowed downtime budgets, and exports production-ready **Prometheus (`PromQL`) / Google Cloud Monitoring** multi-burn-rate alerting rules (`14.4x`, `6x`, `1x`).

---

## 🚀 Quick Start

```bash
git clone https://github.com/WallisonWS/sre-osv-sentinel.git
cd sre-osv-sentinel

# 1) Audit dependencies against Google's OSV.dev API
python3 osv_sre.py scan-osv package.json
python3 osv_sre.py scan-osv pubspec.yaml
python3 osv_sre.py scan-osv go.mod

# 2) Generate Google SRE Multi-Burn-Rate SLO Alert Rules (99.95% target)
python3 osv_sre.py slo --target 99.95 --service checkout-api --days 30

# 3) Native Windows PowerShell query against Google OSV.dev
.\osv_sre.ps1 -Ecosystem npm -Package lodash -Version 4.17.19
```

---

<div align="center">
  Built by <b><a href="https://github.com/WallisonWS">Wallison Araujo (@WallisonWS)</a></b> • MIT License.
</div>
