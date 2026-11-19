#!/usr/bin/env python3
"""
SRE & OSV Sentinel (osv_sre.py)
1) Queries Google's official OSV.dev API (https://api.osv.dev/v1/querybatch) for
   real-time CVEs across package.json, requirements.txt, go.mod and pubspec.yaml.
2) Computes Google SRE Workbook Multi-Window Multi-Burn-Rate SLO Error Budgets
   and exports Prometheus / Google Cloud Monitoring alert rules.
Zero external dependencies (Python 3 stdlib only).
Author: Wallison Araujo (@WallisonWS) | License: MIT
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def parse_dependencies(file_path: Path) -> List[Dict[str, Any]]:
    name = file_path.name.lower()
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    queries: List[Dict[str, Any]] = []

    if name == "package.json":
        data = json.loads(text)
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for pkg, ver in deps.items():
            clean = re.sub(r"^[\^~>=<\s]+", "", str(ver))
            if re.match(r"^\d+\.\d+", clean):
                queries.append({"package": {"name": pkg, "ecosystem": "npm"}, "version": clean})
    elif name.endswith(".txt"):  # requirements.txt
        for line in text.splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
            if m:
                queries.append({"package": {"name": m.group(1), "ecosystem": "PyPI"}, "version": m.group(2)})
    elif name == "go.mod":
        for line in text.splitlines():
            m = re.match(r"^\s*([a-zA-Z0-9.\-_/]+)\s+v(\d+\.\d+\.\d+[^\s]*)", line)
            if m and not line.strip().startswith("//"):
                queries.append({"package": {"name": m.group(1), "ecosystem": "Go"}, "version": m.group(2)})
    elif name == "pubspec.yaml":
        in_deps = False
        for line in text.splitlines():
            if re.match(r"^(dependencies|dev_dependencies):", line):
                in_deps = True
                continue
            if re.match(r"^[a-zA-Z_]+:", line):
                in_deps = False
            if in_deps:
                m = re.match(r"^\s{2}([a-zA-Z0-9_]+):\s*[\^~]?(\d+\.\d+\.\d+)", line)
                if m:
                    queries.append({"package": {"name": m.group(1), "ecosystem": "Pub"}, "version": m.group(2)})
    return queries


def scan_osv(file_path: Path) -> Dict[str, Any]:
    queries = parse_dependencies(file_path)
    if not queries:
        return {"file": str(file_path), "scanned": 0, "vulnerable": []}

    payload = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "SRE-OSV-Sentinel/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    vulnerable: List[Dict[str, Any]] = []
    for query, res in zip(queries, data.get("results", [])):
        vulns = res.get("vulns", [])
        if vulns:
            vulnerable.append({
                "ecosystem": query["package"]["ecosystem"],
                "package": query["package"]["name"],
                "version": query["version"],
                "vuln_ids": [v.get("id") for v in vulns],
            })
    return {"file": str(file_path), "scanned": len(queries), "vulnerable_count": len(vulnerable), "vulnerable": vulnerable}


def compute_sre_slo(slo_percent: float, service: str = "payments-api", window_days: int = 30) -> Dict[str, Any]:
    error_budget_ratio = (100.0 - slo_percent) / 100.0
    total_minutes = window_days * 24 * 60
    allowed_downtime_min = round(total_minutes * error_budget_ratio, 2)
    burn_rates = [
        {"tier": "Page (Critical - 2% budget in 1h)", "burn_rate": 14.4, "long_window": "1h", "short_window": "5m", "error_threshold": round(error_budget_ratio * 14.4, 6)},
        {"tier": "Page (High - 5% budget in 6h)", "burn_rate": 6.0, "long_window": "6h", "short_window": "30m", "error_threshold": round(error_budget_ratio * 6.0, 6)},
        {"tier": "Ticket (Warning - 10% budget in 3d)", "burn_rate": 1.0, "long_window": "3d", "short_window": "6h", "error_threshold": round(error_budget_ratio * 1.0, 6)},
    ]
    prom_rule = (
        f"groups:\n  - name: {service}_slo_alerts\n    rules:\n"
        f"      - alert: {service}_HighErrorBudgetBurn\n"
        f"        expr: (\n"
        f'          job:slo_errors_per_request:ratio_rate1h{{service="{service}"}} > (14.4 * {error_budget_ratio:.6f})\n'
        f"          and\n"
        f'          job:slo_errors_per_request:ratio_rate5m{{service="{service}"}} > (14.4 * {error_budget_ratio:.6f})\n'
        f"        )\n        labels:\n          severity: page\n"
    )
    return {
        "service": service,
        "slo_target_percent": slo_percent,
        "window_days": window_days,
        "error_budget_ratio": round(error_budget_ratio, 6),
        "allowed_downtime_minutes": allowed_downtime_min,
        "multi_window_burn_rates": burn_rates,
        "prometheus_rule_yaml": prom_rule,
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="osv_sre", description="Google OSV.dev Supply-Chain Scanner & Google SRE Multi-Burn-Rate SLO Engine")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_osv = sub.add_parser("scan-osv", help="Query Google OSV.dev API for vulnerabilities in dependency manifests")
    p_osv.add_argument("manifest", help="Path to package.json, requirements.txt, go.mod or pubspec.yaml")

    p_slo = sub.add_parser("slo", help="Compute Google SRE Error Budget & Multi-Burn-Rate Prometheus rules")
    p_slo.add_argument("--target", type=float, default=99.9, help="SLO target percent (e.g. 99.9, 99.95, 99.99)")
    p_slo.add_argument("--service", default="checkout-api")
    p_slo.add_argument("--days", type=int, default=30)

    args = parser.parse_args(argv)
    if args.cmd == "scan-osv":
        print(json.dumps(scan_osv(Path(args.manifest)), indent=2))
    else:
        print(json.dumps(compute_sre_slo(args.target, args.service, args.days), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
