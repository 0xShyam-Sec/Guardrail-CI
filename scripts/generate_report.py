#!/usr/bin/env python3
"""Merge security scan results into a single Markdown report."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def parse_bandit(path: str) -> dict:
    """Parse Bandit JSON output."""
    try:
        data = json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {"findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    details = []
    for result in data.get("results", []):
        sev = result.get("issue_severity", "LOW").lower()
        if sev == "undefined":
            sev = "low"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        details.append({
            "file": result.get("filename", "unknown"),
            "line": result.get("line_number", 0),
            "severity": sev.upper(),
            "issue": result.get("issue_text", ""),
            "cwe": result.get("issue_cwe", {}).get("id", "N/A"),
        })

    total = sum(severity_counts.values())
    return {**severity_counts, "findings": total, "details": details}


def parse_trivy(path: str) -> dict:
    """Parse Trivy JSON output."""
    try:
        data = json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {"findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    details = []

    results = data.get("Results", [])
    for result in results:
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "LOW").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            details.append({
                "package": vuln.get("PkgName", "unknown"),
                "version": vuln.get("InstalledVersion", "unknown"),
                "severity": sev.upper(),
                "vuln_id": vuln.get("VulnerabilityID", "N/A"),
                "title": vuln.get("Title", ""),
            })

    total = sum(severity_counts.values())
    return {**severity_counts, "findings": total, "details": details}


def parse_gitleaks(path: str) -> dict:
    """Parse Gitleaks JSON output."""
    try:
        data = json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {"findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    if not isinstance(data, list):
        data = []

    details = []
    for finding in data:
        details.append({
            "file": finding.get("File", "unknown"),
            "rule": finding.get("RuleID", "unknown"),
            "match": finding.get("Match", "")[:50] + "...",
        })

    count = len(data)
    return {
        "findings": count,
        "critical": count,  # All secret leaks are critical
        "high": 0,
        "medium": 0,
        "low": 0,
        "details": details,
    }


def parse_zap(path: str) -> dict:
    """Parse ZAP JSON report."""
    try:
        data = json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {"findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    risk_map = {"3": "high", "2": "medium", "1": "low", "0": "low"}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    details = []

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = risk_map.get(str(alert.get("riskcode", "0")), "low")
            severity_counts[risk] = severity_counts.get(risk, 0) + 1
            details.append({
                "alert": alert.get("alert", "unknown"),
                "risk": risk.upper(),
                "description": alert.get("desc", "")[:100],
                "url": alert.get("url", "N/A"),
            })

    total = sum(severity_counts.values())
    return {**severity_counts, "findings": total, "details": details}


def status_label(result: dict) -> str:
    if result["critical"] > 0 or result["high"] > 0:
        return "FAIL"
    return "PASS"


def generate_report(
    bandit_path: str,
    trivy_path: str,
    gitleaks_path: str,
    zap_path: str,
    commit_sha: str = "unknown",
) -> str:
    """Generate the full Markdown report."""
    bandit = parse_bandit(bandit_path)
    trivy = parse_trivy(trivy_path)
    gitleaks = parse_gitleaks(gitleaks_path)
    zap = parse_zap(zap_path)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    report = f"""# Aegis Security Report — {now} [{commit_sha[:8]}]

## Summary

| Scanner  | Findings | Critical | High | Medium | Low | Status |
|----------|----------|----------|------|--------|-----|--------|
| Bandit   | {bandit['findings']}        | {bandit['critical']}        | {bandit['high']}    | {bandit['medium']}      | {bandit['low']}   | {status_label(bandit)}   |
| Trivy    | {trivy['findings']}        | {trivy['critical']}        | {trivy['high']}    | {trivy['medium']}      | {trivy['low']}   | {status_label(trivy)}   |
| Gitleaks | {gitleaks['findings']}        | {gitleaks['critical']}        | {gitleaks['high']}    | {gitleaks['medium']}      | {gitleaks['low']}   | {status_label(gitleaks)}   |
| ZAP      | {zap['findings']}        | {zap['critical']}        | {zap['high']}    | {zap['medium']}      | {zap['low']}   | {status_label(zap)}   |

"""

    # Bandit details
    if bandit.get("details"):
        report += "## Bandit (SAST) Details\n\n"
        for d in bandit["details"]:
            report += f"- **[{d['severity']}]** `{d['file']}:{d['line']}` — {d['issue']} (CWE-{d['cwe']})\n"
        report += "\n"

    # Trivy details
    if trivy.get("details"):
        report += "## Trivy (SCA) Details\n\n"
        for d in trivy["details"]:
            report += f"- **[{d['severity']}]** `{d['package']}=={d['version']}` — {d['vuln_id']}: {d['title']}\n"
        report += "\n"

    # Gitleaks details
    if gitleaks.get("details"):
        report += "## Gitleaks (Secrets) Details\n\n"
        for d in gitleaks["details"]:
            report += f"- **[CRITICAL]** `{d['file']}` — Rule: {d['rule']}, Match: `{d['match']}`\n"
        report += "\n"

    # ZAP details
    if zap.get("details"):
        report += "## ZAP (DAST) Details\n\n"
        for d in zap["details"]:
            report += f"- **[{d['risk']}]** {d['alert']} — {d['description']}\n"
        report += "\n"

    # Overall status
    all_results = [bandit, trivy, gitleaks, zap]
    any_fail = any(status_label(r) == "FAIL" for r in all_results)
    report += f"## Overall Status: {'FAIL' if any_fail else 'PASS'}\n"

    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate Aegis security report")
    parser.add_argument("--bandit", default="bandit-report.json")
    parser.add_argument("--trivy", default="trivy-report.json")
    parser.add_argument("--gitleaks", default="gitleaks-report.json")
    parser.add_argument("--zap", default="zap-report.json")
    parser.add_argument("--commit", default="unknown")
    parser.add_argument("--output", default="aegis-report.md")

    args = parser.parse_args()

    report = generate_report(
        bandit_path=args.bandit,
        trivy_path=args.trivy,
        gitleaks_path=args.gitleaks,
        zap_path=args.zap,
        commit_sha=args.commit,
    )

    Path(args.output).write_text(report)
    print(f"Report written to {args.output}")
