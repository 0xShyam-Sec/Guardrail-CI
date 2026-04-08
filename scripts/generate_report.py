#!/usr/bin/env python3
"""Merge security scan results into Markdown and HTML reports."""

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
        "critical": count,
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


def generate_markdown(bandit, trivy, gitleaks, zap, now, commit_sha):
    """Generate Markdown report."""
    report = f"""# Aegis Security Report — {now} [{commit_sha[:8]}]

## Summary

| Scanner  | Findings | Critical | High | Medium | Low | Status |
|----------|----------|----------|------|--------|-----|--------|
| Bandit   | {bandit['findings']}        | {bandit['critical']}        | {bandit['high']}    | {bandit['medium']}      | {bandit['low']}   | {status_label(bandit)}   |
| Trivy    | {trivy['findings']}        | {trivy['critical']}        | {trivy['high']}    | {trivy['medium']}      | {trivy['low']}   | {status_label(trivy)}   |
| Gitleaks | {gitleaks['findings']}        | {gitleaks['critical']}        | {gitleaks['high']}    | {gitleaks['medium']}      | {gitleaks['low']}   | {status_label(gitleaks)}   |
| ZAP      | {zap['findings']}        | {zap['critical']}        | {zap['high']}    | {zap['medium']}      | {zap['low']}   | {status_label(zap)}   |

"""

    if bandit.get("details"):
        report += "## Bandit (SAST) Details\n\n"
        for d in bandit["details"]:
            report += f"- **[{d['severity']}]** `{d['file']}:{d['line']}` — {d['issue']} (CWE-{d['cwe']})\n"
        report += "\n"

    if trivy.get("details"):
        report += "## Trivy (SCA) Details\n\n"
        for d in trivy["details"]:
            report += f"- **[{d['severity']}]** `{d['package']}=={d['version']}` — {d['vuln_id']}: {d['title']}\n"
        report += "\n"

    if gitleaks.get("details"):
        report += "## Gitleaks (Secrets) Details\n\n"
        for d in gitleaks["details"]:
            report += f"- **[CRITICAL]** `{d['file']}` — Rule: {d['rule']}, Match: `{d['match']}`\n"
        report += "\n"

    if zap.get("details"):
        report += "## ZAP (DAST) Details\n\n"
        for d in zap["details"]:
            report += f"- **[{d['risk']}]** {d['alert']} — {d['description']}\n"
        report += "\n"

    all_results = [bandit, trivy, gitleaks, zap]
    any_fail = any(status_label(r) == "FAIL" for r in all_results)
    report += f"## Overall Status: {'FAIL' if any_fail else 'PASS'}\n"

    return report


def _severity_badge(sev):
    """Return HTML badge for severity level."""
    colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#2563eb",
    }
    color = colors.get(sev, "#6b7280")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600">{sev}</span>'


def _status_badge(status):
    """Return HTML badge for pass/fail status."""
    if status == "FAIL":
        return '<span style="background:#dc2626;color:#fff;padding:4px 12px;border-radius:4px;font-weight:700;font-size:13px">FAIL</span>'
    return '<span style="background:#16a34a;color:#fff;padding:4px 12px;border-radius:4px;font-weight:700;font-size:13px">PASS</span>'


def _stat_card(label, value, color):
    """Return an HTML stat card."""
    return f"""<div style="background:{color};border-radius:12px;padding:20px 24px;min-width:120px;text-align:center">
        <div style="font-size:32px;font-weight:800;color:#fff">{value}</div>
        <div style="font-size:13px;color:rgba(255,255,255,0.85);margin-top:4px">{label}</div>
    </div>"""


def generate_html(bandit, trivy, gitleaks, zap, now, commit_sha):
    """Generate styled HTML report."""
    all_results = [bandit, trivy, gitleaks, zap]
    total_findings = sum(r["findings"] for r in all_results)
    total_critical = sum(r["critical"] for r in all_results)
    total_high = sum(r["high"] for r in all_results)
    total_medium = sum(r["medium"] for r in all_results)
    total_low = sum(r["low"] for r in all_results)
    any_fail = any(status_label(r) == "FAIL" for r in all_results)
    overall = "FAIL" if any_fail else "PASS"
    overall_color = "#dc2626" if any_fail else "#16a34a"

    scanners = [
        ("Bandit", "SAST — Static Analysis", "Scans source code for security anti-patterns", bandit),
        ("Trivy", "SCA — Dependency Scan", "Checks libraries for known CVEs", trivy),
        ("Gitleaks", "Secrets Scanner", "Detects leaked credentials in git history", gitleaks),
        ("ZAP", "DAST — Dynamic Analysis", "Attacks the running app to find exploits", zap),
    ]

    # Build scanner detail sections
    detail_sections = ""

    # Bandit details
    if bandit.get("details"):
        rows = ""
        for d in bandit["details"]:
            rows += f"""<tr>
                <td>{_severity_badge(d['severity'])}</td>
                <td><code>{d['file']}:{d['line']}</code></td>
                <td>{d['issue']}</td>
                <td>CWE-{d['cwe']}</td>
            </tr>"""
        detail_sections += f"""
        <div style="margin-bottom:32px">
            <h3 style="color:#e2e8f0;margin-bottom:12px">Bandit — SAST Findings</h3>
            <table style="width:100%;border-collapse:collapse">
                <thead><tr style="border-bottom:2px solid #334155">
                    <th style="text-align:left;padding:10px;color:#94a3b8">Severity</th>
                    <th style="text-align:left;padding:10px;color:#94a3b8">Location</th>
                    <th style="text-align:left;padding:10px;color:#94a3b8">Issue</th>
                    <th style="text-align:left;padding:10px;color:#94a3b8">CWE</th>
                </tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    # Trivy details
    if trivy.get("details"):
        rows = ""
        for d in trivy["details"]:
            rows += f"""<tr>
                <td>{_severity_badge(d['severity'])}</td>
                <td><code>{d['package']}=={d['version']}</code></td>
                <td>{d['vuln_id']}</td>
                <td>{d['title']}</td>
            </tr>"""
        detail_sections += f"""
        <div style="margin-bottom:32px">
            <h3 style="color:#e2e8f0;margin-bottom:12px">Trivy — Dependency Vulnerabilities</h3>
            <table style="width:100%;border-collapse:collapse">
                <thead><tr style="border-bottom:2px solid #334155">
                    <th style="text-align:left;padding:10px;color:#94a3b8">Severity</th>
                    <th style="text-align:left;padding:10px;color:#94a3b8">Package</th>
                    <th style="text-align:left;padding:10px;color:#94a3b8">CVE</th>
                    <th style="text-align:left;padding:10px;color:#94a3b8">Description</th>
                </tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    # Gitleaks details
    if gitleaks.get("details"):
        rows = ""
        for d in gitleaks["details"]:
            rows += f"""<tr>
                <td>{_severity_badge('CRITICAL')}</td>
                <td><code>{d['file']}</code></td>
                <td>{d['rule']}</td>
                <td><code>{d['match']}</code></td>
            </tr>"""
        detail_sections += f"""
        <div style="margin-bottom:32px">
            <h3 style="color:#e2e8f0;margin-bottom:12px">Gitleaks — Exposed Secrets</h3>
            <table style="width:100%;border-collapse:collapse">
                <thead><tr style="border-bottom:2px solid #334155">
                    <th style="text-align:left;padding:10px;color:#94a3b8">Severity</th>
                    <th style="text-align:left;padding:10px;color:#94a3b8">File</th>
                    <th style="text-align:left;padding:10px;color:#94a3b8">Rule</th>
                    <th style="text-align:left;padding:10px;color:#94a3b8">Match</th>
                </tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    # ZAP details
    if zap.get("details"):
        rows = ""
        for d in zap["details"]:
            rows += f"""<tr>
                <td>{_severity_badge(d['risk'])}</td>
                <td>{d['alert']}</td>
                <td>{d['description']}</td>
                <td><code>{d['url']}</code></td>
            </tr>"""
        detail_sections += f"""
        <div style="margin-bottom:32px">
            <h3 style="color:#e2e8f0;margin-bottom:12px">ZAP — Runtime Vulnerabilities</h3>
            <table style="width:100%;border-collapse:collapse">
                <thead><tr style="border-bottom:2px solid #334155">
                    <th style="text-align:left;padding:10px;color:#94a3b8">Risk</th>
                    <th style="text-align:left;padding:10px;color:#94a3b8">Alert</th>
                    <th style="text-align:left;padding:10px;color:#94a3b8">Description</th>
                    <th style="text-align:left;padding:10px;color:#94a3b8">URL</th>
                </tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    # Scanner summary cards
    scanner_cards = ""
    for name, subtitle, desc, result in scanners:
        s = status_label(result)
        icon = "&#10060;" if s == "FAIL" else "&#9989;"
        border_color = "#dc2626" if s == "FAIL" else "#16a34a"
        scanner_cards += f"""
        <div style="background:#1e293b;border-radius:12px;padding:20px;border-left:4px solid {border_color}">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                <div>
                    <span style="font-size:18px;font-weight:700;color:#f1f5f9">{icon} {name}</span>
                    <span style="color:#64748b;font-size:13px;margin-left:8px">{subtitle}</span>
                </div>
                {_status_badge(s)}
            </div>
            <div style="color:#94a3b8;font-size:13px;margin-bottom:12px">{desc}</div>
            <div style="display:flex;gap:16px;flex-wrap:wrap">
                <span style="color:#94a3b8">Findings: <strong style="color:#f1f5f9">{result['findings']}</strong></span>
                <span style="color:#dc2626">Critical: <strong>{result['critical']}</strong></span>
                <span style="color:#ea580c">High: <strong>{result['high']}</strong></span>
                <span style="color:#ca8a04">Medium: <strong>{result['medium']}</strong></span>
                <span style="color:#2563eb">Low: <strong>{result['low']}</strong></span>
            </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegis Security Report — {commit_sha[:8]}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ background: #0f172a; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; }}
        code {{ background: #334155; padding: 2px 6px; border-radius: 4px; font-size: 13px; color: #e2e8f0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        td, th {{ padding: 10px; text-align: left; }}
        tbody tr {{ border-bottom: 1px solid #1e293b; }}
        tbody tr:hover {{ background: #1e293b; }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 24px; }}
    </style>
</head>
<body>
    <div class="container">

        <!-- Header -->
        <div style="text-align:center;margin-bottom:48px">
            <div style="font-size:14px;color:#64748b;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">Guardrail CI</div>
            <h1 style="font-size:32px;font-weight:800;color:#f8fafc;margin-bottom:8px">Aegis Security Report</h1>
            <div style="color:#94a3b8;font-size:14px">
                {now} &nbsp;&bull;&nbsp; Commit <code>{commit_sha[:8]}</code>
            </div>
        </div>

        <!-- Overall Status -->
        <div style="text-align:center;margin-bottom:40px">
            <div style="display:inline-block;background:{overall_color};color:#fff;padding:12px 32px;border-radius:8px;font-size:20px;font-weight:800;letter-spacing:1px">
                PIPELINE {overall}
            </div>
        </div>

        <!-- Stat Cards -->
        <div style="display:flex;gap:16px;justify-content:center;flex-wrap:wrap;margin-bottom:48px">
            {_stat_card("Total Findings", total_findings, "#475569")}
            {_stat_card("Critical", total_critical, "#dc2626")}
            {_stat_card("High", total_high, "#ea580c")}
            {_stat_card("Medium", total_medium, "#ca8a04")}
            {_stat_card("Low", total_low, "#2563eb")}
        </div>

        <!-- Scanner Cards -->
        <h2 style="font-size:22px;font-weight:700;color:#f1f5f9;margin-bottom:20px">Scanner Results</h2>
        <div style="display:flex;flex-direction:column;gap:16px;margin-bottom:48px">
            {scanner_cards}
        </div>

        <!-- Detail Tables -->
        <h2 style="font-size:22px;font-weight:700;color:#f1f5f9;margin-bottom:20px">Detailed Findings</h2>
        {detail_sections if detail_sections else '<p style="color:#64748b">No detailed findings to display.</p>'}

        <!-- Footer -->
        <div style="text-align:center;margin-top:64px;padding-top:24px;border-top:1px solid #1e293b;color:#475569;font-size:13px">
            Generated by <strong style="color:#64748b">Guardrail CI — Aegis Security Pipeline</strong>
            &nbsp;&bull;&nbsp; {now}
        </div>

    </div>
</body>
</html>"""

    return html


def generate_reports(bandit_path, trivy_path, gitleaks_path, zap_path, commit_sha="unknown"):
    """Generate both Markdown and HTML reports."""
    bandit = parse_bandit(bandit_path)
    trivy = parse_trivy(trivy_path)
    gitleaks = parse_gitleaks(gitleaks_path)
    zap = parse_zap(zap_path)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    md = generate_markdown(bandit, trivy, gitleaks, zap, now, commit_sha)
    html = generate_html(bandit, trivy, gitleaks, zap, now, commit_sha)

    return md, html


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate Aegis security report")
    parser.add_argument("--bandit", default="bandit-report.json")
    parser.add_argument("--trivy", default="trivy-report.json")
    parser.add_argument("--gitleaks", default="gitleaks-report.json")
    parser.add_argument("--zap", default="zap-report.json")
    parser.add_argument("--commit", default="unknown")
    parser.add_argument("--output", default="aegis-report.md")
    parser.add_argument("--html-output", default="aegis-report.html")

    args = parser.parse_args()

    md, html = generate_reports(
        bandit_path=args.bandit,
        trivy_path=args.trivy,
        gitleaks_path=args.gitleaks,
        zap_path=args.zap,
        commit_sha=args.commit,
    )

    Path(args.output).write_text(md)
    Path(args.html_output).write_text(html)
    print(f"Markdown report written to {args.output}")
    print(f"HTML report written to {args.html_output}")
