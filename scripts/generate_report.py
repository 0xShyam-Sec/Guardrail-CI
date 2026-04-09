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


def _cwe_info(cwe_id):
    """Return explanation, risk, and example payload for a CWE."""
    cwe_db = {
        "89": {
            "name": "SQL Injection",
            "why_blocked": "User input is inserted directly into a SQL query without sanitization. An attacker can manipulate the query to read, modify, or delete any data in the database.",
            "risk": "An attacker can steal all customer data, modify account balances, or delete entire database tables.",
            "payload": "GET /accounts/1 OR 1=1--\nGET /accounts/0 UNION SELECT id,username,hashed_password FROM users--\nGET /accounts/1; DROP TABLE accounts;--",
            "fix": "Use parameterized queries (ORM) instead of string concatenation. Replace text(f\"SELECT ... {user_input}\") with db.query(Model).filter(Model.id == user_input).",
        },
        "259": {
            "name": "Hardcoded Password",
            "why_blocked": "A password or secret key is written directly in the source code. Anyone who can read the code (e.g., on a public GitHub repo) has access to the credential.",
            "risk": "Attacker reads the source code, finds the secret, and can forge authentication tokens or access protected resources.",
            "payload": "# Attacker reads config.py and finds:\nSECRET_KEY = \"skyline-super-secret-123\"\n# Then forges a JWT token:\nimport jwt\nfake = jwt.encode({\"sub\": \"1\"}, \"skyline-super-secret-123\")",
            "fix": "Store secrets in environment variables or a secrets manager. Use os.environ.get(\"SECRET_KEY\") instead of hardcoding.",
        },
        "200": {
            "name": "Information Disclosure",
            "why_blocked": "The application exposes internal details (environment variables, stack traces, system info) to external users.",
            "risk": "Attacker learns database URLs, API keys, internal IPs, and software versions — all useful for planning further attacks.",
            "payload": "GET /admin/debug\n# Response includes:\n# DATABASE_URL, AWS_SECRET_KEY, internal IPs, Python version",
            "fix": "Remove debug endpoints in production. Never expose os.environ or stack traces to end users.",
        },
    }
    return cwe_db.get(str(cwe_id), {
        "name": f"CWE-{cwe_id}",
        "why_blocked": "A security anti-pattern was detected in the source code by static analysis.",
        "risk": "This code pattern is known to introduce security vulnerabilities.",
        "payload": "N/A — see CWE database for details.",
        "fix": "Refer to https://cwe.mitre.org/data/definitions/" + str(cwe_id) + ".html",
    })


def _finding_card(severity, title, location, why_blocked, risk, payload, fix):
    """Return a detailed HTML finding card."""
    sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#2563eb"}
    border = sev_colors.get(severity, "#6b7280")

    payload_html = ""
    if payload and payload != "N/A":
        escaped = payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        payload_html = f"""
            <div style="margin-top:12px">
                <div style="color:#f87171;font-weight:600;font-size:13px;margin-bottom:6px">Example Attack Payload</div>
                <pre style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:12px;color:#fbbf24;font-size:13px;overflow-x:auto;white-space:pre-wrap">{escaped}</pre>
            </div>"""

    return f"""
    <div style="background:#1e293b;border-left:4px solid {border};border-radius:8px;padding:20px;margin-bottom:16px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
            <div style="display:flex;align-items:center;gap:10px">
                {_severity_badge(severity)}
                <span style="font-size:16px;font-weight:700;color:#f1f5f9">{title}</span>
            </div>
            <code style="font-size:12px;color:#94a3b8">{location}</code>
        </div>

        <div style="margin-bottom:12px">
            <div style="color:#f97316;font-weight:600;font-size:13px;margin-bottom:4px">Why was this blocked?</div>
            <div style="color:#cbd5e1;font-size:14px">{why_blocked}</div>
        </div>

        <div style="margin-bottom:12px">
            <div style="color:#ef4444;font-weight:600;font-size:13px;margin-bottom:4px">What could happen?</div>
            <div style="color:#cbd5e1;font-size:14px">{risk}</div>
        </div>

        {payload_html}

        <div style="margin-top:12px">
            <div style="color:#22c55e;font-weight:600;font-size:13px;margin-bottom:4px">How to fix</div>
            <div style="color:#cbd5e1;font-size:14px">{fix}</div>
        </div>
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
        cards = ""
        for d in bandit["details"]:
            info = _cwe_info(d["cwe"])
            cards += _finding_card(
                severity=d["severity"],
                title=info["name"],
                location=f"{d['file']}:{d['line']}",
                why_blocked=info["why_blocked"],
                risk=info["risk"],
                payload=info["payload"],
                fix=info["fix"],
            )
        detail_sections += f"""
        <div style="margin-bottom:40px">
            <h3 style="color:#e2e8f0;margin-bottom:4px">Bandit — SAST Findings</h3>
            <p style="color:#64748b;font-size:13px;margin-bottom:16px">Static analysis scanned source code without running it and found these security issues.</p>
            {cards}
        </div>"""

    # Trivy details
    if trivy.get("details"):
        cards = ""
        for d in trivy["details"]:
            cards += _finding_card(
                severity=d["severity"],
                title=f"{d['vuln_id']}",
                location=f"{d['package']}=={d['version']}",
                why_blocked=f"The library <strong>{d['package']}</strong> version <strong>{d['version']}</strong> has a publicly known vulnerability ({d['vuln_id']}). Attackers can look up exactly how to exploit it.",
                risk=d["title"] if d["title"] else "This version contains a security flaw that has been fixed in a newer release.",
                payload=f"# This CVE is public. Attackers can find exploit details at:\n# https://nvd.nist.gov/vuln/detail/{d['vuln_id']}\n# https://security.snyk.io/vuln/{d['vuln_id']}",
                fix=f"Update {d['package']} to the latest patched version. Run: pip install --upgrade {d['package']}",
            )
        detail_sections += f"""
        <div style="margin-bottom:40px">
            <h3 style="color:#e2e8f0;margin-bottom:4px">Trivy — Dependency Vulnerabilities</h3>
            <p style="color:#64748b;font-size:13px;margin-bottom:16px">Your project uses third-party libraries with known security flaws registered in the CVE database.</p>
            {cards}
        </div>"""

    # Gitleaks details
    if gitleaks.get("details"):
        # Deduplicate by file+rule
        seen = set()
        unique_details = []
        for d in gitleaks["details"]:
            key = f"{d['file']}:{d['rule']}"
            if key not in seen:
                seen.add(key)
                unique_details.append(d)

        cards = ""
        for d in unique_details:
            escaped_match = d["match"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            cards += _finding_card(
                severity="CRITICAL",
                title=f"Secret Detected — {d['rule']}",
                location=d["file"],
                why_blocked=f"A credential or secret was found committed in the source code. The pattern <code>{escaped_match}</code> matches a known secret format. Even if deleted later, it remains in git history forever.",
                risk="Anyone with repo access (or public access) can extract this secret and use it to: forge auth tokens, access databases, impersonate users, or escalate privileges.",
                payload=f"# Attacker runs:\ngit log -p -- {d['file']}\n# Finds the secret in commit history\n# Uses it to authenticate as any user",
                fix="1. Rotate the secret immediately (generate a new one).\n2. Store secrets in environment variables or GitHub Encrypted Secrets.\n3. Use git filter-branch or BFG Repo Cleaner to remove from history.",
            )

        total_secrets = len(gitleaks["details"])
        unique_count = len(unique_details)
        detail_sections += f"""
        <div style="margin-bottom:40px">
            <h3 style="color:#e2e8f0;margin-bottom:4px">Gitleaks — Exposed Secrets</h3>
            <p style="color:#64748b;font-size:13px;margin-bottom:16px">{total_secrets} secret(s) found across all commits ({unique_count} unique). Gitleaks scans the entire git history — secrets "deleted" in later commits are still visible.</p>
            {cards}
        </div>"""

    # ZAP details
    if zap.get("details"):
        cards = ""
        for d in zap["details"]:
            cards += _finding_card(
                severity=d["risk"],
                title=d["alert"],
                location=d["url"],
                why_blocked=f"OWASP ZAP attacked the live API and discovered: {d['description']}",
                risk="This vulnerability was found by actually exploiting the running application. A real attacker could reproduce this attack.",
                payload=f"# ZAP sent malicious payloads to:\n# {d['url']}\n# The application did not properly reject the attack.",
                fix="Validate and sanitize all user input. Use parameterized queries for databases. Set security headers. Follow OWASP Top 10 guidelines.",
            )
        detail_sections += f"""
        <div style="margin-bottom:40px">
            <h3 style="color:#e2e8f0;margin-bottom:4px">ZAP — Runtime Vulnerabilities</h3>
            <p style="color:#64748b;font-size:13px;margin-bottom:16px">OWASP ZAP attacked the running application with real exploit payloads and found these exploitable vulnerabilities.</p>
            {cards}
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
