---
title: "Operation Aegis — DevSecOps Pipeline Design Spec"
date: 2026-04-06
status: approved
---

# Operation Aegis: DevSecOps Pipeline for Skyline Financial Tech

## Overview

A fully automated, end-to-end security pipeline built on GitHub Actions that acts as an invisible shield around a mock banking application. This is a portfolio/capstone project demonstrating four layers of automated security defense.

**Stack:** Python 3.11 + FastAPI + SQLAlchemy + SQLite + Docker
**CI/CD:** GitHub Actions (public repo, free tier)
**Notifications:** Email (SMTP) + GitHub Artifacts
**Blog:** Medium

---

## 1. Sample Application — Skyline Banking API

### Endpoints

| Endpoint | Method | Purpose | Planted Vulnerability |
|---|---|---|---|
| `/auth/register` | POST | Create account | Weak password policy |
| `/auth/login` | POST | JWT login | Hardcoded JWT secret in code |
| `/accounts/{id}` | GET | View balance | IDOR (no ownership check) |
| `/accounts/{id}/transfer` | POST | Send money | SQL injection via raw query |
| `/admin/debug` | GET | Debug info | Exposes env vars / stack traces |

### Project Structure

```
skyline-banking-api/
├── app/
│   ├── main.py              # FastAPI app entry
│   ├── auth.py              # Register/login routes
│   ├── accounts.py          # Account/transfer routes
│   ├── admin.py             # Debug endpoint
│   ├── models.py            # SQLAlchemy models
│   ├── database.py          # DB connection
│   └── config.py            # Hardcoded secrets (intentional)
├── tests/
│   └── test_api.py          # Basic endpoint tests
├── scripts/
│   └── generate_report.py   # Merges scan results into Markdown report
├── .github/
│   ├── workflows/
│   │   └── aegis-pipeline.yml
│   └── dependabot.yml
├── .gitleaks.toml
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md                  ← created last
```

### Intentional Vulnerabilities

- Hardcoded `SECRET_KEY = "skyline-super-secret-123"` in `config.py`
- Raw SQL in transfer endpoint: `f"SELECT * FROM accounts WHERE id = {user_input}"`
- JWT with `HS256` and no expiry
- `/admin/debug` returns `os.environ` contents
- `requirements.txt` pins an older version of `urllib3` with known CVEs

---

## 2. GitHub Actions Pipeline — Four Layers of Defense

### Execution Flow

```
Push/PR to main
    │
    ├── Stage 1 (parallel jobs):
    │   ├── SAST: CodeQL
    │   ├── SAST: Bandit
    │   ├── SCA: Trivy
    │   └── Secrets: Gitleaks
    │
    ├── Stage 2 (needs Stage 1):
    │   └── DAST: OWASP ZAP (against Docker container)
    │
    └── Stage 3 (needs all above, runs always):
        └── Report generation + Email notification + Badge update
```

Dependabot runs separately via `.github/dependabot.yml` (native GitHub feature, not a workflow job).

### Layer 1: Code Security (SAST + SCA)

**Job: `sast-codeql`**
- Uses `github/codeql-action` (free for public repos)
- Language: Python
- Fails the build on high/critical severity findings

**Job: `sast-bandit`**
- Runs `bandit -r app/ -f json -o bandit-report.json`
- Python-specific security linter
- Catches things CodeQL misses (e.g., `os.system()`, hardcoded passwords)
- Fails on high-severity issues

**Job: `sca-trivy`**
- Uses `aquasecurity/trivy-action` against `requirements.txt` and the Docker image
- Reports known CVEs in dependencies
- Fails on HIGH/CRITICAL CVEs

**Dependabot:**
- Configured via `.github/dependabot.yml`
- Monitors pip dependencies
- Auto-creates PRs for vulnerable packages

### Layer 2: Runtime Security (DAST)

**Job: `dast-zap`**
- Depends on: Stage 1 passing
- Steps:
  1. Build and start the app via `docker-compose up -d`
  2. Wait for health check (`/docs` endpoint returns 200)
  3. Run OWASP ZAP API scan using `zaproxy/action-api-scan` with the FastAPI OpenAPI spec (`/openapi.json`)
  4. Tear down container
- Fails on HIGH alerts

### Layer 3: Secrets & Configuration

**Job: `secrets-gitleaks`**
- Runs `gitleaks/gitleaks-action` against the full commit history
- Fails if any secret pattern is detected
- Custom `.gitleaks.toml` to tune rules

**GitHub Encrypted Secrets:**
- Real credentials (e.g., SMTP password) stored in GitHub Settings > Secrets
- Injected via `${{ secrets.SMTP_PASSWORD }}`
- Never appear in plain text in logs

### Layer 4: Feedback & Reporting

**Job: `report-and-notify`**
- Depends on: all previous jobs (uses `if: always()`)
- Steps:
  1. Download all scan artifacts (Bandit JSON, Trivy JSON, ZAP HTML, Gitleaks JSON)
  2. Run `scripts/generate_report.py` to merge into a single Markdown summary
  3. Upload merged report as GitHub artifact
  4. Send email via `dawidd6/action-send-mail` with summary + artifact link
  5. Update shields.io badge based on workflow status

---

## 3. Report Format

```markdown
# Aegis Security Report — [date] [commit SHA]

## Summary
| Scanner | Findings | Critical | High | Medium | Low | Status |
|---------|----------|----------|------|--------|-----|--------|
| CodeQL  | 2        | 0        | 1    | 1      | 0   | FAIL   |
| Bandit  | 3        | 1        | 1    | 1      | 0   | FAIL   |
| Trivy   | 1        | 0        | 1    | 0      | 0   | FAIL   |
| ZAP     | 4        | 0        | 2    | 2      | 0   | FAIL   |
| Gitleaks| 1        | 1        | 0    | 0      | 0   | FAIL   |

## Details
[Per-scanner breakdown with finding descriptions and remediation hints]
```

---

## 4. Email Notification

- Action: `dawidd6/action-send-mail`
- Triggers on: every pipeline run (pass or fail)
- Content: summary table + link to full artifact
- SMTP credentials: stored in GitHub Encrypted Secrets

---

## 5. Security Badge

- shields.io workflow status badge in README
- Shows green "passing" or red "failing" based on `aegis-pipeline.yml` status

---

## 6. "Fix" Branch Strategy

After the `main` branch demonstrates a failing (but correctly catching) pipeline:
- Create a `fix/secure-skyline` branch
- Fix all planted vulnerabilities
- Push and show a green pipeline
- Provides a before/after narrative for the Medium blog post

---

## 7. Deliverables

| Deliverable | Description |
|---|---|
| `aegis-pipeline.yml` | Full GitHub Actions workflow with all four layers |
| `.github/dependabot.yml` | Automated dependency update config |
| `.gitleaks.toml` | Custom secret scanning rules |
| Scan artifacts | Bandit, Trivy, ZAP, Gitleaks reports as GitHub artifacts |
| `generate_report.py` | Script to merge scan results into summary report |
| Email notifications | Automated email on every pipeline run |
| Security badge | shields.io badge in README |
| README.md | Master documentation (created last) |
| Medium blog post | Technical walkthrough of Operation Aegis |
