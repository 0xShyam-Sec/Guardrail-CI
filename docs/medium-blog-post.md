# I Built a 4-Layer Automated Security Pipeline That Catches Vulnerabilities Before They Ship

## How I used GitHub Actions, CodeQL, OWASP ZAP, and 3 other scanners to build a DevSecOps pipeline that blocks insecure code automatically

---

Imagine a fintech startup deploying code 50 times a day. New features ship every hour. Developers are moving fast. The CEO is happy.

Then one night:

- A junior developer accidentally pushes a live AWS secret key to a public repository
- A week later, a critical SQL injection flaw is discovered in the production transfer API
- Customer data may have been exposed

The board issues an ultimatum: **automate the security, or shut down the deployment pipeline.**

This is the scenario I set out to solve. Not with manual code reviews. Not with a "we'll check it before release" promise. But with an automated security pipeline that scans every single commit across four layers of defense — and blocks anything that fails.

I called it **Guardrail CI**.

---

## The Problem: Speed vs Security

Modern software teams deploy fast. But every deployment is a risk:

- A hardcoded password in the source code
- A library with a known vulnerability
- An API endpoint vulnerable to injection attacks
- A secret accidentally committed to git history

Manual security reviews can't keep up with 50 deployments a day. By the time a human reviewer catches a flaw, it's already in production serving real users.

**The question I wanted to answer:** Can you build a system that automatically scans every code change for vulnerabilities — and blocks it if anything is wrong — without slowing down developers?

---

## The Solution: 4 Layers of Automated Defense

I designed the pipeline with four distinct security layers, each catching a different category of vulnerability:

### Layer 1: Static Analysis (SAST) — Reading the Code

**Tools: CodeQL + Bandit**

Static analysis reads your source code without running it — like a proofreader checking an essay for errors.

**CodeQL** (built by GitHub) performs taint analysis. It traces the flow of data through your code and asks: "Does user input from a URL parameter end up inside a SQL query without sanitization?" If yes — that's a SQL injection vulnerability.

**Bandit** is Python-specific. It catches patterns that CodeQL might miss: hardcoded passwords, use of unsafe functions like `os.system()`, and weak cryptographic practices.

In my test application, Bandit found **5 SQL injection vectors** in a single file — every place where I used raw f-string queries instead of parameterized ORM queries.

### Layer 2: Dependency Scanning (SCA) — Checking the Supply Chain

**Tools: Trivy + Dependabot**

Your application doesn't just contain your code. It contains hundreds of third-party libraries — and any of them could have known vulnerabilities.

**Trivy** scans `requirements.txt` against the National Vulnerability Database (NVD) and reports any library with a known CVE.

In my project, Trivy flagged **5 high/critical vulnerabilities**:
- `python-jose==3.3.0` had CVE-2024-33663 (algorithm confusion — CRITICAL)
- `urllib3==1.26.5` had 4 CVEs including cookie header leaks and decompression bombs

These aren't theoretical risks. These CVEs have public exploit details. Anyone can look them up and attack your application.

**Dependabot** runs natively on GitHub and automatically creates pull requests to update vulnerable dependencies. Within minutes of pushing my code, Dependabot had already opened a PR to upgrade `urllib3`.

### Layer 3: Dynamic Analysis (DAST) — Attacking the Live App

**Tool: OWASP ZAP**

Static analysis finds bugs in code. But some vulnerabilities only appear when the application is actually running. DAST takes a different approach: it **attacks your live application** with real exploit payloads.

Here's how it works in the pipeline:

1. Docker builds and starts the application inside a container
2. The pipeline waits for the health check to confirm the app is running
3. OWASP ZAP reads the FastAPI-generated OpenAPI specification (so it knows every endpoint and parameter)
4. ZAP sends hundreds of malicious payloads: SQL injection strings, XSS scripts, path traversal attempts
5. It analyzes the responses to determine which attacks succeeded
6. The container is torn down

This is the same approach professional penetration testers use — except it runs automatically on every commit.

### Layer 4: Secrets Scanning — Guarding the Keys

**Tool: Gitleaks**

The most dangerous vulnerability isn't a code bug — it's a leaked credential. A single exposed API key can give an attacker full access to your cloud infrastructure, database, and customer data.

Gitleaks scans the **entire git history**, not just the current code. This is critical because even if you delete a secret in a later commit, the old commit still has it. Anyone can run `git log` and find it. The current code looks clean, but the history tells the truth. Gitleaks catches this.

In my repository, Gitleaks found **21 secrets** across all commits — including hardcoded keys in configuration files and even passwords mentioned in documentation.

---

## The Architecture

The entire pipeline runs in a single GitHub Actions workflow file, organized into three stages:

**Stage 1 — Code Security (~60 seconds, all run in parallel)**

Four scanners launch simultaneously on four separate machines: CodeQL performs taint analysis for logic flaws, Bandit runs Python-specific security checks, Trivy scans dependencies for known CVEs, and Gitleaks searches the entire git history for leaked secrets. Running them in parallel keeps the total time under a minute.

**Stage 2 — Runtime Attack (~2 minutes, runs after Stage 1)**

OWASP ZAP spins up the application inside a Docker container and attacks it with real exploit payloads. This only starts after Stage 1 completes — there's no point attacking the app if leaked credentials have already been found.

**Stage 3 — Reporting (always runs, even if scanners fail)**

A Python script downloads all scan results, merges them into a single styled HTML dashboard, and uploads it as a downloadable artifact. An email notification is also sent. This stage runs even if previous stages fail — so developers always know what went wrong.

---

## The Test: Proving It Works

Building a security pipeline is meaningless if you can't prove it catches real vulnerabilities. So I built a deliberately vulnerable FastAPI banking API with these planted flaws:

- **SQL Injection** (transfer endpoint) — raw f-string queries let attackers manipulate database operations
- **IDOR** (account endpoint) — any logged-in user can view any other user's bank balance by changing the ID in the URL
- **Hardcoded Secrets** (config file) — JWT signing key and admin password written directly in source code
- **Information Disclosure** (debug endpoint) — returns all server environment variables to any visitor
- **Vulnerable Dependencies** (requirements.txt) — pinned old versions of urllib3 and python-jose with known CVEs
- **No Token Expiry** (login endpoint) — JWT tokens never expire, so a stolen token works forever

### The Result: Pipeline FAILS (as expected)

When pushed to GitHub, every scanner correctly identified the vulnerabilities:

- **Bandit**: 5 SQL injection findings in `accounts.py`
- **Trivy**: 5 HIGH/CRITICAL CVEs in dependencies
- **Gitleaks**: 21 secrets found across git history
- **ZAP**: Vulnerabilities detected in the running application

The build was **blocked**. The code cannot merge. This is exactly what should happen.

### The Fix: Pipeline PASSES

I then created a `fix/secure-skyline` branch that addresses every vulnerability:

- **SQL Injection** — replaced raw queries with ORM parameterized queries
- **IDOR** — added ownership checks (403 Access Denied if the account doesn't belong to you)
- **Hardcoded Secrets** — moved to environment variables via `os.environ.get()`
- **Info Disclosure** — removed the debug endpoint entirely
- **Vulnerable Dependencies** — updated urllib3 to 2.1.0, replaced python-jose with pyjwt
- **No Token Expiry** — added 1-hour JWT expiration

The pipeline runs again on the fix branch — and **passes green**. This before/after flow is the proof that the system works.

---

## The Reporting Layer

A security pipeline that blocks code but doesn't explain why is frustrating for developers. So I built a consolidated reporting system:

Every pipeline run generates a styled HTML dashboard that shows:

- **Overall status** (PASS/FAIL) with color-coded severity cards
- **Per-scanner breakdown** with finding counts
- **Detailed finding cards** for each vulnerability, including:
  - Why it was blocked (plain-language explanation)
  - What could happen (real-world risk)
  - Example attack payload (how an attacker would exploit it)
  - How to fix it (specific remediation steps)

The report is uploaded as a GitHub artifact — downloadable by anyone on the team. An email notification is also sent with a link to the results.

This matters because security scanning isn't just about catching bugs — it's about **teaching developers** why their code is insecure and how to fix it.

---

## Key Technical Decisions

**Why CodeQL AND Bandit?**

CodeQL excels at taint analysis — tracing data flow across functions. But it's a general-purpose tool. Bandit is Python-specific and catches patterns CodeQL misses, like hardcoded passwords assigned to variables. Using both gives layered SAST coverage.

**Why Docker for DAST?**

The DAST scanner needs a running application to attack. Docker ensures the app runs the same way in the CI environment as it does locally. The pipeline builds the container, starts it, waits for the health check, runs ZAP, then tears everything down — fully automated.

**Why Gitleaks scans full history?**

Most secret scanners only check the current commit. But secrets committed in the past and "deleted" in later commits still exist in git history. `fetch-depth: 0` in the checkout step ensures Gitleaks sees everything.

**Why `if: always()` on the report job?**

If a Stage 1 scanner fails, we still want the report generated. Without `if: always()`, GitHub Actions skips dependent jobs when a dependency fails. The report job needs to run regardless — so developers know what went wrong.

---

## What I Learned

**1. Security tools disagree with each other.** Bandit flagged hardcoded passwords as MEDIUM severity. Most security teams would call that HIGH or CRITICAL. Tuning thresholds is part of the job — there's no "plug and play."

**2. The CI environment is different from your machine.** GitHub Actions uses `docker compose` (v2, with a space), not `docker-compose` (v1, with a hyphen). Python 3.13+ broke SQLAlchemy 2.0.23. These are the kinds of issues that only surface in CI.

**3. False positives are a real problem.** Gitleaks flagged test passwords like `"password123"` in test files. These aren't real secrets, but the scanner can't tell the difference. Allowlists and tuning are essential.

**4. The report matters as much as the scan.** A wall of JSON output is useless to most developers. The HTML dashboard with "Why was this blocked?" and "How to fix it" sections turned the pipeline from a blocker into a teacher.

---

## Try It Yourself

The entire project is open source:

**GitHub**: https://github.com/0xShyam-Sec/Guardrail-CI

- `main` branch — vulnerable app + failing pipeline (proves scanners work)
- `fix/secure-skyline` branch — fixed code + passing pipeline
- Full pipeline configuration in `.github/workflows/aegis-pipeline.yml`
- Styled HTML report generator in `scripts/generate_report.py`

Fork it, push to your own repo, and watch the pipeline run. The tools are all free for public repositories.

---

## How This Compares to What Companies Actually Use

Everything I built here uses free, open-source tools. In production, companies invest in enterprise platforms that do the same thing at scale:

**For SAST** (I used CodeQL + Bandit) — enterprises use **Checkmarx**, **SonarQube**, or **Semgrep**. Samsung, Dropbox, Slack, and NASA run these on every commit.

**For SCA** (I used Trivy + Dependabot) — enterprises use **Snyk** or **WhiteSource**. Google, Salesforce, and Atlassian depend on these to catch vulnerable dependencies.

**For DAST** (I used OWASP ZAP) — enterprises use **StackHawk** or **Veracode**. Banks and Fortune 500 companies run these against their live APIs.

**For Secrets** (I used Gitleaks) — enterprises use **GitGuardian** or **GitHub Advanced Security**. IBM and Microsoft use these to prevent credential leaks across thousands of repositories.

**For Reporting** (I built a custom HTML dashboard) — enterprises use **SonarQube dashboards** or **Snyk Console**. Every security team needs a single pane of glass.

On top of all this, tools like **CodeRabbit** add AI-powered code review — automatically commenting on pull requests with security suggestions before a human reviewer even looks at the code.

The point isn't which specific tool you use. The point is the **pattern**: scan at every layer, block on failure, explain the findings, and make it automatic. Whether you build it with free tools on GitHub Actions or pay $100K/year for an enterprise platform — the architecture is the same.

What I built here for $0 covers the same four layers that companies pay six figures to automate. The enterprise tools add scale, compliance reporting, and support. But the security logic is identical.

---

## Final Thought

In a world where companies deploy code every hour, security cannot be a final checkbox. It has to be **automated, invisible, and non-negotiable**.

Guardrail CI isn't a product — it's a pattern. The specific tools can be swapped. CodeQL can be replaced with Semgrep. Trivy can be replaced with Snyk. OWASP ZAP can be replaced with StackHawk. The principle stays the same: **every commit gets scanned, every vulnerability gets explained, and nothing ships until it's clean.**

The pipeline doesn't make your code secure. It makes insecure code **impossible to deploy**.

---

*Built with Python, FastAPI, GitHub Actions, CodeQL, Bandit, Trivy, OWASP ZAP, and Gitleaks.*

*#DevSecOps #GitHubActions #CyberSecurity #DevSecBlueprint*
