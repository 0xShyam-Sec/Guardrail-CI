================================
MEDIUM BLOG POST — READY TO PASTE
================================

How to use this file:
- Copy section by section into Medium
- Follow the [FORMAT] instructions for each line
- Replace [SCREENSHOT] lines with actual images
- Delete all lines starting with [FORMAT] or [SCREENSHOT] — they are instructions only

================================


[FORMAT: Title — click the large "T" in Medium toolbar]
I Planted 6 Vulnerabilities in a Banking API — Then Built a Pipeline That Caught All of Them

[FORMAT: Subtitle — click the small "T" in Medium toolbar]
How I used GitHub Actions, CodeQL, OWASP ZAP, and 3 other scanners to build a DevSecOps pipeline that blocks insecure code automatically

[FORMAT: Type --- and press Enter to create a horizontal line]

Imagine a fintech startup deploying code 50 times a day. New features ship every hour. Developers are moving fast. The CEO is happy.

Then one night:

[FORMAT: Bullet list — type each line starting with a dash]
- A junior developer accidentally pushes a live AWS secret key to a public repository
- A week later, a critical SQL injection flaw is discovered in the production transfer API
- Customer data may have been exposed

The board issues an ultimatum: [FORMAT: Bold this →] automate the security, or shut down the deployment pipeline.

This is the scenario I set out to solve. Not with manual code reviews. Not with a "we'll check it before release" promise. But with an automated security pipeline that scans every single commit across four layers of defense — and blocks anything that fails.

I called it [FORMAT: Bold this →] Guardrail CI.

[FORMAT: Type --- and press Enter to create a horizontal line]


[FORMAT: Small heading — click small "T"]
The Problem: Speed vs Security

Modern software teams deploy fast. But every deployment is a risk:

- A hardcoded password in the source code
- A library with a known vulnerability
- An API endpoint vulnerable to injection attacks
- A secret accidentally committed to git history

Manual security reviews can't keep up with 50 deployments a day. By the time a human reviewer catches a flaw, it's already in production serving real users.

[FORMAT: Bold this entire line →] The question I wanted to answer: Can you build a system that automatically scans every code change for vulnerabilities — and blocks it if anything is wrong — without slowing down developers?

[FORMAT: Type --- and press Enter to create a horizontal line]


[FORMAT: Small heading — click small "T"]
The Solution: 4 Layers of Automated Defense

I designed the pipeline with four distinct security layers, each catching a different category of vulnerability:

[SCREENSHOT: Insert the Mermaid flowchart diagram image here. Create it at mermaid.live using the code from the instructions I gave you earlier. Download as PNG and drag it into Medium.]


[FORMAT: Small heading — click small "T"]
Layer 1: Static Analysis (SAST) — Reading the Code

[FORMAT: Bold this →] Tools: CodeQL + Bandit

Static analysis reads your source code without running it — like a proofreader checking an essay for errors.

[FORMAT: Bold this →] CodeQL (built by GitHub) performs taint analysis. It traces the flow of data through your code and asks: "Does user input from a URL parameter end up inside a SQL query without sanitization?" If yes — that's a SQL injection vulnerability.

[FORMAT: Bold this →] Bandit is Python-specific. It catches patterns that CodeQL might miss: hardcoded passwords, use of unsafe functions like os.system(), and weak cryptographic practices.

In my test application, Bandit found [FORMAT: Bold this →] 5 SQL injection vectors in a single file — every place where I used raw f-string queries instead of parameterized ORM queries.

[SCREENSHOT: Go to GitHub Actions → click latest run on main → click "SAST — Bandit" → expand "Fail on medium severity or above" → screenshot the log showing "Medium/High/Critical findings: 5"]


[FORMAT: Small heading — click small "T"]
Layer 2: Dependency Scanning (SCA) — Checking the Supply Chain

[FORMAT: Bold this →] Tools: Trivy + Dependabot

Your application doesn't just contain your code. It contains hundreds of third-party libraries — and any of them could have known vulnerabilities.

[FORMAT: Bold this →] Trivy scans requirements.txt against the National Vulnerability Database (NVD) and reports any library with a known CVE.

In my project, Trivy flagged [FORMAT: Bold this →] 5 high/critical vulnerabilities:
- python-jose==3.3.0 had CVE-2024-33663 (algorithm confusion — CRITICAL)
- urllib3==1.26.5 had 4 CVEs including cookie header leaks and decompression bombs

These aren't theoretical risks. These CVEs have public exploit details. Anyone can look them up and attack your application.

[SCREENSHOT: Go to GitHub Actions → click latest run → click "SCA — Trivy" → expand "Fail on high/critical CVEs" → screenshot showing "High/Critical vulnerabilities: 5"]

[FORMAT: Bold this →] Dependabot runs natively on GitHub and automatically creates pull requests to update vulnerable dependencies. Within minutes of pushing my code, Dependabot had already opened a PR to upgrade urllib3.

[SCREENSHOT: Go to your repo → Pull requests tab → find the Dependabot PR "Bump urllib3 from 1.26.5 to 2.6.3" → screenshot the PR title and CVE details in the description]


[FORMAT: Small heading — click small "T"]
Layer 3: Dynamic Analysis (DAST) — Attacking the Live App

[FORMAT: Bold this →] Tool: OWASP ZAP

Static analysis finds bugs in code. But some vulnerabilities only appear when the application is actually running. DAST takes a different approach: it [FORMAT: Bold this →] attacks your live application with real exploit payloads.

Here's how it works in the pipeline:

[FORMAT: Numbered list]
1. Docker builds and starts the application inside a container
2. The pipeline waits for the health check to confirm the app is running
3. OWASP ZAP reads the FastAPI-generated OpenAPI specification (so it knows every endpoint and parameter)
4. ZAP sends hundreds of malicious payloads: SQL injection strings, XSS scripts, path traversal attempts
5. It analyzes the responses to determine which attacks succeeded
6. The container is torn down

This is the same approach professional penetration testers use — except it runs automatically on every commit.

[SCREENSHOT: Go to GitHub Actions → click latest run → click "DAST — OWASP ZAP" → expand "Build and start application" → screenshot showing "Application is ready!"]


[FORMAT: Small heading — click small "T"]
Layer 4: Secrets Scanning — Guarding the Keys

[FORMAT: Bold this →] Tool: Gitleaks

The most dangerous vulnerability isn't a code bug — it's a leaked credential. A single exposed API key can give an attacker full access to your cloud infrastructure, database, and customer data.

Gitleaks scans the [FORMAT: Bold this →] entire git history, not just the current code. This is critical because even if you delete a secret in a later commit, the old commit still has it. Anyone can run git log and find it. The current code looks clean, but the history tells the truth. Gitleaks catches this.

In my repository, Gitleaks found [FORMAT: Bold this →] 21 secrets across all commits — including hardcoded keys in configuration files and even passwords mentioned in documentation.

[SCREENSHOT: Go to GitHub Actions → click latest run → click "Secrets — Gitleaks" → expand "Fail if secrets found" → screenshot showing "Secrets found: 21"]

[FORMAT: Type --- and press Enter to create a horizontal line]


[FORMAT: Small heading — click small "T"]
The Architecture

The entire pipeline runs in a single GitHub Actions workflow file, organized into three stages:

[FORMAT: Bold this →] Stage 1 — Code Security (~60 seconds, all run in parallel)

Four scanners launch simultaneously on four separate machines: CodeQL performs taint analysis for logic flaws, Bandit runs Python-specific security checks, Trivy scans dependencies for known CVEs, and Gitleaks searches the entire git history for leaked secrets. Running them in parallel keeps the total time under a minute.

[FORMAT: Bold this →] Stage 2 — Runtime Attack (~2 minutes, runs after Stage 1)

OWASP ZAP spins up the application inside a Docker container and attacks it with real exploit payloads. This only starts after Stage 1 completes — there's no point attacking the app if leaked credentials have already been found.

[FORMAT: Bold this →] Stage 3 — Reporting (always runs, even if scanners fail)

A Python script downloads all scan results, merges them into a single styled HTML dashboard, and uploads it as a downloadable artifact. An email notification is also sent. This stage runs even if previous stages fail — so developers always know what went wrong.

[FORMAT: Type --- and press Enter to create a horizontal line]


[FORMAT: Small heading — click small "T"]
The Test: Proving It Works

Building a security pipeline is meaningless if you can't prove it catches real vulnerabilities. So I built a deliberately vulnerable FastAPI banking API with these planted flaws:

- [FORMAT: Bold this →] SQL Injection (transfer endpoint) — raw f-string queries let attackers manipulate database operations
- [FORMAT: Bold this →] IDOR (account endpoint) — any logged-in user can view any other user's bank balance by changing the ID in the URL
- [FORMAT: Bold this →] Hardcoded Secrets (config file) — JWT signing key and admin password written directly in source code
- [FORMAT: Bold this →] Information Disclosure (debug endpoint) — returns all server environment variables to any visitor
- [FORMAT: Bold this →] Vulnerable Dependencies (requirements.txt) — pinned old versions of urllib3 and python-jose with known CVEs
- [FORMAT: Bold this →] No Token Expiry (login endpoint) — JWT tokens never expire, so a stolen token works forever


[FORMAT: Small heading — click small "T"]
The Result: Pipeline FAILS (as expected)

When pushed to GitHub, every scanner correctly identified the vulnerabilities:

- [FORMAT: Bold this →] Bandit: 5 SQL injection findings in accounts.py
- [FORMAT: Bold this →] Trivy: 5 HIGH/CRITICAL CVEs in dependencies
- [FORMAT: Bold this →] Gitleaks: 21 secrets found across git history
- [FORMAT: Bold this →] ZAP: Vulnerabilities detected in the running application

The build was [FORMAT: Bold this →] blocked. The code cannot merge. This is exactly what should happen.

[SCREENSHOT: Go to GitHub Actions → click latest run on main → this is the Summary page showing all jobs in the left sidebar with red X and green checkmarks. Screenshot the full sidebar.]


[FORMAT: Small heading — click small "T"]
The Fix: Pipeline PASSES

I then created a fix/secure-skyline branch that addresses every vulnerability:

- [FORMAT: Bold this →] SQL Injection — replaced raw queries with ORM parameterized queries
- [FORMAT: Bold this →] IDOR — added ownership checks (403 Access Denied if the account doesn't belong to you)
- [FORMAT: Bold this →] Hardcoded Secrets — moved to environment variables via os.environ.get()
- [FORMAT: Bold this →] Info Disclosure — removed the debug endpoint entirely
- [FORMAT: Bold this →] Vulnerable Dependencies — updated urllib3 to 2.1.0, replaced python-jose with pyjwt
- [FORMAT: Bold this →] No Token Expiry — added 1-hour JWT expiration

The pipeline runs again on the fix branch — and [FORMAT: Bold this →] passes green. This before/after flow is the proof that the system works.

[SCREENSHOT: Go to PR #14 → "Files changed" tab → screenshot the diff of accounts.py showing red lines (raw SQL) replaced by green lines (ORM query)]

[FORMAT: Type --- and press Enter to create a horizontal line]


[FORMAT: Small heading — click small "T"]
The Reporting Layer

A security pipeline that blocks code but doesn't explain why is frustrating for developers. So I built a consolidated reporting system:

Every pipeline run generates a styled HTML dashboard that shows:

- [FORMAT: Bold this →] Overall status (PASS/FAIL) with color-coded severity cards
- [FORMAT: Bold this →] Per-scanner breakdown with finding counts
- [FORMAT: Bold this →] Detailed finding cards for each vulnerability, including:

Why it was blocked (plain-language explanation), what could happen (real-world risk), example attack payload (how an attacker would exploit it), and how to fix it (specific remediation steps).

[SCREENSHOT: Open the HTML report (aegis-report.html) in your browser. Take a full-page screenshot showing the GUARDRAIL CI header, PIPELINE FAIL banner, and stat cards.]

[SCREENSHOT: Scroll down in the same HTML report. Screenshot one detailed finding card that shows all 4 sections — "Why was this blocked?", "What could happen?", "Example Attack Payload", "How to fix".]

The report is uploaded as a GitHub artifact — downloadable by anyone on the team. An email notification is also sent with a link to the results.

This matters because security scanning isn't just about catching bugs — it's about [FORMAT: Bold this →] teaching developers why their code is insecure and how to fix it.

[FORMAT: Type --- and press Enter to create a horizontal line]


[FORMAT: Small heading — click small "T"]
Key Technical Decisions

[FORMAT: Bold this →] Why CodeQL AND Bandit?

CodeQL excels at taint analysis — tracing data flow across functions. But it's a general-purpose tool. Bandit is Python-specific and catches patterns CodeQL misses, like hardcoded passwords assigned to variables. Using both gives layered SAST coverage.

[FORMAT: Bold this →] Why Docker for DAST?

The DAST scanner needs a running application to attack. Docker ensures the app runs the same way in the CI environment as it does locally. The pipeline builds the container, starts it, waits for the health check, runs ZAP, then tears everything down — fully automated.

[FORMAT: Bold this →] Why Gitleaks scans full history?

Most secret scanners only check the current commit. But secrets committed in the past and "deleted" in later commits still exist in git history. Setting fetch-depth to 0 in the checkout step ensures Gitleaks sees everything.

[FORMAT: Bold this →] Why "if: always()" on the report job?

If a Stage 1 scanner fails, we still want the report generated. Without this setting, GitHub Actions skips dependent jobs when a dependency fails. The report job needs to run regardless — so developers know what went wrong.

[FORMAT: Type --- and press Enter to create a horizontal line]


[FORMAT: Small heading — click small "T"]
What I Learned

[FORMAT: Bold this →] 1. Security tools disagree with each other. Bandit flagged hardcoded passwords as MEDIUM severity. Most security teams would call that HIGH or CRITICAL. Tuning thresholds is part of the job — there's no "plug and play."

[FORMAT: Bold this →] 2. The CI environment is different from your machine. GitHub Actions uses "docker compose" (v2, with a space), not "docker-compose" (v1, with a hyphen). Python 3.13+ broke SQLAlchemy 2.0.23. These are the kinds of issues that only surface in CI.

[FORMAT: Bold this →] 3. False positives are a real problem. Gitleaks flagged test passwords like "password123" in test files. These aren't real secrets, but the scanner can't tell the difference. Allowlists and tuning are essential.

[FORMAT: Bold this →] 4. The report matters as much as the scan. A wall of JSON output is useless to most developers. The HTML dashboard with "Why was this blocked?" and "How to fix it" sections turned the pipeline from a blocker into a teacher.

[FORMAT: Type --- and press Enter to create a horizontal line]


[FORMAT: Small heading — click small "T"]
Try It Yourself

The entire project is open source:

[FORMAT: Bold this →] GitHub: https://github.com/0xShyam-Sec/Guardrail-CI

- main branch — vulnerable app + failing pipeline (proves scanners work)
- fix/secure-skyline branch — fixed code + passing pipeline
- Full pipeline configuration in .github/workflows/aegis-pipeline.yml
- Styled HTML report generator in scripts/generate_report.py

Fork it, push to your own repo, and watch the pipeline run. The tools are all free for public repositories.

[SCREENSHOT: Go to your repo main page (github.com/0xShyam-Sec/Guardrail-CI) → screenshot the top of the README showing project name, badges, and the Mermaid architecture diagram]

[FORMAT: Type --- and press Enter to create a horizontal line]


[FORMAT: Small heading — click small "T"]
How This Compares to What Companies Actually Use

Everything I built here uses free, open-source tools. In production, companies invest in enterprise platforms that do the same thing at scale:

[FORMAT: Bold this →] For SAST (I used CodeQL + Bandit) — enterprises use Checkmarx, SonarQube, or Semgrep. Samsung, Dropbox, Slack, and NASA run these on every commit.

[FORMAT: Bold this →] For SCA (I used Trivy + Dependabot) — enterprises use Snyk or WhiteSource. Google, Salesforce, and Atlassian depend on these to catch vulnerable dependencies.

[FORMAT: Bold this →] For DAST (I used OWASP ZAP) — enterprises use StackHawk or Veracode. Banks and Fortune 500 companies run these against their live APIs.

[FORMAT: Bold this →] For Secrets (I used Gitleaks) — enterprises use GitGuardian or GitHub Advanced Security. IBM and Microsoft use these to prevent credential leaks across thousands of repositories.

[FORMAT: Bold this →] For Reporting (I built a custom HTML dashboard) — enterprises use SonarQube dashboards or Snyk Console. Every security team needs a single pane of glass.

On top of all this, tools like [FORMAT: Bold this →] CodeRabbit add AI-powered code review — automatically commenting on pull requests with security suggestions before a human reviewer even looks at the code.

The point isn't which specific tool you use. The point is the [FORMAT: Bold this →] pattern: scan at every layer, block on failure, explain the findings, and make it automatic. Whether you build it with free tools on GitHub Actions or pay $100K/year for an enterprise platform — the architecture is the same.

What I built here for $0 covers the same four layers that companies pay six figures to automate. The enterprise tools add scale, compliance reporting, and support. But the security logic is identical.

[FORMAT: Type --- and press Enter to create a horizontal line]


[FORMAT: Small heading — click small "T"]
Final Thought

In a world where companies deploy code every hour, security cannot be a final checkbox. It has to be [FORMAT: Bold this →] automated, invisible, and non-negotiable.

Guardrail CI isn't a product — it's a pattern. The specific tools can be swapped. CodeQL can be replaced with Semgrep. Trivy can be replaced with Snyk. OWASP ZAP can be replaced with StackHawk. The principle stays the same: [FORMAT: Bold this →] every commit gets scanned, every vulnerability gets explained, and nothing ships until it's clean.

The pipeline doesn't make your code secure. It makes insecure code [FORMAT: Bold this →] impossible to deploy.

[FORMAT: Type --- and press Enter to create a horizontal line]

[FORMAT: Italic this entire line →] Built with Python, FastAPI, GitHub Actions, CodeQL, Bandit, Trivy, OWASP ZAP, and Gitleaks.

[FORMAT: Add these as Medium tags when publishing:]
DevSecOps, GitHub Actions, Cybersecurity, Python, DevOps
