# Grafter

Grafter scans a GitHub organization or user account for GitHub Actions
trust-boundary risks, exposed credentials, unsafe issue-ops policies, and
agentic workflow injection. It combines deterministic YAML analysis and
source/sink heuristics with a dashboard for investigation, review, comparison,
and reporting.

**Stack:** Python/FastAPI, React/TypeScript/Vite, and local SQLite persistence.
Scanning does not require an LLM. Ollama review and experimental Live PoC
automation are separate, optional features.

See the [complete documentation](DOCUMENTATION.md) for every rule, dashboard
action, API endpoint, configuration variable, and operational limitation.

## Run locally

Requirements: Python 3.10+, Node.js 18+ with npm, a GitHub PAT, and the `curl`
executable for credential validation. Git is additionally required for Live PoC.

From the repository root, prepare and start the backend:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

In another terminal, from the repository root:

```powershell
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** and log in with **`admin` / `password`**.
The backend listens on **http://127.0.0.1:8765**; Vite proxies `/api` requests
to it. After initial dependency setup, `.\startup.ps1` starts both services
in separate PowerShell windows and opens the browser.

The default credentials are for local use. Override `GRAFTER_ADMIN_USER`,
`GRAFTER_ADMIN_PASSWORD`, and `GRAFTER_SESSION_SECRET` before shared deployment.
Sessions last three days by default; `GRAFTER_SESSION_TTL_SECONDS` can extend,
but not shorten, that lifetime.

## Main functionality

| Area | Functionality |
| --- | --- |
| Scanning | Organization/user discovery, optional forks, repository limit, selectable rules, workflow and policy analysis, referenced-helper inspection, credential validation, and historical log checks |
| Token pool | Save multiple PATs, inspect masked previews, remove accounts, rotate across usable tokens, and display account-aware combined API quota |
| Queue | Durable jobs, live activity and API telemetry, automatic quota waits, repository checkpoints, restart recovery, cancellation, retry, and pending-job ordering |
| Findings | Search, filters, sorting, pagination, evidence, snippets, gate rationale, source/sink graph, manual verdicts, bulk actions, and recheck at HEAD |
| Comparison | New, persistent, fixed, and severity/confidence-changed findings across scans, with partial-rule-scope handling |
| Reporting | Bug-bounty report drafts, Markdown, SARIF 2.1.0, full JSON, compact triage JSON, and reviewed JSON/CSV |
| Ask AI | Optional Ollama second opinion using current workflow YAML and related workflow context |
| Live PoC / Jobs | Experimental driver-based mirror reproduction, phase logs, observed signals, verdicts, cancellation, and history |

Findings, scan history, review labels, jobs, and repository checkpoints survive
backend restarts. Data defaults to `%USERPROFILE%\.grafter`, outside this
checkout. Saved PATs are stored locally in `tokens.json`; they are **not
encrypted** and are never copied into scan queue rows.

## Nine rule families

| Family | What it searches for |
| --- | --- |
| Untrusted code execution | PR-controlled checkouts, scripts, local actions, Dockerfiles, auto-merge paths, and executable tool configuration |
| Injection primitives | Event data reaching shell/JavaScript, runner controls, workflow command channels, weak actor gates, or trusted filenames |
| Cross-workflow trust-boundary leaks | Privileged `workflow_run`, artifact/env-file poisoning, cache writes, and trusted-label persistence |
| Data exfiltration | Artifact exposure, validated credential candidates, wholesale secrets serialization, and unmasked secret-shaped log values |
| Runner & infrastructure compromise | Untrusted self-hosted execution, connected Docker-authority paths, and recursive PR-controlled submodules |
| Cloud & registry abuse | Conditional OIDC/cloud credential exposure and release/package/container publishing |
| Supply chain | Mutable external actions, remote installers, and reusable-workflow secret inheritance |
| Agentic workflow injection | Untrusted prompts, code context, instruction/MCP files, agent tools, automatic application, and AI-based authorization |
| Hygiene & visibility | Permissions, persisted checkout credentials, artifacts, caches, nonblocking security checks, issue-ops policies, and parse failures |

The [rule reference](DOCUMENTATION.md#rule-reference) describes every category.
The scan pane's searchable **Rules to run** selector supports individual
categories and remembers the selection in the browser. Rule scope persists
through queue retries and restarts. Selecting fewer rules filters emitted
findings; it does not skip every discovery, log-check, or secret-validation
phase. Workflow/policy parse-error categories remain enabled.

## Queue, quota, and retry

Direct scans and queued attempts use the **same scanning engine**. Queue rows
show the current phase/repository, completed/failed/unfinished repositories,
saved findings, queued/in-flight API requests, responses received, last response
age, backoff, token rotations, and quota reset information.

Two independent accounts with 5,000-request limits can contribute a combined
10,000-request capacity, but the display shows their **actual remaining**
requests. Same-account tokens share a budget and are not double-counted.
Inactive token quotas are refreshed during long scans; exhausted pools wait
for reset rather than continuously sending requests.

Retry preserves the scan ID and saved findings, skips completed repositories,
and retries failed or unfinished repositories. Resume is **repository-level,
not file-level**. Request telemetry resets per attempt; durable checkpoints do
not. Repeated finding IDs are upserted rather than duplicated.

See [queue behavior](DOCUMENTATION.md#scan-queue-and-recovery) and
[token-pool accounting](DOCUMENTATION.md#github-tokens-and-api-quota).

## Interpreting results

Findings are review candidates, not a guarantee of anonymous-fork exploitability.
The analyzer considers triggers, checkout refs, permissions, runner type, and
recognizable gates, but cannot prove every runtime condition or external policy.
Confidence is a heuristic score, not an exploitation probability.

The findings list and standard exports enforce **confidence >= 80**.
The live scan-status payload further limits its inline findings to
`HIGHLY_EXPLOITABLE`, `REALISTIC`, `CONDITIONAL`, and `HARDENED`.
Changing dashboard filters cannot disable the confidence threshold.

The corrected **`docker-runner-compromise`** rule requires connected attacker
execution and Docker authority in the same execution context. A socket
elsewhere in a job, host networking, ordinary Dockerfile builds, container root,
or broad agent tool flags do not independently prove host compromise.
Surviving Docker findings are **MEDIUM / CONDITIONAL**, with **unscored CVSS**
until provenance and effective daemon/host impact are established. Recheck or
rescan old findings to apply updated detection; stored records are not
automatically rewritten by a code update.

## Optional integrations

**Ask AI:** install Ollama, pull the configured model (default `qwen3:1.7b`),
and use **Ask AI** in a finding. Its advice does not automatically change the
finding's score or manual verdict.

**Live PoC is experimental and creates public mirrors.** Do not use it to copy
confidential source into a mirror. Seven categories currently have automated
drivers; other rules have static report guidance, not automated reproduction.
All registered drivers advertise mirror-only operation. Cleanup is best-effort,
and mirror evidence does not prove equivalent impact in the original repository.
See the [Live PoC guide](DOCUMENTATION.md#experimental-live-poc-and-jobs).

## Further reference

- [Setup, authentication, and configuration](DOCUMENTATION.md#installation-and-startup)
- [Dashboard and review workflow](DOCUMENTATION.md#dashboard-and-triage)
- [Exports and reports](DOCUMENTATION.md#exports-and-reports)
- [Complete API reference](DOCUMENTATION.md#api-reference)
- [Developer checks](DOCUMENTATION.md#development-and-checks)
- [Troubleshooting](DOCUMENTATION.md#troubleshooting)

Interactive API reference: **http://127.0.0.1:8765/docs**.
Protected API calls require the login session cookie, including scans and exports.
