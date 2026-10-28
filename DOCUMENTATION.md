# Grafter Documentation

This guide describes the functionality implemented in the current checkout.
Grafter is a local web application for scanning GitHub organizations and user
accounts, investigating GitHub Actions and issue-ops automation risks, and
maintaining a durable review history.

## Contents

- [Product overview](#product-overview)
- [Installation and startup](#installation-and-startup)
- [Authentication](#authentication)
- [Running scans](#running-scans)
- [GitHub tokens and API quota](#github-tokens-and-api-quota)
- [Analysis model](#analysis-model)
- [Rule reference](#rule-reference)
- [Finding fields and visibility](#finding-fields-and-visibility)
- [Dashboard and triage](#dashboard-and-triage)
- [Scan queue and recovery](#scan-queue-and-recovery)
- [Cross-scan diff](#cross-scan-diff)
- [Exports and reports](#exports-and-reports)
- [Ask AI](#ask-ai)
- [Experimental Live PoC and Jobs](#experimental-live-poc-and-jobs)
- [Persistence and data handling](#persistence-and-data-handling)
- [Configuration reference](#configuration-reference)
- [API reference](#api-reference)
- [Development and checks](#development-and-checks)
- [Troubleshooting](#troubleshooting)
- [Scope and limitations](#scope-and-limitations)

## Product overview

Grafter combines these components:

| Component | Responsibility |
| --- | --- |
| Python/FastAPI backend | GitHub API access, deterministic analysis, credential checks, queue scheduling, SQLite persistence, reports, and authenticated endpoints |
| React/TypeScript/Vite frontend | Scan setup, token management, progress, findings, Rules, Diff, Queue, and Live PoC Jobs |
| Optional Ollama service | On-demand second opinion about a selected finding |
| Experimental Live PoC subsystem | Driver-based GitHub mirror reproduction and observed-evidence tracking |

The main scanner uses YAML parsing, shared workflow context, and source/sink
heuristics. It does not need an LLM and does not execute target workflow code
locally as part of ordinary scanning. Scanning is not entirely offline:
repository reads, historical log downloads, and enabled provider credential
checks make network requests. Live PoC is a separate, explicitly started mode
that creates GitHub repositories and runs workflows.

## Installation and startup

### Requirements

| Requirement | Used for |
| --- | --- |
| Python 3.10+ | Backend |
| Node.js 18+ and npm | Frontend development/build |
| GitHub PAT | Repository enumeration and reads; private access depends on token permissions |
| `curl` executable on PATH | Provider-specific credential validation |
| Git executable on PATH | Live PoC cloning and repository preparation |
| Ollama and a downloaded model | Optional Ask AI only |

The examples below use Windows PowerShell. Python dependencies are defined in
[`backend/requirements.txt`](backend/requirements.txt); frontend dependencies
and scripts are in [`frontend/package.json`](frontend/package.json).

### Install dependencies

From the repository root:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd ..\frontend
npm install
```

Calling the virtual environment's Python directly avoids PowerShell activation
policy issues. Activation is optional.

### Development services

In one terminal, from the repository root:

```powershell
cd backend
.\.venv\Scripts\python.exe main.py
```

In a second terminal:

```powershell
cd frontend
npm run dev
```

| Service | Default URL |
| --- | --- |
| Dashboard | http://localhost:5173 |
| Backend | http://127.0.0.1:8765 |
| Health | http://127.0.0.1:8765/api/health |
| Swagger UI | http://127.0.0.1:8765/docs |
| OpenAPI schema | http://127.0.0.1:8765/openapi.json |

Vite's development proxy forwards `/api` to port `8765`. If you change the
backend port, update the proxy in `frontend\vite.config.ts` as well.

After dependency installation, this Windows launcher starts both services in
separate PowerShell windows and opens the browser:

```powershell
.\startup.ps1
```

The launcher uses `backend\.venv\Scripts\python.exe` when available, otherwise
`python`. It installs frontend packages only if `node_modules` is absent.
It does not create the backend environment or install backend requirements.

### Serve a built frontend from the backend

From the repository root:

```powershell
npm --prefix frontend run build
$env:GRAFTER_STATIC_DIR = (Resolve-Path .\frontend\dist).Path
.\backend\.venv\Scripts\python.exe .\backend\main.py
```

Open the backend URL for the dashboard. Without an override, the backend looks
for `backend\static`. It does not automatically copy a new Vite build there.
`npm run preview` is also available for previewing a frontend build; it is not
a production deployment service.

Use one backend process for the normal local deployment. Scheduler and Live PoC
coordination include process-local state; multiple backend workers are not a
supported way to increase scan throughput.

## Authentication

Default login: **username `admin`, password `password`**.

Grafter has one configured application administrator, not separate user accounts
or per-user access to findings. Browser login creates a signed session cookie
used by protected API requests.

| Behavior | Current implementation |
| --- | --- |
| Session lifetime | Three days / `259200` seconds by default; smaller configured values are clamped to three days |
| Expiration | Fixed from login, not a sliding inactivity timer; a new login obtains a fresh lifetime |
| Cookie | HttpOnly, SameSite=Lax, path `/`; Secure is configurable |
| Signing secret | `GRAFTER_SESSION_SECRET`, otherwise derived from configured username/password |
| Logout | Clears the browser's session cookie |
| Public API paths | Health, login, logout, and session inspection |
| Other `/api` calls | Require the session cookie; unauthenticated calls return `401` |

Changing credentials invalidates existing sessions when using the derived
signing secret. Configure credentials before launching the backend, and restart
it after configuration changes. Existing cookies retain their original expiry.

For a shared deployment, set nondefault credentials, a random signing secret,
HTTPS, and `GRAFTER_COOKIE_SECURE=true`. The application does not implement a
multi-user identity provider or role model. Swagger/OpenAPI pages themselves
are outside the `/api` authentication middleware; their protected API calls
still need a valid session.

Example environment setup:

```powershell
$env:GRAFTER_ADMIN_USER = "security-admin"
$env:GRAFTER_ADMIN_PASSWORD = "replace-with-a-long-random-password"
$env:GRAFTER_SESSION_SECRET = "replace-with-a-long-random-signing-secret"
```

## Running scans

### Scan workflow

1. Log in and unlock the GitHub connection fields when editing them.
2. Enter an organization or user login, not a repository URL.
3. Supply a PAT or select the locally saved connection; add other PATs to the pool if needed.
4. Choose the repository limit, whether to include forks, and rules to emit.
5. Start the scan and watch progress in the scan pane or Queue.
6. Open findings as they arrive; completion is not required to begin review.

Enumeration first tries the organization endpoint and falls back to the user
endpoint when appropriate. Archived repositories are skipped; forks are skipped
unless enabled. The limit applies to included repositories. This is an
owner-wide scan interface, not a single-repository or arbitrary-branch selector.

For each repository the worker downloads `.github/workflows` YAML files,
collects peer-workflow summaries, inspects eligible referenced helper files,
analyzes workflows, checks relevant historical log candidates, analyzes
`.github/policies` YAML, and optionally discovers and validates credentials.
Reads normally target the current/default branch, not every PR head or all
git history.

### Scan options

| API field | Default | Meaning |
| --- | --- | --- |
| `org` | Required | GitHub organization/user login |
| `token` | Omitted | Use the saved token if not provided |
| `include_forks` | `false` | Include fork repositories; archived repositories remain excluded |
| `max_repos` | `200` | Maximum included repositories; UI offers a numeric input from 1 to 2000 |
| `concurrency` | `8` | Bounds repository workers and GitHub request concurrency |
| `remember` | `true` | Validate and locally save a supplied token |
| `validate_secrets` | `true` | Run repository credential discovery/provider validation |
| `max_secret_candidates_per_repo` | `50` | Candidate-validation budget per repository |
| `selected_rules` | `null` | All selectable categories; otherwise an array of category slugs |

The UI exposes owner, PAT/pool, repository limit, forks, and rule selection.
Advanced concurrency and credential-validation options are available through
the API. `token_pool` is an internal server-populated field, not a client
configuration mechanism.

`POST /api/scan` creates an asynchronous job. Its response is initial status,
not a completed finding set. Poll `/api/scan/{scan_id}` or follow Queue.
Scan status uses `pending`, `starting`, `running`, `waiting_rate_limit`,
`done`, `error`, and `cancelled`; queue history uses `completed` and `failed`
for the corresponding terminal outcomes.

### Rule selection

The searchable **Rules to run** control supports individual categories, Select
all, and Deselect all. Its initial default is All rules; subsequent selection
is remembered in browser local storage.

`GET /api/rules` returns the ordered selectable registry. Omitted/null
`selected_rules` means all rules; an empty selection or unknown slug is
rejected. The normalized scope is part of queue deduplication and persists in
scan history, retries, and restart recovery.

Selection filters **emitted findings**, not all analysis work. Discovery,
workflow downloads, historical log checks, and enabled credential validation
still run. To disable provider credential validation, use
`validate_secrets: false`; deselecting `verified-secret` alone does not do that.
Workflow and policy parse-error categories are operational coverage signals and
are always included in the category scope, although normal visibility limits
still apply.

### Immediate versus queued execution

Both use `run_scan`; there is no separate reduced-capability queue scanner.
A job starts immediately when a worker slot is available. Additional jobs wait
pending. Exhausted API quota moves work to a durable rate-limit wait. Equivalent
active requests with the same owner/options/rule scope return `409` with the
existing job and scan IDs instead of creating duplicates.

## GitHub tokens and API quota

### Saved connections

The scan pane can save a PAT, add additional pool tokens, show masked previews,
and remove saved accounts. Tokens are validated through GitHub's identity API
on save. For classic PATs, `repo` is normally needed for private repositories
and `read:org` for organization access. Repository visibility, organization
SSO authorization, and fine-grained permissions still apply.

Saved tokens are local to the OS user's Grafter data directory, not browser
local storage. Queue rows contain no raw PAT. Each scheduled/retried attempt
loads the current saved pool, so a valid saved token must remain available for
durable recovery. `remember: false` avoids saving a supplied token, but does
not give that token persistence for a delayed attempt or restart.

The legacy `/api/token` API handles the primary connection; `/api/tokens`
manages the pool. Forgetting the legacy scan connection deletes the shared
token file, clearing both the scan pool and any Live PoC credentials in it.
Removing `/api/tokens/{login}` removes saved entries for that login. Current
scan-pool save/remove operations rewrite that file with pool records, so
verify/re-save Live PoC credentials after changing the scan pool.

### Adding a PAT and proxy errors

When you save a PAT, the backend validates it with
`GET https://api.github.com/user` before storing it. This request uses HTTPX
with its default `trust_env=True`, so it can inherit `HTTPS_PROXY`,
`HTTP_PROXY`, and `ALL_PROXY`. On Windows/macOS, HTTPX can also discover system
proxy settings. These are separate from Vite's local frontend-to-backend proxy.

A stale proxy such as `http://127.0.0.1:9` can therefore prevent a **valid PAT**
from being saved. That address is not a configured Grafter endpoint; it can
come from the environment or system proxy configuration. Connection refusal,
proxy errors, and timeouts can occur before GitHub receives the validation
request. The PAT-saving endpoint currently does not translate these network
exceptions into a specific proxy error, so the UI may show a generic server
error instead of a useful diagnosis.

If adding a PAT fails in a new environment:

1. Inspect the backend process's proxy environment variables and relevant OS proxy settings. Proxy URLs can contain credentials; avoid sharing their complete values in logs or screenshots.
2. If a corporate proxy is required, correct its address/configuration and confirm it is reachable.
3. If direct GitHub access is allowed, add GitHub and local application hosts to `NO_PROXY`, preserving existing exclusions.
4. Restart the backend from the terminal with the corrected environment, then retry saving the PAT.

For direct access, stop the existing backend and run the following from the
repository root in PowerShell:

```powershell
$env:NO_PROXY = (@($env:NO_PROXY, "api.github.com", "127.0.0.1", "localhost") |
    Where-Object { $_ }) -join ","
.\backend\.venv\Scripts\python.exe .\backend\main.py
```

This changes only the current terminal's environment and processes started
from it; it does not change an already running backend or permanently modify
the machine's proxy settings. Shells on other platforms use the same
`NO_PROXY` variable with their native environment-setting syntax. A proxy
bypass will not work where direct outbound GitHub access is blocked.

Do not treat every save failure as an invalid token: distinguish network/proxy
failure from a GitHub rejection, then check PAT permissions and organization
SSO authorization when GitHub is reachable. Scans and rechecks use HTTPX too,
so inherited proxy problems can also affect later GitHub operations.

### Rotation and account-aware accounting

Grafter rotates sequentially when the current token has insufficient quota;
it does not round-robin every request. Response quota headers are attributed
to the token that sent the request, including concurrent requests.

| Display | Interpretation |
| --- | --- |
| Pool remaining / limit | Last known quota summed across independently identified account budgets |
| Active token remaining / limit | Quota for the currently selected token, not the entire pool |
| Account breakdown | Each known account's contribution; frontend logins are redacted |
| Partial coverage | One or more token quota probes are unavailable; the total is not fully known |
| Next reset | Earliest applicable reset from GitHub's quota information |
| Rotations | Token switches made by this client/attempt |

Two separate accounts with 5,000-request core API limits can offer 10,000
combined capacity. That does **not** mean every scan starts with 10,000
remaining: one account may already be exhausted or used elsewhere. Multiple
PATs from the same saved login share an account budget and are not counted
as independent 5,000-request allocations.

Inactive-token quota refresh runs about every 30 seconds during active scans.
Previously exhausted accounts become eligible after reset. Idle waiting jobs
also recheck the saved pool at most every 30 seconds and can resume when
usable quota is discovered.

Pool figures are snapshots, not reservations or a promise of future capacity.
Other tools using the same account consume that budget. Rotation changes
credentials but does not expand any token's repository access; pool tokens
should have compatible access to the intended targets.

### Request handling

Transport failures and HTTP `500`, `502`, `503`, and `504` receive up to five
attempts with backoff. Secondary-limit responses use retry guidance or bounded
backoff. Once the entire primary-rate-limit pool is exhausted, pending/new
requests fail fast and the job winds down into its persisted wait.

Persistent transport/retried server failures leave failed repository work
rather than a successful empty result. Authentication, access, missing-file,
and discovery responses have endpoint-specific handling; a repository marked
complete is not proof every potentially relevant file was accessible.

## Analysis model

### Shared context extraction

The analyzer parses workflow YAML and extracts triggers, event types,
permissions, jobs, steps, checkout refs, containers, runner labels,
environments, conditions, and dependency relationships. Peer-workflow summaries
help relate `workflow_run` consumers to upstream workflows. Eligible referenced
scripts can contribute additional evidence, especially to agentic detection
and inspected Docker permission checks.

This is bounded static context, not complete interprocedural analysis. Helper
discovery and downloads are limited, and arbitrary remote action/reusable
workflow implementations are not exhaustively fetched or evaluated.

### Source and sink heuristics

Sources include PR/issue/comment/review text, branch refs, dispatch payloads,
artifacts, and PR-controlled files. Sinks include shell/JavaScript execution,
build/install/test commands, local actions, environment/path command files,
publish operations, agent tools, and metadata mutation.

Different categories use different matching and correlation logic. Evidence
can identify a concrete expression and line, but not every finding has a fully
resolved end-to-end execution path. Presence of an unsafe pattern is not proof
of attacker reachability or production impact.

### Permissions and runner type

Job permissions override workflow permissions where applicable. Explicit write
scopes, `write-all`, secret references, cloud login steps, and `id-token: write`
affect risk classification. Missing permissions leave repository defaults
unknown; the scanner cannot read every effective organization policy.

Runner labels help distinguish hosted execution from persistent self-hosted
infrastructure. Unknown or dynamic labels remain uncertain. Self-hosted
execution may expose local state or network services even when GitHub withholds
repository secrets from a fork PR.

Ordinary hosted fork `pull_request` execution is not automatically credential
compromise: GitHub normally withholds repository/organization secrets and
restricts the workflow token. Same-repository PRs, approved environments,
platform policy, and pre-existing runner/cloud state require separate analysis.
An OIDC claim additionally requires an obtainable token, a matching cloud
federation policy, and useful resulting permissions; `id-token: write` alone
does not establish that chain.

### Gates and confidence

Recognized controls include author/association checks, exact identity checks,
fork/ref/branch restrictions, environments, trigger event types, step gates,
and upstream `needs` gates. They can downgrade severity, confidence, or
exploitability. The presence of `environment:` does not prove required
reviewers are configured; helper names and unknown outputs do not establish
authorization.

General gate analysis remains heuristic. The Docker category has a stricter
context-sensitive witness and admitted/blocked/unknown gate model; do not
assume all other rules have identical path precision.

## Rule reference

The Rules screen organizes **55 categories into nine families**: 53 selectable
security categories and two operational parse-error categories. Its cards show
descriptions, category keys, and finding counts; click a card to filter Findings
to that category. This catalog is separate from the Rules to run scan selector.
The tables below list every key, including visibility/hygiene rules. Catalog
membership does not mean every observation passes dashboard visibility
thresholds or is a demonstrated vulnerability.

### 1. Untrusted code execution

| Category | Searches for |
| --- | --- |
| `checkout-untrusted` | Privileged-trigger checkout resolving to PR-controlled content, with execution/build relationships used to assess impact |
| `pr-code-execution-risk` | PR-controlled execution with a significant runner or credential context, rather than ordinary isolated PR CI alone |
| `pull-request-ci-code-execution` | Contributor code executed by normal PR CI; primarily visibility unless additional privileged context is established |
| `pull-request-authenticated-code-execution` | Conditional environment-approved credential login followed by PR-controlled code; actual credential release must be verified |
| `pr-controlled-dockerfile-build` | A PR-selected Dockerfile/build context reaching Docker/Buildah/build actions; Dockerfile execution is not automatically a host escape |
| `reusable-local-action-untrusted` | Local action/repository code executed after a potentially untrusted checkout |
| `comment-command-pr-checkout` | Issue/comment command paths that select and execute PR head code in a base-repository workflow |
| `pull-request-auto-merge-untrusted` | Untrusted-reachable automation enabling or performing merge without sufficient authorization |
| `living-off-the-pipeline` | Linters, formatters, test/build tools, or wrappers loading executable PR-controlled configuration, such as `conftest.py` or `eslint.config.js` |

### 2. Injection primitives

| Category | Searches for |
| --- | --- |
| `script-injection` | Untrusted GitHub expressions reaching shell/JavaScript or supported wrapper-action script fields, including recognized indirection |
| `runner-control-injection` | Untrusted values in runner, container, service, shell, or matrix control fields |
| `deprecated-commands` | Deprecated or sensitive runner command-channel primitives; effectiveness depends on runner behavior |
| `bypassable-actor-allowlist-gate` | Substring/prefix/suffix or other loose actor comparisons used as authorization |
| `filename-collision-download` | Untrusted downloads taking a predictable filename later consumed as trusted executable/install/publish input |

### 3. Cross-workflow trust-boundary leaks

| Category | Searches for |
| --- | --- |
| `workflow_run-privileged` | Elevated downstream workflows consuming less-trusted upstream artifacts or metadata |
| `artifact-to-github-env` | Downloaded content written into `GITHUB_ENV`/`GITHUB_PATH`, enabling environment/path poisoning |
| `artifact-extraction-poisoning` | Untrusted archive extraction or executable planting in a privileged consumer |
| `cache-poisoning` | Attacker-influenced keys/executable paths where the recognized cache implementation permits writes; known read/none and low-trust defaults are suppressed |
| `pull-request-target-label-persistence` | Trusted labels reused on later `synchronize` events after attacker-controlled code changes |

### 4. Data exfiltration

| Category | Searches for |
| --- | --- |
| `upload-artifact-exfil` | Untrusted artifact inputs or sensitive upload paths that may expose credentials or private content |
| `verified-secret` | Provider-recognized credential candidates accepted by a validation check; PEM blocks are format-verified rather than live-validated |
| `secrets-context-wholesale` | Whole-secret-context serialization such as `toJSON(secrets)` instead of narrowly scoped secret use |
| `secret-echoed-to-log` | Secret-shaped values actually present unmasked in inspected historical Actions logs; shape/log presence is not independent proof the credential is live |

Credential formats/providers include GitHub, OpenAI, Anthropic, Slack, Discord,
npm, AWS, Stripe, SendGrid, Hugging Face, Docker Hub, GitLab, Google API keys,
and PEM private-key blocks. Candidate checks use provider-specific requests
intended to validate access without modifying provider resources. PEM content
is not sent to a provider. Unverified candidates are suppressed.

Credential discovery is bounded by candidate-file selection and per-repository
candidate limits, not a full historical secret audit. Secret findings use
masked values and fingerprints. Historical log checks suppress GitHub-masked
`***` values and unavailable/non-reflected candidates; recent-run limits apply.

### 5. Runner & infrastructure compromise

| Category | Searches for |
| --- | --- |
| `self-hosted-runner-untrusted` | Untrusted-trigger code reaching execution on a self-hosted runner |
| `self-hosted-runner-exposure` | A self-hosted runner reachable from an untrusted trigger without the stronger concrete execution evidence |
| `docker-runner-compromise` | Connected attacker execution and Docker authority within the same execution context |
| `pr-submodules-recursive` | PR-controlled `.gitmodules` used by recursive submodule fetching, with possible outbound-request/credential exposure |

#### Docker rule interpretation

The corrected Docker rule distinguishes runner-host steps, job containers, and
Docker containers with explicit host-authority mounts. It requires a connected
source, attacker execution, and authority witness; unrelated Docker setup
elsewhere in the job is insufficient.

Ordinary Dockerfile builds, fixed pull/login/setup commands, host networking,
container root, checkout alone, and agent `--allow-all-tools` flags do not
independently prove host compromise. A socket exposed only to a trusted gateway
is not automatically attributed to an isolated agent. Safe environment data and
model-mediated instructions are not deterministic shell execution merely
because they occur near a Docker command.

The rule checks relevant job dependencies and step conditions and recognizes
a narrow, fully inspected fail-closed permission-helper pattern. Gates are
admitted, blocked, or unknown. Unknown helpers/activation outputs and
environment protection remain uncertainty. Authorization after attacker
execution does not protect the earlier execution.

Surviving findings are **MEDIUM / CONDITIONAL**: confidence `86` for an
admitted structural path or `75` when gates are uncertain. The latter is below
the standard findings-list threshold. Evidence includes source/execution/sink
locations, context, gate result, permissions, workflow content hash, and
provenance/impact assumptions.

Effective rootful/rootless daemon authority, host impact, and immutable
workflow/helper revisions are not established. Docker CVSS is therefore
**unscored**, including when reporting an older stored Docker finding.
The report API returns null score/vector and SARIF omits numeric CVSS fields.
Use Recheck or a new scan to refresh old detection evidence; a code update does
not retroactively replace every stored finding.

Agent-written state later consumed by a host and credential forwarding are
different boundaries; no separate new rule families for those boundaries are
implied by this Docker correction.

### 6. Cloud & registry abuse

| Category | Searches for |
| --- | --- |
| `oidc-cloud-credential-abuse` | Untrusted execution with OIDC/cloud credential indicators and a plausible privileged path |
| `oidc-cloud-credential-visibility` | OIDC permission/authentication exposure without the stronger complete exploit evidence |
| `release-publish-poisoning` | Untrusted material reaching package, release, or container publishing |

Cloud federation configuration and granted cloud roles are external
preconditions. Existing cloud login may matter only if attacker execution can
actually access its session/credentials; a normal fork PR does not simply
inherit secrets because a login action is named in YAML.

### 7. Supply chain

| Category | Searches for |
| --- | --- |
| `third-party-action-supply-chain` | Mutable external action references in privileged contexts |
| `mutable-action-reference` | Action refs using mutable tags/branches instead of a full commit SHA |
| `remote-script-installer` | Downloaded scripts executed at workflow runtime, such as supported `curl`/`wget` to shell patterns |
| `reusable-workflow-secret-inheritance` | `secrets: inherit` forwarding more credentials than a callee explicitly needs |

An unpinned reference or remote installer is a trust/dependency risk, not proof
that its upstream is already compromised.

### 8. Agentic workflow injection

| Category | Searches for |
| --- | --- |
| `agentic-workflow-injection` | Untrusted GitHub data reaching an agent with repository mutation or privileged tools |
| `agentic-code-context-poisoning` | PR diffs/files/artifacts used as agent context that can contain adversarial instructions |
| `agentic-tool-execution` | Agent/model output controlling shell commands, patches, or other execution/tool sinks |
| `agentic-comment-command` | Untrusted comment/review commands invoking a privileged agent |
| `agentic-workflow-run-poisoning` | Less-trusted upstream artifacts feeding an agent in a privileged downstream workflow |
| `agentic-prompt-file-poisoning` | PR-controlled prompt/instruction files loaded by an agent |
| `agentic-mcp-config-poisoning` | PR-controlled MCP/tool configuration loaded by an agent |
| `agentic-secrets-to-ai-context` | Secret-bearing context combined with attacker-controlled agent input |
| `agentic-output-auto-apply` | Agent output applied/executed/committed without a meaningful human approval boundary |
| `agentic-verdict-authorization` | AI output/verdict used to authorize a privileged workflow operation |

Detection recognizes supported agent/action/CLI patterns and some referenced
helpers. Prompt injection is a model-mediated risk, not a guarantee a specific
payload will cause a specific tool call.

### 9. Hygiene & visibility

| Category | Searches for |
| --- | --- |
| `permissions-not-pinned` | Missing explicit workflow/job token permissions |
| `excessive-token-permissions` | Broad write scopes or `write-all` |
| `checkout-credential-persistence` | Checkout authentication left available to later workspace code |
| `pull-request-target-metadata-write` | Base-context metadata-write permissions, even without a direct code-execution primitive |
| `comment-trigger-write-scope` | Comment/review-style triggers combined with write-capable token scopes |
| `artifact-retention-or-scope` | Broad artifact paths, hidden-file inclusion, or long retention |
| `cache-restore-key-fallback` | Broad fallback restore keys that increase cache confusion risk |
| `security-step-continue-on-error` | Security checks configured not to fail the workflow |
| `workflow-parse-error` | Workflow YAML the scanner could not parse |
| `policy-file-unauth-mutation` | Issue-ops policy events causing labels, closure, merge/review/branch mutation, or similar writes without adequate sender authorization |
| `policy-file-parse-error` | Issue-ops policy YAML the scanner could not parse |

Policies under `.github/policies` are not Actions workflows; their effective
authority belongs to the consuming bot/App. The scanner examines recognized
policy configuration, not the bot's entire server implementation.

## Finding fields and visibility

| Field | Meaning |
| --- | --- |
| ID | Stable identity derived from repository/workflow/job/step/rule identity, used for upserts and comparison |
| Repository / workflow / URL | Location of the observed configuration |
| Trigger / job / step | Context associated with the rule |
| Severity | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| Exploitability | Heuristic attacker-path classification |
| Confidence | Structural heuristic score, not a calibrated probability |
| Why / evidence | Rationale and observations supporting the finding |
| Snippet / line | Relevant code excerpt and optional line number |
| Tainted expression / sink line | Optional exact source/sink references |
| Gates | Recognized controls and downgrade rationale |
| Remediation | Suggested changes to review against the full workflow |
| Manual verdict | Analyst label and timestamp |
| Archive/recheck fields | Current lifecycle state, reason, recheck time, and content SHA when available |

Exploitability vocabulary:

| Value | Meaning |
| --- | --- |
| `HIGHLY_EXPLOITABLE` | Strong heuristic support for a readily usable path |
| `REALISTIC` | Plausible practical path under ordinary relevant conditions |
| `CONDITIONAL` | Additional preconditions or uncertain controls matter |
| `HARDENED` | Important protections reduce the pattern's practical risk |
| `BLOCKED` | A recognized control blocks the claimed path |

Findings-list queries, standard exports, and counts enforce a backend
confidence threshold of `80`. There is no UI filter that disables it.
The inline `findings` array in live scan-status responses additionally accepts
only `HIGHLY_EXPLOITABLE`, `REALISTIC`, `CONDITIONAL`, and `HARDENED`.
These are distinct presentation paths: the database list does not apply that
additional exploitability-set restriction. A stored high-confidence `BLOCKED`
finding can therefore appear in the database view, but selecting Blocked cannot
recover low-confidence observations or findings never emitted by a rule.

Queue saved-finding counts describe durable records before these presentation
filters and may differ from the visible list. Filters, archive state, prior
records, and repeated finding identities can also explain count differences.

## Dashboard and triage

### Navigation and overview

The main views are **Findings**, **Diff**, **Rules**, **Queue**, and **Jobs**.
Live PoC setup/details are inside the finding drawer, not a separate main tab.
Severity cards, category counts, the recent daily trend, and reviewed totals
summarize the stored data. Trend data tracks creation-day findings and review
labels; it is not continuous monitoring of live exploitability.

The scan pane shows current scan status, repository/workflow progress,
activity, errors, and API pool quota. Findings continue refreshing for active
background jobs and when a rate-limited scan resumes.

### Finding search and filters

Supported controls:

| Control | Behavior |
| --- | --- |
| Repository | Substring match on owner/repository |
| Search | Searches title, category, trigger, workflow path, why/evidence/remediation, snippets, and verdict text |
| Category | Searchable category menu with counts |
| Severity / exploitability | Select a single value or all |
| Lifecycle | Live only, Archived, or All |
| Scan scope | Current scan or all stored findings |
| Sort | Severity/confidence, newest, or oldest |
| Pagination | Paged list; API default 50, maximum 500 per page |

Search recognizes verdict aliases: `true positive`, `false positive`,
`severity overstated`, `unreviewed`, `verdict:tp`, `verdict:fp`,
`verdict:tp-overstated`, and `verdict:none`.
Combine one with content, for example `false positive script injection` or
`unreviewed docker`. Remaining content is a substring search, not a general
Boolean query language or a dedicated `source:`/`sink:` grammar.

Severity/category summary endpoints are scoped by scan/lifecycle, not every
free-text/list filter, so their totals need not equal a narrowed list.

### Finding drawer

Open a card to view the complete finding, copy its ID, follow the workflow
link, and inspect gate strength/rationale. The drawer contains:

| View/action | Function |
| --- | --- |
| Details & report | Why, evidence, snippet, remediation, Ask AI, and generated report |
| Exploitability graph | Presentation of source, execution context, gates, sink, and impact extracted from finding data |
| Live PoC | Driver preview, credentials/options, run launch, logs, signals, and history |
| Recheck at HEAD | Re-fetch the file and reassess the existing finding |
| Delete | Remove that finding record |

The graph summarizes the same evidence; it is not a separate runtime trace,
call graph, or proof engine. Report controls support copying report content and
downloading Markdown or single-finding SARIF.

### Manual verdicts and bulk actions

| Verdict | Use |
| --- | --- |
| `true_positive` | Analyst accepts the finding |
| `false_positive` | Analyst rejects the claimed vulnerability/path |
| `true_positive_severity_overstated` | Real issue, but scanner severity overstates its practical impact |
| `null` / Clear | Remove the analyst label |

Verdicts autosave. They do not automatically alter detector logic or retrain
the scanner. Select individual cards or Select visible, then mark TP, mark
TP-overstated, mark FP, clear labels, delete, or recheck the selection.
Select visible is page selection, not selection of every filtered result.
Bulk Recheck accepts up to 200 IDs per request.

Delete All removes findings across the database in the UI; it is not limited
by the current search. Deletion is different from archiving and does not
prevent a later scan from finding the same issue again.

### Recheck and lifecycle

A workflow recheck uses saved PATs and current HEAD content:

| Outcome | Result |
| --- | --- |
| Same finding identity still detected | Live; refresh evidence/scoring and recheck metadata |
| Rule no longer emits that identity | Archived as `fixed` |
| File absent / GitHub reports 404 | Archived as `deleted`; verify access if a private file unexpectedly disappears |
| Transient/permission failure or analysis exception | Do not treat the result as confirmed remediation |

The schema/filter also supports `modified`; the current ordinary recheck path
primarily sets live/fixed/deleted. Bulk recheck shares downloaded workflow/log
context to avoid repeating the same fetch for each finding.

Recheck is narrower than a full repository scan: it re-runs workflow analysis
without all scan-time support-file/peer context. Historical log findings get
their special log validation path. For policy findings, provider-validated
secrets, or context-dependent results, use a full rescan rather than treating
ordinary workflow recheck as complete validation.

## Scan queue and recovery

### States and actions

| Queue state | Meaning / available action |
| --- | --- |
| `pending` | Ready for a worker; move up/down or cancel |
| `starting` | Claimed by scheduler |
| `running` | Active scanning; request cancellation |
| `waiting_rate_limit` | Persisted wait for usable token quota; cancel if no longer needed |
| `completed` | Successful terminal history; delete history row if desired |
| `failed` | Error or failed repositories; Retry or delete history |
| `cancelled` | Interrupted work; Retry or delete history |

Retry is accepted only for failed/cancelled jobs. Only pending work can be
reordered. Only terminal history can be deleted. Deleting a queue-history row
does not delete its saved findings; findings and scan deletion are separate
operations.

Default active scan-job concurrency is one. Per-scan repository/request
concurrency defaults to eight. Raising `GRAFTER_QUEUE_MAX_ACTIVE_JOBS` allows
jobs to compete for the same accounts' API budgets; it does not create more
quota.

### Live activity and counters

Running rows refresh about every 2.5 seconds and explain ongoing work, such as
listing workflows, downloading a helper, analyzing YAML, checking logs,
validating credentials, backing off, rotating tokens, or winding down after
quota exhaustion. With concurrent repositories, the latest activity line is
not a full event log for every worker.

| Counter | Meaning |
| --- | --- |
| Completed / failed / unfinished repositories | Durable checkpoint state, including work from earlier attempts |
| Saved findings | Durable unique finding membership for the scan, before list visibility filters |
| Workflow downloads | Download/processing attempts; resumed repositories can repeat work |
| Pending requests | Logical requests already scheduled, split into queued and in-flight work |
| Responses received | Responses processed by this client, including retry responses |
| Last response age | Time since the latest observed GitHub response |
| Active repositories | Currently occupied repository workers |
| Backoff / rotations | Current retry delay and token switches |
| Pool / active-token quota | Combined account budget alongside the selected token |

Pending requests do not predict the total future work. Zero pending does not
prove a stall: YAML analysis or provider validation may be running. Quota probes
are separate from ordinary request telemetry. Live request/response/rotation
counters reset per attempt or backend restart; checkpoints do not.

### Durable retry and restart recovery

Repository snapshots and state are stored in SQLite. During retry:

1. The existing job and scan IDs are reused.
2. Completed repositories remain complete and are skipped.
3. Failed/interrupted repositories become pending.
4. Existing findings and analyst labels remain; repeated finding IDs are upserted.
5. The attempt loads the current saved token pool and persisted scan/rule options.

Resume is **repository-level**. An interrupted repository starts again from
its beginning, not the exact failed file/API instruction. A new scan is needed
to intentionally rediscover the owner's repository list or reassess previously
completed repositories.

Backend restart recovery returns stale active jobs/repositories to pending.
Cancellation cooperatively stops/drains child work before closing the client.
Successfully saved findings remain available even if the attempt later fails.

### Rate-limit waits versus failures

When all tokens are exhausted, the job persists quota/reset information and
waits. The earliest usable reset guides rescheduling; periodic pool checks can
find new usable capacity sooner. Quota waits have an automatic retry ceiling
of ten by default, configurable through `GRAFTER_QUEUE_MAX_RETRIES`.

Network errors such as DNS resolution failure, dropped connections, and
timeouts receive bounded HTTP retries. If failures remain, the repository is
marked failed and the overall job ends failed after other work finishes.
Manual Retry targets failed/unfinished repositories. Repository errors are
shown in Queue; they should not be confused with a normal quota wait.

Findings need not rise continuously: work can involve downloading, validation,
deduplication, filtered categories, or repositories without matching results.
Use activity, response age, request counts, and repository errors together.

## Cross-scan diff

Diff compares a current scan and a baseline for the same organization/user.
The default baseline is the most recent completed scan that finished before
the current scan started. An earlier scan can be selected explicitly.
Without a baseline, findings are new.

| Group | Meaning |
| --- | --- |
| New | Present only in the current scan |
| Persistent | Present in both; can show prior severity/confidence and deltas |
| Fixed | Present in the baseline but absent from the current scan's compared scope |
| Severity changed | Persistent identities with severity or confidence changes |

The Persistent column's Updated only control narrows it to changed results.
Diff badges show severity direction and confidence changes.

If either scan selected only some categories, comparison uses the intersection
of rule scopes. The response includes `compared_rules` and `scope_warning`;
unselected categories are not declared fixed. This is rule-scope protection,
not proof that repository coverage, permissions, or all runtime conditions
were identical. Incomplete/failed scans need particular care.

`scan_findings` stores membership and observed severity/confidence snapshots,
so later deletion of a live finding row does not erase the historical
comparison identity. This is not a complete immutable repository snapshot.

Recheck asks whether a particular finding matches now. Diff compares two
historical scanner outputs; its Fixed label is not independent confirmation
that a vulnerability was remediated.

## Exports and reports

### Export formats

| Format/action | Content and scope |
| --- | --- |
| SARIF | SARIF 2.1.0 for findings matching the current export filters |
| Full JSON | Full Finding fields, including rationale, evidence, snippet, remediation, gates, and optional source/sink fields |
| Triage JSON | Compact findings with actionable GitHub links, descriptions, evidence, remediation, verdict/lifecycle, and source/sink references |
| Reviewed JSON / CSV | Analyst-labeled findings across the reviewed dataset; separate from current list filters |
| Bug-bounty report | Structured report draft and Markdown for one finding |
| Single-finding SARIF | SARIF document containing one finding |

The UI Export menu offers SARIF, triage JSON with severity shortcuts, and
reviewed JSON/CSV. Full raw JSON is available through the API.
Standard filtered exports accept `repo`, `severity`, `exploitability`,
`scan_id`, `category`, `q`, and `state`. They default to 5,000 records and
clamp `limit` to 20,000; exports are not an unlimited database dump.

Raw Finding JSON does not add the computed bug-bounty CVSS fields. Use the
report API or SARIF for generated scoring metadata.

### SARIF and CVSS

SARIF includes rule/location metadata, supported source-to-sink code flows,
and generated remediation/fix descriptions. When scoring is available,
`properties["security-severity"]` carries numeric CVSS-related severity.
Do not assume every finding has an exact source line or code flow.

Docker findings are explicitly unscored: no numeric security-severity/vector
is fabricated, and CVSS status is recorded. Other report scores are automated
estimates, not independently validated impact assessments. Generated fix
descriptions are not automatically applied patches.

Downloaded SARIF can be supplied to a compatible viewer or a separately
configured GitHub code-scanning upload. Grafter does not automatically upload
results to the scanned repositories.

### Bug-bounty report drafts

Reports include title, severity, optional CVSS score/vector, summary,
vulnerability class, root cause, evidence/location, attacker preconditions,
impact, reproduction guidance, proof-of-concept text, fix diff, remediation,
references, and Markdown.

Review drafts against the full workflow and actual permissions/gates before
submission. Static PoC text is not an executed reproduction, and generated
impact language is not proof that credentials or a host were compromised.
Docker score/vector are nullable and the UI presents the unscored rationale.

## Ask AI

Ask AI is an optional on-demand assessment in the finding drawer. Only
**Ollama** is implemented; it is not required for deterministic scanning.

Local setup:

```powershell
ollama pull qwen3:1.7b
ollama serve
```

If Ollama is already serving, do not start a second server. The default URL is
`http://127.0.0.1:11434`; model and connection settings are configurable.

Ask AI uses saved GitHub tokens to fetch current workflow YAML, local reusable
workflow YAML dependencies, and relevant upstream workflow YAML. It sends
finding evidence plus that bounded, line-numbered context and deterministic
precheck information to the configured Ollama endpoint.

It does **not** send an unrestricted repository checkout or all helper scripts.
The legacy `include_support_files` request flag is deprecated. `max_files`
defaults to 20 and allows 1-50; per-file, total-byte, model-context, and output
limits can truncate evidence.

The response describes verdict, final severity, confidence, whether an attacker
can exploit, gates, severity-lowering factors, attacker model, preconditions,
path, ease/reliability, actual claimed impact, evidence references, and a
recommendation. It does not automatically set a manual verdict, rewrite the
finding, or constitute runtime validation.

The request supports `provider`, `model`, and `max_files`. Provider defaults
to `ollama` in the request model; only Ollama is supported. Provider values
`off`, `none`, or `disabled` are rejected as disabled when selected for the
request. Environment defaults do not override an explicit request provider.
If the endpoint is remote, workflow/evidence context is sent there; only use
an endpoint appropriate for the repository's confidentiality requirements.

## Experimental Live PoC and Jobs

### Availability and actual scope

Live PoC is **experimental / under construction**, separate from scanning.
Start it from a finding's Live PoC drawer tab. Jobs lists active and historical
PoC runs; it is not the organization scan queue.

**Mirrors are public in the current implementation.** They are created under
the maintainer identity and tagged `grafter-poc`. Never rely on old private-
mirror wording in UI tooltips or earlier documentation. Do not copy
confidential/private source into a public mirror.

Currently registered automated drivers:

| Category | Driver intent |
| --- | --- |
| `script-injection` | Marker execution from an untrusted expression |
| `checkout-untrusted` | Marker execution after PR-controlled checkout |
| `pr-controlled-dockerfile-build` | Dockerfile build marker and supported privilege signals |
| `pr-submodules-recursive` | Controlled recursive-submodule/canary observations |
| `workflow_run-privileged` | Marker in a privileged downstream workflow |
| `comment-command-pr-checkout` | Comment-command PR execution |
| `comment-trigger-write-scope` | Comment-triggered write/marker signals |

`GET /api/live-poc/drivers` is the authoritative runtime list. Agentic,
cache, release, Docker-socket, and other categories do not gain automated
drivers merely because they have static report PoC guidance.
Unsupported categories return an error; automated guided fallback is not
implemented.

### Credentials and setup

| Identity | Classic PAT scopes checked by preflight |
| --- | --- |
| Maintainer | `repo`, `workflow`, `delete_repo` |
| Attacker | `repo` |

Use separate identities to model the external-contributor boundary. Credentials
are saved through Live PoC controls and validated with GitHub identity calls;
preflight checks scopes and Git availability. Optional canary configuration
supports a token/value, kind, label, and history URL. The Forget action clears
Live PoC credentials.

LOW/INFO findings cannot start automated PoC runs. A second active run for the
same finding is rejected. An in-process lock serializes execution; additional
runs may be queued.

### Execution and options

The phase sequence is `queued`, `preflight`, `mirror`, `inject`, `trigger`,
`watch`, `verdict`, `cleanup`, then terminal `done`, `failed`, or `cancelled`.
The UI shows phase logs, elapsed time, repository/workflow links, observed
signals, claimed impact, and proven-impact tags.

The orchestrator prepares a public mirror, attempts to seed referenced secrets
with dummy canary values, asks a driver to prepare marker input, and triggers
the applicable PR/issue/comment workflow. Secret seeding requires the optional
`PyNaCl` package, which is not listed in the base backend requirements; without
it, seeding is skipped. Check the run's seeding logs rather than assuming
credentials were populated. A watcher inspects available workflow logs,
artifacts, comments, and configured canary history.

Mirror preparation supports a shallow/full mode for smaller repositories and
a minimal-relevant-files mode for larger repositories or explicit selection.
The full-clone threshold defaults to 1024 MB of GitHub-reported repository
size. File-count, per-file, and total minimal-mirror limits apply; a mirror is
not a byte-for-byte reconstruction of every original dependency or setting.

| Option | Current behavior |
| --- | --- |
| Force minimal mirror | Prefer relevant workflow/helper/manifest/evidence files |
| Keep repositories | Skip normal run cleanup for debugging; the age-based sweeper can still remove mirrors later |
| Real-repository mode | Present in the schema/UI, but all current driver previews advertise `supports_real_repo_mode: false`; not a supported current workflow |
| Cancel | Request task cancellation and cleanup |
| Delete run | Remove terminal history; not a substitute for checking GitHub cleanup |

Workflow discovery/completion watch loops have default 20-minute budgets.
These are **watch-loop budgets, not a single end-to-end hard deadline**
covering preflight, cloning, trigger preparation, watching, and cleanup.

### Verdicts and interpretation

| Verdict | Meaning |
| --- | --- |
| `confirmed` | The driver's configured success requirement was satisfied |
| `weak_repro` | Some relevant signal fired, but not the complete requirement |
| `not_reproduced` | Required signals were not observed under tested conditions |
| `blocked_by_gate` | Observations indicate a gate prevented reproduction |
| `inconclusive` | Insufficient observations, unavailable run, timeout, or ambiguity |
| `error` | Execution/preflight failed |

Interpret `confirmed` against the specific driver's signals and
`proven_impact`, not every impact suggested by the original static finding.
Mirror permissions, dummy secrets, dependency availability, approval settings,
and cloud identities may differ from the original repository. A build marker
alone does not prove host escape or production-secret theft.

### Cleanup and restart

Normal cleanup attempts to delete the mirror and attacker fork unless Keep is
selected. A background sweeper periodically deletes old repositories tagged
`grafter-poc` under the saved maintainer identity: default maximum age 24 hours,
interval 30 minutes. Cleanup is best-effort and requires usable credentials;
verify retained/orphaned repositories manually.

Unlike scan jobs, interrupted PoC runs are marked failed during backend
startup; they are not resumed at the prior phase.

## Persistence and data handling

| Data | Default location / behavior |
| --- | --- |
| Findings, scans, membership snapshots, queue/checkpoints, PoC runs/logs | `%USERPROFILE%\.grafter\findings.db` |
| Scan PAT pool and Live PoC credentials | `%USERPROFILE%\.grafter\tokens.json` |
| Browser rule selection | Local storage key `grafter.selected-rules.v1` |
| Login | Signed browser session cookie |
| POSIX equivalent data directory | `~/.grafter` |

Override the data directory with `GRAFTER_DATA_DIR`. SQLite uses WAL mode; for
backups, stop the backend or use a consistent SQLite backup method rather
than copying only the main file during active writes.

Saved tokens are **plain local JSON, not encrypted credential-vault entries**.
POSIX permissions are restricted on a best-effort basis; Windows access relies
on the profile/file ACLs. The token-preview API does not return full PATs.
Scan queue records persist options/quota information without raw PATs.
PoC credentials share the token file under a separate `live_poc` record.

Secret findings are designed to retain masked values/fingerprints rather than
raw discovered secret material. Other repository-derived snippets, evidence,
exports, logs, and AI context may still be sensitive; treat the data directory
and generated artifacts accordingly. Enabled credential validation contacts
the relevant provider with candidate credentials; it is not a regex-only scan.

Finding IDs are upserted across repeated observations, preserving review
metadata. Historical membership and severity/confidence snapshots are stored
separately. Live finding content is not immutable historical source evidence,
and ordinary URLs may resolve to mutable HEAD.

If present, data from the legacy `~/.pullRequestExploitr` directory can be
migrated by backend initialization. Normal local operation does not require
Azure deployment artifacts or training lab repositories.

## Configuration reference

Set environment variables in the process launching the backend. Restart after
changes. The application does not automatically load a `.env` file.

### Runtime and authentication

| Variable | Default | Purpose |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Backend bind address when running `main.py` |
| `PORT` | `8765` | Backend port when running `main.py` |
| `GRAFTER_STATIC_DIR` | `backend\static` | Built frontend directory, mounted when it exists |
| `GRAFTER_DATA_DIR` | User home `.grafter` | SQLite and token directory |
| `GRAFTER_ADMIN_USER` | `admin` | Administrator username |
| `GRAFTER_ADMIN_PASSWORD` | `password` | Administrator password |
| `GRAFTER_SESSION_SECRET` | Derived from credentials | Cookie signing key |
| `GRAFTER_SESSION_TTL_SECONDS` | `259200` | Session lifetime; minimum `259200` |
| `GRAFTER_COOKIE_SECURE` | Off | Set Secure cookie attribute with `1`, `true`, or `yes` |
| `GRAFTER_SECRET_LOG_RUN_LIMIT` | `10` | Recent runs checked for relevant log evidence; clamped 1-20 |
| `GRAFTER_QUEUE_MAX_ACTIVE_JOBS` | `1` | Concurrent scan jobs; minimum 1 |
| `GRAFTER_QUEUE_MAX_RETRIES` | `10` | Automatic quota-wait retry ceiling |

### Ask AI

| Variable | Default | Purpose |
| --- | --- | --- |
| `GRAFTER_AI_PROVIDER` | `ollama` | Provider fallback; request provider takes precedence |
| `GRAFTER_OLLAMA_URL` | `http://127.0.0.1:11434` | Ollama endpoint |
| `GRAFTER_AI_MODEL` | `qwen3:1.7b` | Model unless overridden per request |
| `GRAFTER_AI_TIMEOUT_SECONDS` | `180` | Ollama request timeout |
| `GRAFTER_AI_MAX_FILE_BYTES` | `12000` | Dependent-file context cap |
| `GRAFTER_AI_MAX_PRIMARY_FILE_BYTES` | `35000` | Primary workflow context cap |
| `GRAFTER_AI_MAX_TOTAL_BYTES` | `40000` | Total file-context cap |
| `GRAFTER_AI_NUM_CTX` | `4096` | Ollama context size |
| `GRAFTER_AI_NUM_PREDICT` | `520` | Ollama output-token budget |

### Live PoC

| Variable | Default | Purpose |
| --- | --- | --- |
| `GRAFTER_LIVE_POC_FULL_CLONE_MAX_MB` | `1024` | Repository-size threshold for full/shallow versus minimal mirror |
| `GRAFTER_LIVE_POC_MIRROR_MAX_MB` | `50` | Minimal-mirror total payload limit |
| `GRAFTER_LIVE_POC_MIRROR_MAX_FILE_MB` | `5` | Per-file mirror limit |
| `GRAFTER_LIVE_POC_MIRROR_MAX_FILES` | `200` | Minimal-mirror file-count limit |
| `GRAFTER_LIVE_POC_MIRROR_MAX_AGE_HOURS` | `24` | Age threshold for orphan mirror sweeping |
| `GRAFTER_LIVE_POC_SWEEP_INTERVAL_S` | `1800` | Sweeper interval |

## API reference

Except public auth/health endpoints, all `/api` operations require the signed
login cookie. Browser actions use the same routes. Request/response models are
available in Swagger and OpenAPI; unknown API routes return a JSON 404.

### Health and authentication

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Public liveness response; not a GitHub/Ollama/PoC readiness check |
| GET | `/api/auth/session` | Inspect current authentication |
| POST | `/api/auth/login` | JSON `username`, `password`; set session cookie |
| POST | `/api/auth/logout` | Clear session cookie |

### Token management

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/token` | Primary saved connection metadata |
| POST | `/api/token` | Validate/save JSON `token` |
| DELETE | `/api/token` | Delete shared token file, including scan pool and saved Live PoC credentials |
| GET | `/api/tokens` | Pool entries with login, preview, and saved time |
| POST | `/api/tokens` | Validate/add JSON `token` |
| DELETE | `/api/tokens/{login}` | Remove saved account entries |

### Scans and queue

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/scan` | Submit a ScanRequest |
| GET | `/api/scan/{scan_id}` | Live/restored scan status and telemetry |
| DELETE | `/api/scan/{scan_id}` | Delete scan findings/history/membership and associated queue row; cancel active work separately first |
| GET | `/api/scans` | Scan history; `limit` defaults to 200 |
| GET | `/api/scans/{scan_id}/diff` | Compare with `against=previous` or an explicit earlier scan ID |
| GET | `/api/scan-jobs` | Queue/history; optional `state`, `limit`, `offset`; limit defaults 200, maximum 500 |
| GET | `/api/scan-jobs/summary` | Counts by queue state |
| GET | `/api/scan-jobs/{job_id}` | Job details, checkpoints/counts, activity, errors, and quota |
| POST | `/api/scan-jobs/{job_id}/cancel` | Request cancellation |
| POST | `/api/scan-jobs/{job_id}/retry` | Retry failed/cancelled work with existing scan identity |
| POST | `/api/scan-jobs/{job_id}/move` | JSON `direction`: `up` or `down`; pending only |
| DELETE | `/api/scan-jobs/{job_id}` | Delete terminal queue history |
| GET | `/api/rules` | Selectable category registry; excludes operational parse-error categories |

### Findings, review, and reports

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/findings` | Paginated compact list; `page`, `page_size`, `repo`, `severity`, `exploitability`, `scan_id`, `category`, `q`, `sort`, `state` |
| GET | `/api/findings/counts` | Severity totals; optional scan/lifecycle |
| GET | `/api/findings/categories` | Category counts/labels; optional scan/lifecycle |
| GET | `/api/findings/trend` | Daily totals/review labels; `days` defaults 30, optional scan |
| GET | `/api/findings/export` | `format=sarif|json|triage`, export filters, optional `limit` |
| GET | `/api/findings/export-reviewed` | Reviewed dataset; `format=json|csv` |
| GET | `/api/findings/{finding_id}` | Full finding |
| DELETE | `/api/findings/{finding_id}` | Delete one finding |
| DELETE | `/api/findings` | Delete all findings, or those for optional `scan_id`; other list filters are not accepted |
| PATCH | `/api/findings/{finding_id}/manual-verdict` | JSON `manual_verdict`, including null |
| PATCH | `/api/findings/manual-verdict/bulk` | JSON `finding_ids`, `manual_verdict` |
| POST | `/api/findings/bulk-delete` | JSON `finding_ids` |
| GET | `/api/findings/{finding_id}/bug-bounty` | Structured report and Markdown; nullable CVSS |
| GET | `/api/findings/{finding_id}/sarif` | Single-finding SARIF |
| POST | `/api/findings/{finding_id}/recheck` | Recheck current workflow |
| POST | `/api/findings/recheck/bulk` | JSON `finding_ids`; 1-200 IDs |
| POST | `/api/findings/{finding_id}/ask-ai` | JSON `provider`, optional `model`, `max_files`; deprecated support-file flag |

### Live PoC

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/live-poc/tokens` | Saved maintainer/attacker/canary metadata |
| POST | `/api/live-poc/tokens` | Optional `maintainer_token`, `attacker_token`, `canary_token`, `canary_kind`, `canary_label`, `canary_history_url` |
| DELETE | `/api/live-poc/tokens` | Forget Live PoC credentials |
| GET | `/api/live-poc/drivers` | Registered automated categories |
| GET | `/api/findings/{finding_id}/live-poc/preview` | Claim, impact tags, signals/success criteria, payload summary, mode support |
| POST | `/api/findings/{finding_id}/live-poc` | Start; JSON `keep_repos`, `force_minimal_mirror`, `use_real_repo` (currently unsupported by registered drivers) |
| GET | `/api/live-poc/runs` | List; `state=all|active|terminal`, optional `finding_id`, `limit`, `offset` |
| GET | `/api/live-poc/runs/summary` | Active, recent-terminal, and stuck counts |
| GET | `/api/live-poc/runs/{run_id}` | Full run, logs, evidence, error, and proven impact |
| POST | `/api/live-poc/runs/{run_id}/cancel` | Request cancellation |
| DELETE | `/api/live-poc/runs/{run_id}` | Delete terminal run history |
| GET | `/api/findings/{finding_id}/live-poc/runs` | Per-finding run history |

### Authenticated PowerShell example

Use the configured credentials; these are the local defaults. The example
assumes a scan PAT is already saved through the UI and never embeds a PAT in
source or the request example.

```powershell
$base = "http://127.0.0.1:8765"
$login = @{ username = "admin"; password = "password" } | ConvertTo-Json
Invoke-RestMethod "$base/api/auth/login" -Method Post `
  -ContentType "application/json" -Body $login -SessionVariable grafterSession

$body = @{
  org = "octocat"
  max_repos = 20
  selected_rules = @("script-injection", "cache-poisoning")
} | ConvertTo-Json
$scan = Invoke-RestMethod "$base/api/scan" -Method Post `
  -WebSession $grafterSession -ContentType "application/json" -Body $body

# Repeat as needed; the initial POST does not wait for scan completion.
Invoke-RestMethod "$base/api/scan/$($scan.id)" -WebSession $grafterSession

# Export after the desired scan has completed; narrow by its ID.
Invoke-WebRequest "$base/api/findings/export?format=sarif&scan_id=$($scan.id)" `
  -WebSession $grafterSession -OutFile .\grafter.sarif
```

## Development and checks

### Project layout

```text
backend\
  main.py                    API, scanner, persistence, auth, reports, scheduler
  requirements.txt           Backend dependencies
  _smoke*.py                 Targeted regression scripts
  poc\                       Experimental PoC models, drivers, mirror, watcher
  static\                    Backend-served frontend assets when provided
frontend\
  src\
    App.tsx                  Scan setup, auth, findings, Rules, Diff, drawer
    QueueView.tsx            Organization/user queue
    GitHubQuota.tsx           Shared pool and active-token display
    LivePocView.tsx           Per-finding PoC setup/details
    JobsView.tsx              PoC job history
    redaction.ts             Display identity redaction
    styles.css               UI styling
  _smoke_queue.mjs            Queue rendering checks
  package.json               Frontend scripts
  vite.config.ts             Development proxy
startup.ps1                  Windows launcher
README.md                    Quick start and feature summary
DOCUMENTATION.md             Full reference
```

### Existing regression commands

From the repository root, use an isolated data directory for backend checks
rather than the live dashboard database. For example, set `GRAFTER_DATA_DIR`
to a dedicated temporary test directory before running a chosen script.

| Command | Coverage |
| --- | --- |
| `.\backend\.venv\Scripts\python.exe .\backend\_smoke.py` | Shared analyzer, reporting/export, persistence, search, diff, and API regressions |
| `.\backend\.venv\Scripts\python.exe .\backend\_smoke_new_rules.py` | Additional workflow rules and gates |
| `.\backend\.venv\Scripts\python.exe .\backend\_smoke_wiz_rules.py` | Additional real-world rule regression cases |
| `.\backend\.venv\Scripts\python.exe .\backend\_smoke_docker_rule.py` | Docker context/authority/gate false-positive regressions |
| `.\backend\.venv\Scripts\python.exe .\backend\_smoke_auth.py` | Credentials, overrides, and session policy |
| `.\backend\.venv\Scripts\python.exe .\backend\_smoke_queue.py` | Queue, persistence/retry, cancellation, telemetry, transport handling |
| `.\backend\.venv\Scripts\python.exe .\backend\_smoke_token_rotation.py` | Rotation headers, concurrent response attribution, account pooling/reset behavior |
| `node .\frontend\_smoke_queue.mjs` | Queue UI rendering |
| `npx tsc --noEmit` (from `frontend`) | TypeScript checking |
| `npm --prefix frontend run build` | Vite frontend build |

For TypeScript checking, run `npx tsc --noEmit` from `frontend` so it uses
`frontend\tsconfig.json`. No dedicated npm lint script is defined.

## Troubleshooting

| Symptom | Check / explanation |
| --- | --- |
| Cannot log in | Default is `admin` / `password`; inspect backend credential overrides and restart after changes |
| Logged out after changing configuration | Derived signing key/username changed, or cookie expired; log in again |
| Login succeeds but cookie is not retained on local HTTP | Secure-cookie mode requires HTTPS; check cookie settings and host consistency |
| Frontend cannot reach backend | Check `/api/health`, port 8765, and Vite proxy target |
| Old UI or unknown API endpoint after an update | Restart backend/Vite as appropriate; rebuild assets when serving static output |
| Missing Python modules | Install `backend\requirements.txt` using the intended virtual environment |
| Missing frontend packages | Run `npm install` in `frontend` |
| Adding a valid PAT fails with proxy/connection errors or a generic server error | Check inherited proxy settings and restart the backend after correction; see [Adding a PAT and proxy errors](#adding-a-pat-and-proxy-errors) |
| Owner not found | Use an organization/user login, verify spelling/access; API may suggest close login matches |
| Few/no repositories | Check PAT scopes, SSO, private access, archived/fork filtering, and repository limit |
| Pool starts near 5000/10000 | One independent account may have little quota left; inspect account breakdown and partial probes |
| Same-account tokens do not increase total | Account-based GitHub quota is shared |
| Job is waiting despite a valid PAT | Valid authentication is not available quota; inspect reset, compatible repository access, and saved pool |
| Findings stop increasing | Work may be downloading/analyzing/validating or deduplicating; check activity, pending/in-flight, last response, and errors |
| Repositories fail with DNS/timeouts | Fix network/proxy/DNS reachability; bounded retries already occur, then Retry the job |
| Saved-finding total differs from list | Confidence/lifecycle/rule/scan/search filters and stable identities affect presentation |
| Low-confidence/blocked filter shows nothing | Filters cannot bypass backend suppression/visibility thresholds |
| Retry repeats downloads | Checkpoints are per repository, not per file |
| Old Docker findings remain | Code updates do not purge stored results; recheck/rescan, then inspect archive state |
| Recheck says fixed but context is complex | Recheck is narrower than full scanning; rescan with peer/helpers/policy/provider context |
| Ask AI is unavailable | Save a PAT, start Ollama, pull the model, check URL/model/timeouts and bounded context |
| Secret validation yields no findings | Check `curl` availability, candidate limits, provider reachability, and validation status; raw regex matches are suppressed |
| No Live PoC driver | Only seven registered categories support automation; static report guidance is not a driver |
| Live PoC fails before trigger | Check both PATs/scopes, Git, mirror creation, Actions policy, and detailed preflight logs |
| PoC cannot reproduce original impact | Mirrors differ in credentials, permissions, dependencies, cloud identity, and approvals |
| PoC repositories remain | Inspect cleanup logs and GitHub; deleted/expired PATs and Keep options can prevent cleanup |

## Scope and limitations

Grafter prioritizes investigation; it is not an exploitability oracle or a
complete GitHub Actions interpreter. Keep these distinctions when presenting
or using results:

| Distinction | Practical consequence |
| --- | --- |
| Static evidence versus runtime proof | A source/sink heuristic, graph, report, or CVSS estimate does not prove execution or impact |
| Configuration versus effective policy | Environment reviewers, cloud federation, branch protection, runner isolation, and organization defaults may need manual verification |
| Current branch versus immutable revision | Normal scanning/recheck is not pinned historical execution reconstruction |
| Bounded discovery versus exhaustive audit | Helper, file, log, credential, export, and AI-context limits can omit evidence |
| Hosted fork CI versus privileged automation | Normal contributor execution is expected; credential/host/publish claims require a real additional boundary |
| Rule filtering versus reduced API work | Selecting fewer rules does not disable every discovery/validation phase |
| Durable retry versus exact continuation | Completed repositories are skipped; interrupted ones restart from the beginning |
| Stored finding versus current truth | Use recheck/rescan and manual review; old records are not silently rewritten on upgrades |
| Scan diff versus verified remediation | Absence can reflect changed coverage/context, not only a fixed vulnerability |
| AI advice versus authority | Optional model output does not replace full-context review or automatically authorize actions |
| Mirror signal versus original impact | Experimental public-mirror reproduction proves only the observed driver requirement under mirror conditions |

Use the full evidence and exact attacker starting position when deciding
severity or preparing a disclosure. Do not present every catalog entry,
conditional result, or generic reproduction draft as a confirmed compromise.
