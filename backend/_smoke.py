import asyncio
import sys
sys.path.insert(0, ".")
from main import (
    AskAIResponse,
    _ask_ai_precheck,
    _classify_if_expression,
    _compute_cvss,
    _credential_shaped_log_value,
    _extract_json_object,
    _extract_secret_candidates,
    _fix_yaml_diff,
    _job_needs_chain_gates,
    _job_step_gates,
    _merge_precheck_into_ask_ai_response,
    _filter_findings_for_rules,
    _normalize_selected_rules,
    _parse_workflow_summary,
    _redact_ai_context,
    _references_for,
    _revocation_url_for,
    _safe_two_stage_workflow_run_gates,
    _sarif_baseline_state,
    _sarif_level_for,
    _is_secretish_env_name,
    _secret_echo_log_evidence,
    _validate_secret_echo_findings_from_history,
    _workflow_trigger_gates,
    SELECTABLE_RULE_CATEGORIES,
    analyze_workflow,
    build_bug_bounty_report,
    build_sarif,
)

assert len(SELECTABLE_RULE_CATEGORIES) >= 50
assert _normalize_selected_rules(None) is None
assert _normalize_selected_rules(["script-injection", "cache-poisoning", "script-injection"]) == [
    category
    for category in SELECTABLE_RULE_CATEGORIES
    if category in {"script-injection", "cache-poisoning"}
]
for invalid_selection in ([], ["not-a-real-rule"]):
    try:
        _normalize_selected_rules(invalid_selection)
        raise AssertionError(f"selection should be rejected: {invalid_selection}")
    except ValueError:
        pass

scope_source = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/scope.yml",
    """name: scope
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
""",
)
scope_filtered = _filter_findings_for_rules(scope_source, ["script-injection"])
assert scope_filtered
assert {finding.category for finding in scope_filtered} == {"script-injection"}
parse_filtered = _filter_findings_for_rules(
    analyze_workflow(
        "acme/test",
        "https://github.com/acme/test",
        ".github/workflows/broken.yml",
        "name: [broken",
    ),
    ["script-injection"],
)
assert {finding.category for finding in parse_filtered} == {"workflow-parse-error"}
print("rule selection: normalization, filtering, and operational parse retention: ok")

wf = """name: ci
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci
      - run: npm test
      - uses: actions/github-script@v7
        with:
          script: console.log('${{ github.event.pull_request.title }}')
"""

fs = analyze_workflow("acme/test", "https://github.com/acme/test", ".github/workflows/ci.yml", wf)
print(f"findings: {len(fs)}")
for f in fs:
    print(f" - [{f.severity}/{f.exploitability} {f.confidence}%] {f.title}")

# Hardened variant should be downgraded:
wf2 = """name: ci
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    environment: pr-review
    if: github.event.pull_request.author_association == 'MEMBER'
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci
"""
fs2 = analyze_workflow("acme/test", "https://github.com/acme/test", ".github/workflows/ok.yml", wf2)
print("hardened findings:")
for f in fs2:
    print(f" - [{f.severity}/{f.exploitability} {f.confidence}%] {f.title}")


def categories(findings):
    return {f.category for f in findings}


feast_label_persistence_wf = """name: pr-integration
on:
  pull_request_target:
    types:
      - opened
      - synchronize
      - labeled
jobs:
  integration-test-python:
    if: ((github.event.action == 'labeled' && (github.event.label.name == 'approved' || github.event.label.name == 'lgtm' || github.event.label.name == 'ok-to-test')) || (github.event.action != 'labeled' && (contains(github.event.pull_request.labels.*.name, 'ok-to-test') || contains(github.event.pull_request.labels.*.name, 'approved') || contains(github.event.pull_request.labels.*.name, 'lgtm'))))
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
          persist-credentials: false
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
      - run: make install-python-dependencies-ci
      - run: make test-python-integration
        env:
          SNOWFLAKE_CI_PASSWORD: ${{ secrets.SNOWFLAKE_CI_PASSWORD }}
"""
feast_label_persistence_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/pr_integration_tests.yml",
    feast_label_persistence_wf,
    [_parse_workflow_summary(".github/workflows/pr_integration_tests.yml", feast_label_persistence_wf)],
)
assert "pull-request-target-label-persistence" in categories(feast_label_persistence_findings)
label_persistence_finding = next(f for f in feast_label_persistence_findings if f.category == "pull-request-target-label-persistence")
assert label_persistence_finding.severity == "CRITICAL"
assert label_persistence_finding.confidence >= 90
# The workflow also checks out `refs/pull/<num>/merge` via a floating
# `actions/checkout@v4` tag, which is an independently-exploitable untrusted
# checkout primitive (floating tags can be repointed, and the ref itself
# resolves to PR-controlled content). The scanner intentionally reports both
# `pull-request-target-label-persistence` and `checkout-untrusted` for this
# job rather than suppressing either — duplicate-but-accurate reporting is
# preferred over a suppression rule that could cause a false negative.
assert any(f.category == "checkout-untrusted" for f in feast_label_persistence_findings), (
    "feast: checkout-untrusted should still fire alongside pull-request-target-label-persistence "
    "for the untrusted refs/pull/<num>/merge checkout"
)
print("pull_request_target synchronize label persistence bypass: ok")


visibility_wf = """name: visibility
on:
  schedule:
    - cron: '0 0 * * *'
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: thirdparty/deploy-action@main
      - uses: azure/login@v2
"""
visibility_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/visibility.yml",
    visibility_wf,
)
assert "excessive-token-permissions" not in categories(visibility_findings)
assert "mutable-action-reference" in categories(visibility_findings)
assert "oidc-cloud-credential-visibility" in categories(visibility_findings)
assert any(f.severity == "MEDIUM" for f in visibility_findings)
print("medium/low visibility findings: ok")


low_pr_wf = """name: pr-ci
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test
"""
low_pr_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/pr-ci.yml",
    low_pr_wf,
)
assert "permissions-not-pinned" in categories(low_pr_findings)
assert "pull-request-ci-code-execution" in categories(low_pr_findings)
assert any(f.severity == "LOW" for f in low_pr_findings)
print("low PR CI visibility findings: ok")


pr_azure_auth = """name: pr-azure-auth
on: pull_request
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      - run: bash scripts/deploy-check.sh
"""
pr_azure_auth_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/pr-azure-auth.yml",
    pr_azure_auth,
)
# GitHub blanks `secrets.*` for fork PRs on `pull_request`, so `azure/login`
# fails at step 2 and the chain collapses. No defeat present → must NOT fire.
assert "pull-request-authenticated-code-execution" not in categories(pr_azure_auth_findings), (
    "plain pull_request + secret-based cloud auth is defended by fork-PR "
    "secret blanking; the rule must suppress this shape"
)
print("pull_request secret-based cloud auth (fork-PR-defended): suppressed as expected: ok")


pr_azure_auth_env = """name: pr-azure-auth-env
on: pull_request
jobs:
  validate:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      - run: bash scripts/deploy-check.sh
"""
pr_azure_auth_env_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/pr-azure-auth-env.yml",
    pr_azure_auth_env,
)
assert "pull-request-authenticated-code-execution" in categories(pr_azure_auth_env_findings), (
    "environment: is a documented defence-defeat (approved runs receive env "
    "secrets) — the rule must still fire, just downgraded via the gated path"
)
env_finding = next(
    f for f in pr_azure_auth_env_findings
    if f.category == "pull-request-authenticated-code-execution"
)
assert env_finding.severity == "LOW", f"env-gated finding must be LOW, got {env_finding.severity}"
assert "environment" in " ".join(env_finding.evidence).lower()
print("pull_request secret cloud auth with `environment:` defeat: fires LOW (gated): ok")


pr_aws_oidc = """name: pr-aws-oidc
on: pull_request
jobs:
  plan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/ci
          aws-region: us-east-1
      - run: make deploy-plan
"""
pr_aws_oidc_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/pr-aws-oidc.yml",
    pr_aws_oidc,
)
# `id-token` is part of the GITHUB_TOKEN permission namespace. On a
# fork-authored `pull_request` run the platform downgrades the whole
# GITHUB_TOKEN scope set to read-only, so `ACTIONS_ID_TOKEN_REQUEST_URL`
# is never populated and `aws-actions/configure-aws-credentials` fails at
# the AssumeRoleWithWebIdentity step. The chain collapses at step 2, so
# the rule must NOT fire — this is the exact false-positive class the
# hardening exists to eliminate.
assert "pull-request-authenticated-code-execution" not in categories(pr_aws_oidc_findings), (
    "plain pull_request + OIDC cloud auth is defended by fork-PR GITHUB_TOKEN "
    "read-only downgrade — the rule must suppress this shape"
)
# `oidc-cloud-credential-visibility` must also stay silent: same axiom
# renders the visibility hint meaningless on fork `pull_request`.
assert "oidc-cloud-credential-visibility" not in categories(pr_aws_oidc_findings), (
    "oidc-cloud-credential-visibility must NOT fire on plain pull_request — "
    "OIDC endpoint is not populated on fork PR"
)
print("pull_request OIDC cloud auth (fork-PR-defended by id-token downgrade): suppressed as expected: ok")


# Same shape but on `pull_request_target` — OIDC IS reachable there, and
# the OIDC visibility signal is meaningful for org owners.
prt_aws_oidc = """name: prt-aws-oidc
on: pull_request_target
jobs:
  plan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/ci
          aws-region: us-east-1
      - run: make deploy-plan
"""
prt_aws_oidc_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/prt-aws-oidc.yml",
    prt_aws_oidc,
)
assert "oidc-cloud-credential-visibility" in categories(prt_aws_oidc_findings), (
    "pull_request_target IS secret-bearing — OIDC visibility signal must still fire there"
)
print("pull_request_target OIDC cloud auth: visibility fires (correct): ok")


pr_registry_auth = """name: pr-registry-auth
on: pull_request
jobs:
  image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USER }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
      - run: python scripts/build_image.py
"""
pr_registry_auth_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/pr-registry-auth.yml",
    pr_registry_auth,
)
# Same defended shape — `secrets.DOCKERHUB_*` blanked on fork PR, `docker
# login` fails, chain collapses. Must not fire.
assert "pull-request-authenticated-code-execution" not in categories(pr_registry_auth_findings), (
    "plain pull_request + secret-based docker login is defended by fork-PR "
    "secret blanking; the rule must suppress this shape"
)
print("pull_request registry secret auth (fork-PR-defended): suppressed as expected: ok")


pr_registry_auth_selfhosted = """name: pr-registry-selfhosted
on: pull_request
jobs:
  image:
    runs-on: [self-hosted, linux, x64]
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USER }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
      - run: python scripts/build_image.py
"""
pr_registry_auth_selfhosted_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/pr-registry-selfhosted.yml",
    pr_registry_auth_selfhosted,
)
assert "pull-request-authenticated-code-execution" not in categories(pr_registry_auth_selfhosted_findings), (
    "self-hosted execution does not make blank fork secrets available or make "
    "the login succeed; the authenticated-session rule must remain suppressed"
)
print("pull_request registry auth on self-hosted: auth rule suppressed as expected: ok")


secret_log_candidate_wf = """name: secret-log-candidate
on: push
jobs:
  debug:
    runs-on: ubuntu-latest
    steps:
      - run: echo "API_TOKEN=${{ secrets.API_TOKEN }}"
"""
secret_log_candidates = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/secret-log.yml",
    secret_log_candidate_wf,
)
secret_log_candidate = next(
    f for f in secret_log_candidates if f.category == "secret-echoed-to-log"
)
assert secret_log_candidate.tainted_expression == "API_TOKEN"
assert _is_secretish_env_name("API_TOKEN")
assert not _is_secretish_env_name("HAS_PATCH")
assert not _is_secretish_env_name("GH_AW_MODELS_JSON_PATH")
assert not _is_secretish_env_name("CODEQL_ACTION_ANALYSIS_KEY")
assert not _is_secretish_env_name("GH_AW_RESTORE_DAILY_AIC_CACHE_MATCHED_KEY")
assert _is_secretish_env_name("SSH_KEY")
assert _credential_shaped_log_value("github_pat_" + "A1b2C3d4E5f6" * 5)
assert _credential_shaped_log_value("sk-proj-" + "A1b2C3d4E5f6" * 4)
assert _credential_shaped_log_value("AKIAIOSFODNN7EXAMPLE")
assert not _credential_shaped_log_value("/tmp/models.json")
assert not _credential_shaped_log_value("token validation was skipped")

masked_log = """2026-09-30T10:00:00Z Run echo "API_TOKEN=***"
2026-09-30T10:00:01Z API_TOKEN=***
"""
assert not _secret_echo_log_evidence(masked_log, ["API_TOKEN"])

raw_secret_for_test = "test_only_token_ABC123456789"
reflected_log = (
    '2026-09-30T10:00:00Z Run echo "API_TOKEN=' + raw_secret_for_test + '"\n'
    "2026-09-30T10:00:01Z API_TOKEN=" + raw_secret_for_test + "\n"
)
reflected_evidence = _secret_echo_log_evidence(reflected_log, ["API_TOKEN"])
assert reflected_evidence
assert all(raw_secret_for_test not in line for line in reflected_evidence)
assert any("length=" in line and "sha256=" in line for line in reflected_evidence)

transformed_secret_for_test = "QWxhZGRpbjpPcGVuU2VzYW1lMTIzNA=="
transformed_log = (
    '2026-09-30T10:00:00Z Run echo "***" | base64\n'
    "2026-09-30T10:00:01Z " + transformed_secret_for_test + "\n"
)
transformed_evidence = _secret_echo_log_evidence(
    transformed_log,
    ["API_TOKEN"],
    'echo "${{ secrets.API_TOKEN }}" | base64',
)
assert transformed_evidence
assert all(transformed_secret_for_test not in line for line in transformed_evidence)
assert not _secret_echo_log_evidence(
    "2026-09-30T10:00:01Z GH_AW_MODELS_JSON_PATH=/tmp/models.json\n",
    ["GH_AW_MODELS_JSON_PATH"],
)
assert not _secret_echo_log_evidence(
    "2026-09-30T10:00:01Z OAUTH_TOKEN_CHECK_FAILED=token validation was skipped\n",
    ["OAUTH_TOKEN_CHECK_FAILED"],
)
assert _secret_echo_log_evidence(
    "2026-09-30T10:00:01Z BUILD_KEY=test_only_secret_A1b2C3d4E5f6\n",
    ["BUILD_KEY"],
)

ordinary_powershell_env_wf = """name: ordinary-powershell-env
on: push
jobs:
  build:
    runs-on: windows-latest
    steps:
      - run: dotnet restore "$env:solution"
      - run: '& $env:windir\\system32\\inetsrv\\appcmd.exe list site'
"""
ordinary_powershell_env_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/ordinary-powershell-env.yml",
    ordinary_powershell_env_wf,
)
assert "secret-echoed-to-log" not in categories(ordinary_powershell_env_findings)


class _FakeSecretLogGitHub:
    def __init__(self, log_text):
        self.log_text = log_text

    async def list_recent_workflow_runs(self, owner, repo, workflow_path, limit=5):
        return [{
            "id": 12345,
            "html_url": "https://github.com/acme/test/actions/runs/12345",
            "created_at": "2026-09-30T10:00:00Z",
        }]

    async def fetch_run_logs(self, owner, repo, run_id):
        return self.log_text


validated_secret_logs = asyncio.run(
    _validate_secret_echo_findings_from_history(
        _FakeSecretLogGitHub(reflected_log),
        "acme",
        "test",
        ".github/workflows/secret-log.yml",
        [secret_log_candidate.model_copy(deep=True)],
    )
)
assert len(validated_secret_logs) == 1
validated_secret_log = validated_secret_logs[0]
assert validated_secret_log.confidence == 96
assert any("actions/runs/12345" in line for line in validated_secret_log.evidence)
assert all(raw_secret_for_test not in line for line in validated_secret_log.evidence)

suppressed_masked_secret_logs = asyncio.run(
    _validate_secret_echo_findings_from_history(
        _FakeSecretLogGitHub(masked_log),
        "acme",
        "test",
        ".github/workflows/secret-log.yml",
        [secret_log_candidate.model_copy(deep=True)],
    )
)
assert not suppressed_masked_secret_logs

suppressed_missing_secret_logs = asyncio.run(
    _validate_secret_echo_findings_from_history(
        _FakeSecretLogGitHub(""),
        "acme",
        "test",
        ".github/workflows/secret-log.yml",
        [secret_log_candidate.model_copy(deep=True)],
    )
)
assert not suppressed_missing_secret_logs
print("secret echoed to log: masked/unavailable suppressed; reflected value safely fingerprinted: ok")


def _cache_mode_workflow(workflow_mode="", job_mode="", cache_action="actions/cache@v4"):
    workflow_line = f"cache-mode: {workflow_mode}\n" if workflow_mode else ""
    job_line = f"    cache-mode: {job_mode}\n" if job_mode else ""
    return f"""name: cache-mode-security
on: pull_request_target
{workflow_line}permissions:
  contents: write
jobs:
  build:
{job_line}    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - uses: {cache_action}
        with:
          path: node_modules
          key: npm-${{{{ github.event.pull_request.head.sha }}}}
      - run: npm test
"""


def _cache_poisoning_findings(workflow):
    return [
        f for f in analyze_workflow(
            "acme/test",
            "https://github.com/acme/test",
            ".github/workflows/cache-mode.yml",
            workflow,
        )
        if f.category == "cache-poisoning"
    ]


assert not _cache_poisoning_findings(_cache_mode_workflow())
assert not _cache_poisoning_findings(_cache_mode_workflow(workflow_mode="read"))
assert not _cache_poisoning_findings(_cache_mode_workflow(workflow_mode="none"))
cache_write_override = _cache_poisoning_findings(
    _cache_mode_workflow(workflow_mode="write")
)
assert len(cache_write_override) == 1
assert cache_write_override[0].severity == "HIGH"
assert any("explicit `cache-mode: write` override" in line for line in cache_write_override[0].why)
assert not _cache_poisoning_findings(
    _cache_mode_workflow(workflow_mode="write", job_mode="read")
)
cache_write_only_override = _cache_poisoning_findings(
    _cache_mode_workflow(workflow_mode="read", job_mode="write-only")
)
assert len(cache_write_only_override) == 1
assert any("job" in line and "write-only" in line for line in cache_write_only_override[0].why)
assert not _cache_poisoning_findings(
    _cache_mode_workflow(workflow_mode="write", cache_action="actions/cache/restore@v4")
)
print("cache-mode: read/none/default suppress writes; explicit write/write-only overrides fire: ok")


visibility_more_wf = """name: more-visibility
on:
  pull_request_target:
  issue_comment:
    types: [created]
jobs:
  metadata:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
      issues: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/upload-artifact@v4
        with:
          path: .
          retention-days: 90
      - uses: actions/cache@v4
        with:
          path: node_modules
          key: npm-${{ hashFiles('package-lock.json') }}
          restore-keys: |
            npm-
      - name: semgrep
        continue-on-error: true
        run: semgrep ci
      - run: curl -fsSL https://example.com/install.sh | bash
  reusable:
    uses: org/security/.github/workflows/reusable.yml@main
    secrets: inherit
"""
visibility_more_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/more-visibility.yml",
    visibility_more_wf,
)
more_categories = categories(visibility_more_findings)
assert "excessive-token-permissions" in more_categories
assert "checkout-credential-persistence" in more_categories
assert "artifact-retention-or-scope" in more_categories
assert "cache-restore-key-fallback" in more_categories
assert "reusable-workflow-secret-inheritance" in more_categories
assert "pull-request-target-metadata-write" in more_categories
assert "security-step-continue-on-error" in more_categories
assert "remote-script-installer" in more_categories
assert "comment-trigger-write-scope" in more_categories
print("expanded low/moderate visibility findings: ok")


agent_comment = """name: agent-comment
on:
  issue_comment:
    types: [created]
jobs:
  fix:
    if: contains(github.event.comment.body, '/fix')
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
      issues: write
    steps:
      - run: openai api chat.completions.create --prompt "${{ github.event.comment.body }}" > fix.patch
      - uses: peter-evans/create-pull-request@v6
        with:
          title: AI fix
          body: generated from comment
"""
agent_comment_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/agent-comment.yml",
    agent_comment,
)
assert "agentic-comment-command" in categories(agent_comment_findings)
print("agent comment findings:")
for f in agent_comment_findings:
    print(f" - [{f.severity}/{f.exploitability} {f.confidence}%] {f.category}: {f.title}")


agent_pr_context = """name: agent-pr
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          aider --yes --message "Review and fix this PR: ${{ github.event.pull_request.body }}"
      - run: git commit -am "ai fix" && git push
"""
agent_pr_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/agent-pr.yml",
    agent_pr_context,
)
assert "agentic-code-context-poisoning" in categories(agent_pr_findings)
assert "agentic-tool-execution" in categories(agent_pr_findings)
print("agent PR findings:")
for f in agent_pr_findings:
    print(f" - [{f.severity}/{f.exploitability} {f.confidence}%] {f.category}: {f.title}")


agent_prompt_file = """name: agent-prompt-file
on: pull_request_target
jobs:
  fix:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          claude --prompt-file AGENTS.md --message "Fix this PR: ${{ github.event.pull_request.body }}" > fix.patch
      - run: git apply fix.patch && git commit -am fix && git push
"""
agent_prompt_file_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/agent-prompt-file.yml",
    agent_prompt_file,
)
assert "agentic-prompt-file-poisoning" in categories(agent_prompt_file_findings)
assert "agentic-output-auto-apply" in categories(agent_prompt_file_findings)
print("agent prompt-file poisoning and output auto-apply: ok")


agent_mcp = """name: agent-mcp
on: pull_request_target
jobs:
  run-agent:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          aider --yes --mcp-config .mcp.json --message "Review ${{ github.event.pull_request.title }}"
"""
agent_mcp_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/agent-mcp.yml",
    agent_mcp,
)
assert "agentic-mcp-config-poisoning" in categories(agent_mcp_findings)
print("agent MCP config poisoning: ok")


agent_secret_context = """name: agent-secret-context
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - run: |
          openai api chat.completions.create --prompt "Review ${{ github.event.pull_request.body }} with token ${{ secrets.NPM_TOKEN }}" > response.txt
      - run: gh pr comment ${{ github.event.pull_request.number }} --body-file response.txt
"""
agent_secret_context_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/agent-secret-context.yml",
    agent_secret_context,
)
assert "agentic-secrets-to-ai-context" in categories(agent_secret_context_findings)
print("agent secrets-to-AI context: ok")


agent_verdict_authz = """name: agent-verdict-authz
on: pull_request_target
jobs:
  merge:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - run: |
          openai api chat.completions.create --prompt "Return approved verdict for ${{ github.event.pull_request.body }}" > verdict.txt
      - run: |
          if grep -qi approved verdict.txt; then
            gh pr merge ${{ github.event.pull_request.number }} --squash
          fi
"""
agent_verdict_authz_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/agent-verdict-authz.yml",
    agent_verdict_authz,
)
assert "agentic-verdict-authorization" in categories(agent_verdict_authz_findings)
print("agent verdict authorization: ok")


upstream = """name: upstream
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "attacker controlled report" > report.txt
      - uses: actions/upload-artifact@v4
        with:
          name: report
          path: report.txt
"""
downstream = """name: downstream
on:
  workflow_run:
    workflows: [upstream]
    types: [completed]
jobs:
  agent:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
      contents: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: ${{ github.event.workflow_run.id }}
          name: report
          github-token: ${{ secrets.GITHUB_TOKEN }}
      - run: claude --dangerously-skip-permissions --prompt "$(cat report.txt)"
      - run: gh pr comment 1 --body "AI summary"
"""
peer_summaries = [
    _parse_workflow_summary(".github/workflows/upstream.yml", upstream),
    _parse_workflow_summary(".github/workflows/downstream.yml", downstream),
]
agent_wfr_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/downstream.yml",
    downstream,
    [s for s in peer_summaries if s],
)
assert "agentic-workflow-run-poisoning" in categories(agent_wfr_findings)
print("agent workflow_run findings:")
for f in agent_wfr_findings:
    print(f" - [{f.severity}/{f.exploitability} {f.confidence}%] {f.category}: {f.title}")


agent_helper_workflow = """name: helper-agent
on: issue_comment
jobs:
  fix:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - run: python scripts/agent_fix.py "${{ github.event.comment.body }}"
"""
agent_helper_support = {
    "scripts/agent_fix.py": """
import os
from openai import OpenAI
event_path = os.environ.get("GITHUB_EVENT_PATH")
prompt = open(event_path).read()
client = OpenAI()
answer = client.chat.completions.create(messages=[{"role": "user", "content": prompt}])
os.system("gh pr create --title 'AI fix' --body 'generated'")
"""
}
agent_helper_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/helper-agent.yml",
    agent_helper_workflow,
    support_files=agent_helper_support,
)
assert "agentic-comment-command" in categories(agent_helper_findings)
print("agent helper-script findings:")
for f in agent_helper_findings:
    print(f" - [{f.severity}/{f.exploitability} {f.confidence}%] {f.category}: {f.title}")


dispatch_source = """name: comment-dispatch
on: issue_comment
jobs:
  dispatch:
    runs-on: ubuntu-latest
    permissions:
      actions: write
    steps:
      - run: gh api repos/${{ github.repository }}/dispatches -f event_type=ai-fix -f client_payload[prompt]="${{ github.event.comment.body }}"
"""
dispatch_target = """name: dispatch-agent
on: repository_dispatch
jobs:
  fix:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - run: openai api chat.completions.create --prompt "${{ github.event.client_payload.prompt }}" > fix.patch
      - run: git apply fix.patch && git commit -am "ai fix" && git push
"""
dispatch_summaries = [
    _parse_workflow_summary(".github/workflows/comment-dispatch.yml", dispatch_source),
    _parse_workflow_summary(".github/workflows/dispatch-agent.yml", dispatch_target),
]
dispatch_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/dispatch-agent.yml",
    dispatch_target,
    [s for s in dispatch_summaries if s],
)
assert any(f.category == "agentic-workflow-injection" and f.exploitability == "REALISTIC" and f.confidence >= 80 for f in dispatch_findings)
print("agent dispatch findings:")
for f in dispatch_findings:
    print(f" - [{f.severity}/{f.exploitability} {f.confidence}%] {f.category}: {f.title}")


agent_gated_comment = """name: gated-agent
on: issue_comment
jobs:
  fix:
    if: github.event.comment.author_association == 'MEMBER'
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - run: openai api chat.completions.create --prompt "${{ github.event.comment.body }}" > fix.patch
      - uses: peter-evans/create-pull-request@v6
"""
agent_gated_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/agent-gated.yml",
    agent_gated_comment,
)
assert all(
    f.category != "agentic-comment-command" or (f.exploitability == "CONDITIONAL" and f.confidence < 80)
    for f in agent_gated_findings
)
print("agent gated findings: downgraded")


agent_read_only = """name: ai-readonly
on: issue_comment
jobs:
  summarize:
    if: contains(github.event.comment.body, '/summarize')
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: openai api chat.completions.create --prompt "${{ github.event.comment.body }}"
"""
agent_read_only_findings = analyze_workflow(
    "acme/test",
    "https://github.com/acme/test",
    ".github/workflows/agent-readonly.yml",
    agent_read_only,
)
assert not (categories(agent_read_only_findings) & {
    "agentic-workflow-injection",
    "agentic-code-context-poisoning",
    "agentic-tool-execution",
    "agentic-comment-command",
    "agentic-workflow-run-poisoning",
})
print("agent read-only findings: suppressed")


redacted = _redact_ai_context("token: ghp_abcdefghijklmnopqrstuvwxyzABCDE1234567890 and ${{ secrets.OPENAI_API_KEY }}")
assert "ghp_" not in redacted
assert "secrets.OPENAI_API_KEY" not in redacted
print("ask-ai redaction: ok")


precheck = _ask_ai_precheck(
    next(f for f in agent_gated_findings if f.category == "agentic-comment-command"),
    agent_gated_comment,
    [],
)
assert precheck["gates"]
print("ask-ai gate precheck: ok")


label_gated_pr = """name: label-gated
on:
  pull_request_target:
    types: [labeled]
jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"""
label_precheck = _ask_ai_precheck(
    next(iter(analyze_workflow("acme/test", "https://github.com/acme/test", ".github/workflows/label.yml", label_gated_pr)), None)
    or agent_gated_findings[0],
    label_gated_pr,
    [],
)
assert any("label" in gate.lower() for gate in label_precheck["gates"])
print("ask-ai label-event gate precheck: ok")


label_condition_pr = """name: label-condition
on: pull_request_target
jobs:
  triage:
    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"""
label_condition_precheck = _ask_ai_precheck(agent_gated_findings[0], label_condition_pr, [])
assert any("label" in gate.lower() for gate in label_condition_precheck["gates"])
merged = _merge_precheck_into_ask_ai_response(
    AskAIResponse(
        verdict="Valid High Confidence",
        final_severity="High",
        confidence="High",
        attacker_can_exploit=True,
        summary="test",
        blocking_gates=[],
        severity_lowering_factors=[],
        attacker_model="external",
        required_preconditions=[],
        realistic_exploit_path=[],
        ease_of_exploit="Easy",
        reliability="Consistent",
        real_impact="write",
        evidence=[],
        recommendation="Work on it",
    ),
    label_condition_precheck,
)
assert merged.attacker_can_exploit
assert merged.final_severity == "Medium"
assert merged.severity_lowering_factors
assert "conditional" in (merged.why_overstated or "").lower()
print("ask-ai label gate response merge: ok")


parsed = _extract_json_object("""```json
{
  "verdict": "Not Exploitable",
  "final_severity": "Informational",
  "confidence": "High",
  "attacker_can_exploit": false,
  "summary": "Blocked by maintainer gate.",
  "blocking_gates": ["author association"],
  "severity_lowering_factors": ["maintainer-only author association gate"],
  "attacker_model": "External commenter",
  "required_preconditions": ["Maintainer approval"],
  "realistic_exploit_path": ["Attack stops at gate"],
  "ease_of_exploit": "Impractical",
  "reliability": "Rare",
  "real_impact": "No practical impact",
  "why_overstated": "The gate was not considered.",
  "evidence": [{"file": ".github/workflows/agent-gated.yml", "lines": "L5-L5", "reason": "Job if restricts author association"}],
  "recommendation": "Deprioritize"
}
```""")
AskAIResponse(**parsed)
print("ask-ai response parsing: ok")


# ===========================================================================
# Gate classifier regression + new pattern coverage
# ===========================================================================

# 1. Unbounded || alternative disqualifies the entire gate.
assert _classify_if_expression(
    "github.event.pull_request.user.login == 'dependabot[bot]' || true"
) == []
assert _classify_if_expression(
    "github.event.pull_request.head.repo.fork == false || github.event_name == 'push'"
) == []

# 2. Bot-actor allowlist is credited as strong.
bot_gates = _classify_if_expression(
    "github.event.pull_request.user.login == 'dependabot[bot]'"
)
assert any(g[0] == "bot-actor" and g[1] == "strong" for g in bot_gates), bot_gates

# 3. fromJson allowlist on github.actor is strong.
allowlist_gates = _classify_if_expression(
    "contains(fromJson('[\"alice\",\"bob\"]'), github.actor)"
)
assert any(g[0] == "allowlist-fromjson" and g[1] == "strong" for g in allowlist_gates), allowlist_gates

# 4. startsWith on actor is medium.
prefix_gates = _classify_if_expression("startsWith(github.actor, 'acme-')")
assert any(g[0] == "actor-prefix" and g[1] == "medium" for g in prefix_gates), prefix_gates

# 5. Branch ref pin is medium.
branch_gates = _classify_if_expression("github.ref == 'refs/heads/main'")
assert any(g[0] == "branch-ref" and g[1] == "medium" for g in branch_gates), branch_gates

# 6. !github.event.pull_request.head.repo.fork is credited as strong fork-false.
fork_neg_gates = _classify_if_expression("!github.event.pull_request.head.repo.fork")
assert any(g[0] == "fork-false" and g[1] == "strong" for g in fork_neg_gates), fork_neg_gates

# 7. Negated strong gate (e.g. !author_association ...) is NOT credited.
neg_strong_gates = _classify_if_expression(
    "!(github.event.pull_request.author_association == 'MEMBER')"
)
assert neg_strong_gates == [], neg_strong_gates

# 8. && chain with one strong gate credits it.
and_gates = _classify_if_expression(
    "github.event.pull_request.head.repo.full_name == github.repository && github.actor != 'foo'"
)
assert any(g[0] == "same-repo" and g[1] == "strong" for g in and_gates), and_gates

# 9. pull_request_target with types: [closed] only is a strong workflow-level gate.
wf_post_merge_gates = _workflow_trigger_gates({"pull_request_target": {"types": ["closed"]}})
assert any(g[0] == "trigger-post-merge" and g[1] == "strong" for g in wf_post_merge_gates), wf_post_merge_gates

# 10. Mixed [closed, opened] disqualifies the post-merge gate.
wf_mixed_gates = _workflow_trigger_gates({"pull_request_target": {"types": ["closed", "opened"]}})
assert not any(g[0] == "trigger-post-merge" for g in wf_mixed_gates), wf_mixed_gates

# 11. Step-level gating: every step has a strong if -> _job_step_gates returns gates.
step_job = {
    "steps": [
        {"if": "github.event.pull_request.head.repo.fork == false", "run": "echo hi"},
        {"if": "github.actor == 'dependabot[bot]'", "run": "echo bot"},
    ]
}
step_gates = _job_step_gates(step_job)
assert step_gates and any(g[0].startswith("step:") for g in step_gates), step_gates

# 12. Step-level gating: one ungated step disqualifies step-level credit.
mixed_step_job = {
    "steps": [
        {"if": "github.event.pull_request.head.repo.fork == false", "run": "echo hi"},
        {"run": "echo ungated"},
    ]
}
assert _job_step_gates(mixed_step_job) == []

# 13. needs-chain: downstream inherits upstream gate.
jobs_with_chain = {
    "gate": {"if": "github.event.pull_request.author_association == 'MEMBER'", "steps": [{"run": "echo ok"}]},
    "deploy": {"needs": "gate", "steps": [{"run": "deploy.sh"}]},
}
chain_gates = _job_needs_chain_gates(jobs_with_chain["deploy"], jobs_with_chain)
assert any(g[0].startswith("needs:") for g in chain_gates), chain_gates

# 14. Safe two-stage workflow_run pattern.
two_stage_gates = _safe_two_stage_workflow_run_gates(
    {
        "if": "github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.head_branch == 'main'"
    },
    ["workflow_run"],
    "trusted",
)
assert any(g[0] == "two-stage-workflow-run" for g in two_stage_gates), two_stage_gates

# 15. End-to-end: a closed-only pull_request_target workflow with PR checkout
# is downgraded to LOW but NOT deleted from findings.
closed_only_wf = """name: closed-only
on:
  pull_request_target:
    types: [closed]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
"""
closed_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/closed-only.yml", closed_only_wf
)
assert closed_findings, "Closed-only workflow must still yield findings (just downgraded)."
assert all(
    f.severity in ("LOW", "INFO", "MEDIUM") or "closed" in " ".join(f.why).lower()
    for f in closed_findings
), [(f.severity, f.title) for f in closed_findings]
assert any("trigger-post-merge" in g or "closed" in g.lower() for f in closed_findings for g in f.gates_detected), [
    f.gates_detected for f in closed_findings
]
print("gate classifier: ok")
print("trigger-post-merge gate: ok")
print("bot-actor gate: ok")
print("fromJson allowlist gate: ok")
print("step-level gate aggregation: ok")
print("needs-chain inheritance: ok")
print("safe two-stage workflow_run: ok")
print("|| with unbounded branch discarded: ok")
print("closed-only workflow findings preserved + downgraded: ok")


# ============================================================================
# checkout-untrusted enhancements: fetch-depth 0, submodules, expanded sinks,
# local composite actions, wrapper actions.
# ============================================================================
checkout_amplifiers_wf = """name: prt-amplified
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 0
          submodules: recursive
      - run: bun install
      - uses: ./.github/actions/local-build
"""
checkout_amplifiers_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/prt-amplified.yml", checkout_amplifiers_wf
)
co = next(f for f in checkout_amplifiers_findings if f.category == "checkout-untrusted")
why_blob = "\n".join(co.why)
assert "fetch-depth: 0" in why_blob, "fetch-depth: 0 amplifier not surfaced"
assert "submodules" in why_blob and "recursive" in why_blob, "submodules amplifier not surfaced"
assert "bun install" in why_blob, "bun install sink not detected"
assert "local composite action" in why_blob, "local composite action sink not detected"
assert co.confidence >= 90, f"expected >=90% confidence with amplifiers+sinks, got {co.confidence}"
print("checkout-untrusted amplifiers (fetch-depth/submodules): ok")
print("checkout-untrusted expanded sinks (bun, local composite action): ok")


checkout_wrapper_wf = """name: prt-wrapper
on: pull_request_target
jobs:
  ssh:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: appleboy/ssh-action@master
        with:
          host: example.com
          script: bash deploy.sh
"""
wrapper_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/prt-wrapper.yml", checkout_wrapper_wf
)
co2 = next(f for f in wrapper_findings if f.category == "checkout-untrusted")
assert "appleboy/ssh-action" in "\n".join(co2.why), "ssh-action wrapper sink not detected"
print("checkout-untrusted wrapper action sink (appleboy/ssh-action): ok")


checkout_expanded_sinks_wf = """name: prt-modern
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: uv sync
      - run: ./gradlew build
      - run: nx run build
"""
modern_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/prt-modern.yml", checkout_expanded_sinks_wf
)
co3 = next(f for f in modern_findings if f.category == "checkout-untrusted")
sinks_text = "\n".join(co3.why)
assert "uv sync" in sinks_text, "uv sync not detected as sink"
assert "gradlew" in sinks_text, "./gradlew not detected as sink"
assert "nx run" in sinks_text, "nx run not detected as sink"
print("checkout-untrusted expanded sinks (uv, gradlew, nx): ok")


# ============================================================================
# script-injection enhancements: env-indirection, EXECUTION_ACTIONS lookup,
# smuggle tokens, Windows echo widening, new untrusted expressions.
# ============================================================================
env_indirect_wf = """name: env-indirect
on: pull_request_target
jobs:
  danger:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - env:
          BODY: ${{ github.event.pull_request.body }}
        run: |
          eval "$BODY"
"""
env_indirect_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/env-indirect.yml", env_indirect_wf
)
env_si = [f for f in env_indirect_findings if f.category == "script-injection" and "env:" in f.title.lower()]
assert env_si, "env-indirection injection not detected"
assert env_si[0].severity in ("CRITICAL", "HIGH"), f"env-indirection severity too low: {env_si[0].severity}"
assert any("eval" in u for u in env_si[0].evidence + env_si[0].why), "eval sink not surfaced"
print("script-injection env-indirection (eval): ok")


env_indirect_ghenv_wf = """name: env-indirect-ghenv
on: pull_request_target
jobs:
  danger:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "PR_TITLE=$TITLE" >> "$GITHUB_ENV"
"""
env_ghenv_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/env-indirect-ghenv.yml", env_indirect_ghenv_wf
)
env_ghenv_si = [f for f in env_ghenv_findings if f.category == "script-injection" and "env:" in f.title.lower()]
assert env_ghenv_si, "env-indirection to GITHUB_ENV not detected"
assert "GITHUB_ENV" in " ".join(env_ghenv_si[0].evidence + env_ghenv_si[0].why), "GITHUB_ENV sink not surfaced"
print("script-injection env-indirection (GITHUB_ENV write): ok")


# The classic safe env pattern MUST NOT trigger env-indirection.
env_safe_wf = """name: env-safe
on: pull_request_target
jobs:
  ok:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "Title is: $TITLE"
          printf '%s\\n' "$TITLE" > /tmp/title.txt
"""
env_safe_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/env-safe.yml", env_safe_wf
)
assert not any(
    f.category == "script-injection" and "env:" in f.title.lower() for f in env_safe_findings
), "safe env pattern falsely flagged as env-indirection"
print("script-injection env-indirection (safe quoted pattern): not falsely flagged")


wrapper_action_injection_wf = """name: ssh-inject
on: pull_request_target
jobs:
  ssh:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: appleboy/ssh-action@master
        with:
          host: example.com
          script: echo "${{ github.event.pull_request.title }}"
"""
wrapper_injection_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/ssh-inject.yml", wrapper_action_injection_wf
)
wsi = next(f for f in wrapper_injection_findings if f.category == "script-injection")
assert wsi.severity == "CRITICAL", f"expected CRITICAL for appleboy/ssh-action tainted script:, got {wsi.severity}"
assert "appleboy/ssh-action" in "\n".join(wsi.why), "wrapper action not attributed"
print("script-injection wrapper action (appleboy/ssh-action script:): CRITICAL")


smuggle_wf = """name: smuggle
on: pull_request_target
jobs:
  danger:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: |
          echo "::stop-commands::my-token"
          echo "::set-env name=EVIL::rm -rf /"
          echo "::my-token::"
"""
smuggle_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/smuggle.yml", smuggle_wf
)
dep = next(f for f in smuggle_findings if f.category == "deprecated-commands")
assert dep.severity == "HIGH", f"expected HIGH when ::stop-commands:: is present, got {dep.severity}"
assert dep.confidence >= 70, f"expected >=70 confidence, got {dep.confidence}"
assert "stop-commands" in " ".join(dep.evidence)
print("deprecated-commands smuggle-token amplifier (::stop-commands::): HIGH")


winshell_wf = """name: winshell
on: pull_request_target
jobs:
  pwsh:
    runs-on: windows-latest
    permissions:
      contents: write
    steps:
      - shell: pwsh
        run: |
          Write-Output "${{ github.event.pull_request.title }}"
"""
winshell_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/winshell.yml", winshell_wf
)
wsi_pwsh = next(f for f in winshell_findings if f.category == "script-injection")
assert any(
    "Write-Output" in w or "stdout" in w for w in wsi_pwsh.why
), "PowerShell Write-Output not recognized as stdout sink"
print("script-injection PowerShell stdout widening (Write-Output): ok")


# New UNTRUSTED_INPUT_EXPR entries should each raise script-injection.
new_expr_wf = """name: new-untrusted
on: pull_request_target
jobs:
  danger:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: |
          echo "${{ github.event.workflow_run.display_title }}"
          echo "${{ github.event.milestone.title }}"
          echo "${{ github.event.deployment.description }}"
"""
new_expr_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/new-untrusted.yml", new_expr_wf
)
ne_si = next(f for f in new_expr_findings if f.category == "script-injection")
injected = " ".join(ne_si.why)
assert "workflow_run.display_title" in injected, "workflow_run.display_title not detected"
assert "milestone.title" in injected, "milestone.title not detected"
assert "deployment.description" in injected, "deployment.description not detected"
print("script-injection new UNTRUSTED_INPUT_EXPR entries (workflow_run.display_title, milestone.title, deployment.description): ok")


# ============================================================================
# Per-finding bug-bounty specificity: tainted_expression, detected_sink_line,
# line_number are populated by the scanner; CVSS is per-finding; references
# are category-specific; fix diff is generated; PoC/steps quote the exact
# detected value.
# ============================================================================
bounty_checkout_wf = """name: prt-bounty
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: bun install
"""
bounty_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/prt-bounty.yml", bounty_checkout_wf
)
co = next(f for f in bounty_findings if f.category == "checkout-untrusted")
assert co.tainted_expression, "checkout-untrusted must populate tainted_expression"
assert "pull_request.head.sha" in co.tainted_expression, f"unexpected tainted_expression: {co.tainted_expression!r}"
assert co.detected_sink_line, "checkout-untrusted must populate detected_sink_line"
assert "bun install" in co.detected_sink_line, f"unexpected sink line: {co.detected_sink_line!r}"
assert co.line_number and co.line_number > 0, "line_number must be populated"
print(f"scanner threading: tainted_expression, detected_sink_line, line_number populated (checkout-untrusted, line {co.line_number}): ok")

# Bug-bounty report reflects those specifics.
rep = build_bug_bounty_report(co)
assert rep.tainted_expression == co.tainted_expression, "report tainted_expression mismatch"
assert rep.detected_sink_line == co.detected_sink_line, "report detected_sink_line mismatch"
# CVSS: real vector shape and score in the correct range.
assert rep.cvss_vector.startswith("CVSS:3.1/AV:") and "/AC:" in rep.cvss_vector, f"malformed CVSS vector: {rep.cvss_vector!r}"
assert 5.0 <= rep.cvss_score <= 10.0, f"CVSS score out of expected range for CRITICAL: {rep.cvss_score}"
# References are category-specific: the checkout-untrusted entry has the
# adnanthekhan post as its top-of-list ref, so it must appear before the
# generic OWASP entry.
assert any("adnanthekhan.com" in r for r in rep.references), "checkout-untrusted category reference missing"
adnan_idx = next(i for i, r in enumerate(rep.references) if "adnanthekhan.com" in r)
owasp_idx = next(i for i, r in enumerate(rep.references) if "owasp.org" in r)
assert adnan_idx < owasp_idx, "category-specific references must appear before common ones"
# Fix diff quotes the detected sink and the tainted ref.
assert "actions/checkout" in rep.fix_diff and "persist-credentials: false" in rep.fix_diff, "checkout-untrusted fix diff missing"
# PoC quotes the sink so triagers see the concrete file to plant.
assert "bun install" in rep.proof_of_concept or "package.json" in rep.proof_of_concept, (
    "PoC must reference the specific sink or fork-side file"
)
# Steps quote the fork branch and the specific tainted expression.
steps_blob = " ".join(rep.steps_to_reproduce)
assert "grafter-poc-" in steps_blob, "steps must include a concrete fork branch"
print(f"bug-bounty report specifics (checkout-untrusted): CVSS={rep.cvss_score} vector={rep.cvss_vector}: ok")


# Script injection report: tainted expression appears verbatim in the fix
# diff (as a `${{ ... }}` reference) and PoC.
bounty_inject_wf = """name: si-bounty
on: pull_request_target
jobs:
  danger:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: |
          echo "PR title: ${{ github.event.pull_request.title }}"
"""
inject_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/si-bounty.yml", bounty_inject_wf
)
si = next(f for f in inject_findings if f.category == "script-injection")
assert si.tainted_expression == "github.event.pull_request.title", f"unexpected tainted: {si.tainted_expression!r}"
assert si.line_number and si.line_number > 0
rep_si = build_bug_bounty_report(si)
assert "${{ github.event.pull_request.title }}" in rep_si.fix_diff, "fix diff must render the exact tainted expression"
assert "TITLE:" in rep_si.fix_diff or "TITLE :" in rep_si.fix_diff or "env:" in rep_si.fix_diff, "fix diff must show env-lifting remediation"
# CVSS must reflect the "privileged, unauthenticated, no-UI" shape for a
# raw pull_request_target script-injection — score should be >= 9.0.
assert rep_si.cvss_score >= 9.0, f"expected critical CVSS for raw pull_request_target script-injection, got {rep_si.cvss_score}"
# The GHSA advisory link for set-env smuggling is category-specific.
assert any("advisories/GHSA-mfwh-5m23-j46w" in r for r in rep_si.references), "script-injection GHSA reference missing"
print(f"bug-bounty report specifics (script-injection): CVSS={rep_si.cvss_score}: ok")


# CVSS scaling: strong gates lower the score.
gated_wf = """name: gated
on: pull_request_target
jobs:
  danger:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    if: github.event.pull_request.author_association == 'MEMBER'
    steps:
      - run: |
          echo "${{ github.event.pull_request.title }}"
"""
gated_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/gated.yml", gated_wf
)
gsi = next(f for f in gated_findings if f.category == "script-injection")
rep_gated = build_bug_bounty_report(gsi)
assert rep_gated.cvss_score < rep_si.cvss_score, (
    f"gated finding should have a lower CVSS ({rep_gated.cvss_score}) than ungated ({rep_si.cvss_score})"
)
print(f"CVSS gate-awareness: gated={rep_gated.cvss_score} < ungated={rep_si.cvss_score}: ok")


# Provider revocation URL for verified-secret category.
assert _revocation_url_for("github") and "github.com/settings" in _revocation_url_for("github")
assert _revocation_url_for("openai") and "platform.openai.com" in _revocation_url_for("openai")
assert _revocation_url_for("aws") and "console.aws.amazon.com" in _revocation_url_for("aws")
assert _revocation_url_for(None) is None
assert _revocation_url_for("unknownprovider") is None
print("verified-secret revocation URLs (github/openai/aws): ok")


# Category references: every known category yields a non-empty list, and
# the common refs are always included as a fallback tail.
from main import _CATEGORY_REFERENCES, _COMMON_REFS  # noqa: E402
class _FakeFinding:
    def __init__(self, cat: str) -> None:
        self.category = cat
for cat in list(_CATEGORY_REFERENCES.keys())[:5]:
    refs = _references_for(_FakeFinding(cat))  # type: ignore[arg-type]
    assert refs, f"no refs returned for category {cat}"
    assert refs[-len(_COMMON_REFS):] == _COMMON_REFS or any(
        r in refs for r in _COMMON_REFS
    ), f"common refs missing for {cat}"
print(f"category references non-empty for {len(_CATEGORY_REFERENCES)} categories, common refs appended: ok")


# Live vs archived: state="live" hides archived rows; state="archived"
# shows only them; state="all" shows both.
from main import db_query_findings, db_update_archive_state, _db_init, db_insert_findings, Finding as _Finding  # noqa: E402
import tempfile, os as _os  # noqa: E402
# Use a throwaway DB so we don't pollute the real one.
_test_db_dir = tempfile.mkdtemp(prefix="grafter-smoke-")
_os.environ["GRAFTER_DATA_DIR"] = _test_db_dir
# Force a re-init pointed at the tempdir. `_db_init` is idempotent.
import importlib, main as _main_mod  # noqa: E402
importlib.reload(_main_mod)  # picks up new GRAFTER_DATA_DIR
_main_mod._db_init()
sample_a = _main_mod.Finding(
    id="test-a", repo="acme/test", repo_url="https://github.com/acme/test",
    workflow_path=".github/workflows/x.yml", workflow_url="",
    trigger="pull_request_target", severity="CRITICAL",
    exploitability="HIGHLY_EXPLOITABLE", confidence=95,
    title="live one", why=["w"], evidence=["e"], remediation=["r"], snippet="s",
    category="script-injection",
)
sample_b = _main_mod.Finding(
    id="test-b", repo="acme/test", repo_url="https://github.com/acme/test",
    workflow_path=".github/workflows/y.yml", workflow_url="",
    trigger="pull_request_target", severity="CRITICAL",
    exploitability="HIGHLY_EXPLOITABLE", confidence=95,
    title="soon-archived", why=["w"], evidence=["e"], remediation=["r"], snippet="s",
    category="script-injection",
)
_main_mod.db_insert_findings("scan-1", [sample_a, sample_b])
# Archive one and verify the state filter.
_main_mod.db_update_archive_state("test-b", archived_state="fixed", reason="unit test")
total_live, live_items = _main_mod.db_query_findings(1, 50, state="live")
total_arch, arch_items = _main_mod.db_query_findings(1, 50, state="archived")
total_all, all_items = _main_mod.db_query_findings(1, 50, state="all")
live_ids = {i.id for i in live_items}
arch_ids = {i.id for i in arch_items}
all_ids = {i.id for i in all_items}
assert "test-a" in live_ids and "test-b" not in live_ids, f"live filter broken: {live_ids}"
assert "test-b" in arch_ids and "test-a" not in arch_ids, f"archived filter broken: {arch_ids}"
assert {"test-a", "test-b"}.issubset(all_ids), f"all filter broken: {all_ids}"
# Archived FindingListItem carries the reason so the badge is renderable.
b_item = next(i for i in arch_items if i.id == "test-b")
assert b_item.archived_state == "fixed"
assert b_item.archived_reason == "unit test"
# Re-inserting the same finding (as a re-scan would) resets the archive.
_main_mod.db_insert_findings("scan-2", [sample_b])
total_live2, live_items2 = _main_mod.db_query_findings(1, 50, state="live")
assert "test-b" in {i.id for i in live_items2}, "re-inserted finding must revert to live"
print("live/archived toggle: state=live hides fixed, state=archived shows only fixed, state=all shows both; re-scan reverts to live: ok")


# ============================================================================
# Expanded secret providers — regex recognition for the 8 new provider
# recognizers. We do NOT hit any real API in tests (validators would try to
# curl provider endpoints); we just assert that the extractor labels the
# provider/kind correctly on synthetic values that mimic each format.
# ============================================================================
def _providers_seen(text: str) -> dict[str, str]:
    cands = _extract_secret_candidates("test.env", text, limit=200)
    return {c.provider: c.kind for c in cands}

# Each token below is a synthetic string matching the *format* the recognizer
# expects — long enough to satisfy the regex length bounds. No real secret.
new_provider_corpus = "\n".join([
    "STRIPE_LIVE=sk_live_" + ("A" * 24),
    "STRIPE_TEST=sk_test_" + ("B" * 24),
    "STRIPE_RESTRICTED=rk_live_" + ("C" * 24),
    "SENDGRID_API_KEY=SG." + ("D" * 22) + "." + ("E" * 43),
    "HF_TOKEN=hf_" + ("F" * 34),
    "DOCKERHUB=dckr_pat_" + ("G" * 32),
    "GITLAB_TOKEN=glpat-" + ("H" * 25),
    "ANTHROPIC_API_KEY=sk-ant-api03-" + ("I" * 90),
    "GOOGLE_KEY=AIza" + ("J" * 35),
])
seen = _providers_seen(new_provider_corpus)
assert seen.get("stripe") in ("live-secret-key", "test-secret-key"), f"stripe not detected: {seen}"
assert seen.get("sendgrid") == "api-key", f"sendgrid not detected: {seen}"
assert seen.get("huggingface") == "access-token", f"huggingface not detected: {seen}"
assert seen.get("dockerhub") == "pat", f"dockerhub not detected: {seen}"
assert seen.get("gitlab") == "pat", f"gitlab not detected: {seen}"
assert seen.get("anthropic") == "api-key", f"anthropic not detected: {seen}"
assert seen.get("google") == "api-key", f"google not detected: {seen}"
# The Anthropic key must NOT also be flagged as OpenAI (regex must exclude
# sk-ant-…).
assert "openai" not in seen or seen["openai"] != "api-key", (
    f"Anthropic key spuriously detected as OpenAI: {seen}"
)
print("secret providers: stripe / sendgrid / huggingface / dockerhub / gitlab / anthropic / google recognised; anthropic does not collide with openai: ok")

# PEM private key block is captured across multiple lines.
pem_corpus = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    + ("MIIEpAIBAAKCAQEA1x2y3z4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b\n" * 6)
    + "-----END RSA PRIVATE KEY-----\n"
)
pem_seen = _providers_seen(pem_corpus)
assert "pem-private-key" in pem_seen, f"PEM private key not detected: {pem_seen}"
# Placeholder blocks should be skipped.
placeholder_corpus = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "YOUR PRIVATE KEY HERE\n"
    "-----END RSA PRIVATE KEY-----\n"
)
placeholder_seen = _providers_seen(placeholder_corpus)
assert "pem-private-key" not in placeholder_seen, "placeholder PEM block must be skipped"
print("secret providers: PEM private key block detected; placeholder blocks skipped: ok")

# Revocation URLs for the new providers are wired into the report generator.
for provider, expected_substring in [
    ("stripe", "dashboard.stripe.com"),
    ("sendgrid", "app.sendgrid.com"),
    ("huggingface", "huggingface.co/settings"),
    ("dockerhub", "hub.docker.com/settings"),
    ("gitlab", "gitlab.com"),
    ("anthropic", "console.anthropic.com"),
    ("google", "console.cloud.google.com"),
]:
    url = _revocation_url_for(provider)
    assert url and expected_substring in url, f"revocation URL for {provider} missing: {url!r}"
print("secret providers: revocation URLs wired for all 7 new providers: ok")


# ============================================================================
# SARIF 2.1.0 export — schema shape, level mapping, security-severity from
# per-finding CVSS, source→sink code flow, rules aggregation, baselineState
# mapping, and single-finding endpoint parity.
# ============================================================================
sarif_wf = """name: sarif-target
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci
"""
sarif_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test", ".github/workflows/sarif-target.yml", sarif_wf
)
assert sarif_findings, "expected at least one finding to build SARIF against"

sarif = build_sarif(sarif_findings, repo_hint="acme/test")
# Top-level schema sanity.
assert sarif.get("$schema", "").endswith("sarif-schema-2.1.0.json"), "SARIF schema URI missing"
assert sarif["version"] == "2.1.0", "SARIF version must be 2.1.0"
assert isinstance(sarif["runs"], list) and len(sarif["runs"]) == 1
run = sarif["runs"][0]
# Tool driver.
driver = run["tool"]["driver"]
assert driver["name"] == "Grafter"
assert driver["informationUri"].startswith("https://")
assert isinstance(driver["rules"], list) and driver["rules"], "SARIF must include at least one rule"
# Rules are unique per category and carry a helpUri when known.
rule_ids = [r["id"] for r in driver["rules"]]
assert len(rule_ids) == len(set(rule_ids)), f"duplicate rule ids: {rule_ids}"
assert "checkout-untrusted" in rule_ids, f"expected rule for checkout-untrusted, got {rule_ids}"
checkout_rule = next(r for r in driver["rules"] if r["id"] == "checkout-untrusted")
assert checkout_rule.get("helpUri", "").startswith("http"), "expected helpUri on checkout-untrusted rule"
assert "security" in checkout_rule["properties"]["tags"], "expected 'security' tag on rule"
# Provenance ties results back to the repo.
assert run.get("versionControlProvenance"), "SARIF must carry versionControlProvenance"
assert run["versionControlProvenance"][0]["repositoryUri"] == "https://github.com/acme/test"
# Results carry the right fields for GitHub code scanning.
results = run["results"]
assert results, "SARIF must include at least one result"
result = next(r for r in results if r["ruleId"] == "checkout-untrusted")
assert result["level"] in ("error", "warning", "note", "none"), f"invalid level: {result['level']}"
# CRITICAL/HIGH → "error".
assert result["level"] == "error", "checkout-untrusted should map to level=error"
# security-severity is a stringified CVSS score usable by GitHub.
sec_sev = result["properties"]["security-severity"]
assert isinstance(sec_sev, str) and 0.0 <= float(sec_sev) <= 10.0, f"bad security-severity: {sec_sev!r}"
# CVSS vector is present.
assert result["properties"]["cvss-vector"].startswith("CVSS:3.1/AV:"), "cvss-vector missing or malformed"
# Location includes SRCROOT and startLine (from the scanner's line_number).
loc = result["locations"][0]["physicalLocation"]
assert loc["artifactLocation"]["uri"] == ".github/workflows/sarif-target.yml"
assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
assert loc["region"]["startLine"] >= 1, "startLine must be positive"
# codeFlow source→sink is present when tainted_expression + detected_sink_line
# are known (they are for checkout-untrusted).
assert result.get("codeFlows"), "expected codeFlows source→sink for checkout-untrusted"
flow = result["codeFlows"][0]["threadFlows"][0]["locations"]
assert len(flow) == 2, "expected exactly two threadFlow locations (source, sink)"
assert "pull_request.head.sha" in flow[0]["location"]["message"]["text"], f"source location wrong: {flow[0]}"
# fixes[] carries the unified diff.
assert result.get("fixes"), "expected fixes[] block from _fix_yaml_diff"
fix_markdown = result["fixes"][0]["description"]["markdown"]
assert "```diff" in fix_markdown, "expected fenced diff in SARIF fix markdown"
# partialFingerprints stable across scans.
assert result["partialFingerprints"]["grafterId/v1"], "partialFingerprints must include grafterId/v1"
# baselineState reflects live status.
assert result["baselineState"] in ("new", "absent", "updated", "unchanged"), (
    f"invalid baselineState: {result['baselineState']}"
)
# uriBaseId root is present.
assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].startswith("http")
print(
    f"SARIF export: schema 2.1.0, level=error for CRITICAL, security-severity={sec_sev}, "
    f"codeFlow source->sink, fixes[] with diff, provenance, baselineState: ok"
)

# level mapping helper honours the full severity ladder.
assert _sarif_level_for("CRITICAL") == "error"
assert _sarif_level_for("HIGH") == "error"
assert _sarif_level_for("MEDIUM") == "warning"
assert _sarif_level_for("LOW") == "note"
assert _sarif_level_for("INFO") == "none"
assert _sarif_baseline_state(None) == "new"
assert _sarif_baseline_state("live") == "new"
assert _sarif_baseline_state("fixed") == "absent"
assert _sarif_baseline_state("deleted") == "absent"
assert _sarif_baseline_state("modified") == "updated"
print("SARIF level and baselineState mappings: ok")

# Building SARIF for zero findings must still produce a valid document (empty
# rules + empty results) — this happens when the export endpoint is called on
# a scan that had nothing to report.
empty_sarif = build_sarif([], repo_hint="acme/test")
assert empty_sarif["version"] == "2.1.0"
assert empty_sarif["runs"][0]["tool"]["driver"]["rules"] == []
assert empty_sarif["runs"][0]["results"] == []
print("SARIF export: empty-findings case still produces a valid document: ok")


# ============================================================================
# pr-controlled-dockerfile-build — the new rule for the msamp Build Image
# workflow: `pull_request` triggers a docker/build-push-action against a
# checkout of PR head on a self-hosted runner. Attacker RUN instructions in
# the Dockerfile execute on the runner.
# ============================================================================
dfb_selfhosted_wf = """name: build-image
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
jobs:
  docker:
    runs-on: [self-hosted, linux, x64, gpu]
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v2
        with:
          submodules: true
      - uses: docker/setup-buildx-action@v1
      - uses: docker/login-action@v1
        if: ${{ github.event_name != 'pull_request' }}
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v2
        with:
          context: .
          file: Dockerfile
          push: ${{ github.event_name != 'pull_request' }}
"""
dfb_findings = analyze_workflow(
    "azure/msamp", "https://github.com/azure/msamp",
    ".github/workflows/build.yml", dfb_selfhosted_wf,
)
dfb = next((f for f in dfb_findings if f.category == "pr-controlled-dockerfile-build"), None)
assert dfb is not None, (
    f"pr-controlled-dockerfile-build not detected on self-hosted+PR+docker-build: "
    f"got {[f.category for f in dfb_findings]}"
)
assert dfb.severity == "CRITICAL", f"expected CRITICAL, got {dfb.severity}"
assert dfb.exploitability == "HIGHLY_EXPLOITABLE"
assert dfb.confidence >= 90, f"confidence too low: {dfb.confidence}"
# Sink line names the specific action and its `context:`/`file:` inputs.
assert "docker/build-push-action" in (dfb.detected_sink_line or "")
assert "context=" in (dfb.detected_sink_line or "")
assert "file=Dockerfile" in (dfb.detected_sink_line or "")
# Self-hosted rationale surfaces in the why.
assert any("self-hosted" in w.lower() for w in dfb.why), "self-hosted why-line missing"
# Registry login step is called out.
assert any("registry" in w.lower() and "login" in w.lower() for w in dfb.why), "registry-login rationale missing"
# CVSS is scope-changed (publishing to a registry / cache-poisoning) and near-max.
vec, score = _compute_cvss(dfb)
assert "/S:C/" in vec, f"expected scope-changed CVSS for dockerfile-build, got {vec}"
assert score >= 9.5, f"expected near-max CVSS for self-hosted+push scenario, got {score}"
print(f"pr-controlled-dockerfile-build (self-hosted): CRITICAL, CVSS={score:.1f} scope=C: ok")

# Bug-bounty report: category-specific steps + PoC + fix-diff.
r_dfb = build_bug_bounty_report(dfb)
assert "dockerfile" in " ".join(r_dfb.steps_to_reproduce).lower(), "steps must mention Dockerfile"
assert "RUN" in r_dfb.proof_of_concept, "PoC must show a Dockerfile RUN instruction"
assert "GRAFTER_MARKER" in r_dfb.proof_of_concept, "PoC must show a benign marker payload"
assert "build-push-action" in r_dfb.fix_diff, "fix diff must reference build-push-action"
assert "push: false" in r_dfb.fix_diff, "fix diff must show `push: false` remediation"
assert any("docker/build-push-action" in ref for ref in r_dfb.references), (
    "category-specific docker/build-push-action reference missing"
)
print("pr-controlled-dockerfile-build report: dockerfile-specific steps + PoC + fix diff + refs: ok")

# SARIF representation for the new rule.
sarif_dfb = build_sarif([dfb], repo_hint="azure/msamp")
rule_ids = {r["id"] for r in sarif_dfb["runs"][0]["tool"]["driver"]["rules"]}
assert "pr-controlled-dockerfile-build" in rule_ids
result_dfb = next(r for r in sarif_dfb["runs"][0]["results"] if r["ruleId"] == "pr-controlled-dockerfile-build")
assert result_dfb["level"] == "error"
assert float(result_dfb["properties"]["security-severity"]) >= 9.5
print("SARIF: pr-controlled-dockerfile-build rule + result (level=error, security-severity>=9.5): ok")

# Hosted-runner variant: still HIGH+ because PAT/OIDC exposure, but not
# CRITICAL unless push: true or extra boosters — verify severity scales.
dfb_hosted_wf = """name: build-pr
on:
  pull_request:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v6
        with:
          context: .
          file: Dockerfile
          push: false
"""
dfb_hosted = analyze_workflow(
    "acme/test", "https://github.com/acme/test",
    ".github/workflows/build-pr.yml", dfb_hosted_wf,
)
dfb_h = next((f for f in dfb_hosted if f.category == "pr-controlled-dockerfile-build"), None)
assert dfb_h is not None, "hosted-runner dockerfile-build should still fire"
# On hosted `pull_request` with empty `permissions: {}` and no push, the
# platform blanks `secrets.*` for fork PRs and read-onlys GITHUB_TOKEN, so
# the residual attacker impact is compute abuse only. Downgrade rule 5
# (post-processing) caps this at MEDIUM. Same-repo PRs would still carry
# the original higher severity — annotated in `why`.
assert dfb_h.severity == "MEDIUM", f"expected MEDIUM for hosted no-push case (fork-PR downgrade), got {dfb_h.severity}"
assert any("Severity capped at MEDIUM" in w for w in dfb_h.why), (
    "downgrade rule 5 should attach a fork-PR / same-repo-PR annotation to the why: block"
)
print(f"pr-controlled-dockerfile-build (hosted, no push, no perms): {dfb_h.severity} + downgrade annotation: ok")

# Negative case: no docker build step -> no finding.
no_docker_wf = """name: pr-tests
on:
  pull_request:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
"""
no_docker_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test",
    ".github/workflows/tests.yml", no_docker_wf,
)
assert not any(f.category == "pr-controlled-dockerfile-build" for f in no_docker_findings), (
    "must not fire when no docker build step is present"
)
print("pr-controlled-dockerfile-build: no false positive on plain PR-CI without docker build: ok")

# Negative case: docker build but only push:main (no pull_request) -> no
# untrusted trigger, no finding.
push_only_wf = """name: publish
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v6
        with:
          context: .
          push: true
"""
push_only_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test",
    ".github/workflows/publish.yml", push_only_wf,
)
assert not any(f.category == "pr-controlled-dockerfile-build" for f in push_only_findings), (
    "must not fire when only push:main triggers the build (no PR reachability)"
)
print("pr-controlled-dockerfile-build: no false positive on push-only publish workflow: ok")

# Direct `docker buildx build` in `run:` should be detected too, not just
# the docker/build-push-action wrapper.
dfb_shell_wf = """name: pr-buildx
on:
  pull_request:
    branches: [main]
jobs:
  build:
    runs-on: [self-hosted, linux, x64]
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - run: docker buildx build --file Dockerfile --push -t ghcr.io/acme/x:pr .
"""
dfb_shell_findings = analyze_workflow(
    "acme/test", "https://github.com/acme/test",
    ".github/workflows/buildx.yml", dfb_shell_wf,
)
dfb_s = next((f for f in dfb_shell_findings if f.category == "pr-controlled-dockerfile-build"), None)
assert dfb_s is not None, "shell `docker buildx build` after PR checkout must be detected"
assert "docker buildx build" in (dfb_s.detected_sink_line or "").lower()
print("pr-controlled-dockerfile-build: direct `docker buildx build` in run: detected: ok")


# ============================================================================
# pr-submodules-recursive-on-self-hosted — `.gitmodules` is attacker-
# controlled after PR-head checkout; `submodules: true|recursive` turns each
# URL into an outbound request from the runner. GITHUB_TOKEN is sent in the
# Authorization header by default; the primitive works even with
# `permissions: contents: read` and no pull_request_target.
# ============================================================================
sm_selfhosted_wf = """name: unit-test
on:
  pull_request:
    branches: [main]
jobs:
  test:
    runs-on: [self-hosted, gpu]
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive
      - run: pytest -q
"""
sm_findings = analyze_workflow(
    "microsoft/ltp-sglang", "https://github.com/microsoft/ltp-sglang",
    ".github/workflows/unit-test.yml", sm_selfhosted_wf,
)
sm = next((f for f in sm_findings if f.category == "pr-submodules-recursive"), None)
assert sm is not None, (
    f"pr-submodules-recursive not detected on self-hosted+PR+submodules:recursive: "
    f"{[f.category for f in sm_findings]}"
)
assert sm.severity == "CRITICAL", f"expected CRITICAL for self-hosted+persist=default, got {sm.severity}"
assert sm.exploitability == "HIGHLY_EXPLOITABLE"
assert sm.confidence >= 88
# Sink line names the submodules mode and persist-credentials state.
assert "submodules: recursive" in (sm.detected_sink_line or "")
assert "persist-credentials=default true" in (sm.detected_sink_line or ""), (
    f"sink must report persist-credentials state: {sm.detected_sink_line}"
)
# Rationale surfaces the token-exfil mechanism and self-hosted amplifier.
why_blob = "\n".join(sm.why).lower()
assert "authorization" in why_blob or "x-access-token" in why_blob or "github_token" in why_blob, (
    "must mention the token-exfil mechanism"
)
assert "169.254.169.254" in why_blob or "instance metadata" in why_blob, (
    "must mention IMDS reachability on self-hosted runners"
)
assert "recursive" in why_blob, "must call out `submodules: recursive` amplification"
# CVSS: not scope-changed here (attack stays within the org's control plane).
vec, score = _compute_cvss(sm)
assert score >= 8.0, f"expected high CVSS for self-hosted+persist=default, got {score}"
print(f"pr-submodules-recursive (self-hosted, persist=default): CRITICAL CVSS={score:.1f}: ok")

# Bug-bounty report: category-specific steps + PoC + fix diff + refs.
r_sm = build_bug_bounty_report(sm)
steps_blob = " ".join(r_sm.steps_to_reproduce).lower()
assert ".gitmodules" in steps_blob, "steps must reference .gitmodules"
assert "collector" in steps_blob, "steps must describe the attacker-side collector"
assert "authorization" in r_sm.proof_of_concept.lower(), "PoC must call out the Authorization header"
assert "persist-credentials: false" in r_sm.fix_diff, "fix diff must show persist-credentials remediation"
assert any("GHSA-cxww-7g56-2vh6" in ref or "CVE-2018-11235" in ref for ref in r_sm.references), (
    "category-specific submodule advisories missing"
)
print("pr-submodules-recursive report: .gitmodules-specific steps + PoC + fix diff + CVEs: ok")

# persist-credentials: false downgrade — still HIGH on self-hosted (SSRF /
# git CVEs remain) but no longer CRITICAL.
sm_persist_false_wf = """name: unit-test
on:
  pull_request:
    branches: [main]
jobs:
  test:
    runs-on: [self-hosted, gpu]
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive
          persist-credentials: false
"""
sm_pf = analyze_workflow(
    "acme/test", "https://github.com/acme/test",
    ".github/workflows/pf.yml", sm_persist_false_wf,
)
pf = next(f for f in sm_pf if f.category == "pr-submodules-recursive")
assert pf.severity == "HIGH", (
    f"persist-credentials=false on self-hosted should downgrade CRITICAL->HIGH, got {pf.severity}"
)
pf_why = "\n".join(pf.why).lower()
assert "ssrf" in pf_why or "dos" in pf_why or "cve-2018-11235" in pf_why, (
    "downgrade rationale must name the remaining primitives"
)
print("pr-submodules-recursive: persist-credentials=false downgrades self-hosted CRITICAL -> HIGH: ok")

# GitHub-hosted + persist=default → HIGH (token exfil still real, no IMDS).
sm_hosted_wf = """name: ci
on:
  pull_request:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
"""
sm_h = analyze_workflow(
    "acme/test", "https://github.com/acme/test",
    ".github/workflows/h.yml", sm_hosted_wf,
)
h = next(f for f in sm_h if f.category == "pr-submodules-recursive")
# Downgrade rule 5: hosted `pull_request` with blanked secrets → compute
# abuse only → MEDIUM cap. Original HIGH would apply on same-repo PR (or
# on self-hosted, which is a different test above).
assert h.severity == "MEDIUM", f"expected MEDIUM for hosted+persist=default (fork-PR downgrade), got {h.severity}"
assert any("Severity capped at MEDIUM" in w for w in h.why), (
    "downgrade rule 5 must attach the fork-PR / same-repo-PR annotation"
)
# Non-recursive should not add the recursive-amplifier why line.
h_why = "\n".join(h.why).lower()
assert "amplifying the attack surface" not in h_why, (
    "recursive-amplifier line should NOT appear for `submodules: true`"
)
print("pr-submodules-recursive: hosted+persist=default -> HIGH; non-recursive omits amplifier line: ok")

# Hosted + persist=false → MEDIUM (only SSRF/DoS/git CVEs left).
sm_hosted_pf_wf = """name: ci
on:
  pull_request:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
          persist-credentials: false
"""
sm_hpf = analyze_workflow(
    "acme/test", "https://github.com/acme/test",
    ".github/workflows/hpf.yml", sm_hosted_pf_wf,
)
hpf = next(f for f in sm_hpf if f.category == "pr-submodules-recursive")
assert hpf.severity == "MEDIUM", (
    f"hosted+persist=false should be MEDIUM, got {hpf.severity}"
)
print("pr-submodules-recursive: hosted+persist=false -> MEDIUM (SSRF/DoS only): ok")

# Negative: push-only trigger -> no fire.
sm_push_only_wf = """name: ci
on:
  push:
    branches: [main]
jobs:
  test:
    runs-on: [self-hosted, gpu]
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive
"""
sm_po = analyze_workflow(
    "acme/test", "https://github.com/acme/test",
    ".github/workflows/po.yml", sm_push_only_wf,
)
assert not any(f.category == "pr-submodules-recursive" for f in sm_po), (
    "must not fire when trigger is not PR-reachable"
)
print("pr-submodules-recursive: no false positive on push-only workflow: ok")

# Negative: submodules: false / omitted -> no fire.
sm_no_submodules_wf = """name: ci
on:
  pull_request:
    branches: [main]
jobs:
  test:
    runs-on: [self-hosted, gpu]
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: false
      - run: pytest
"""
sm_no = analyze_workflow(
    "acme/test", "https://github.com/acme/test",
    ".github/workflows/nosm.yml", sm_no_submodules_wf,
)
assert not any(f.category == "pr-submodules-recursive" for f in sm_no), (
    "must not fire when submodules is false"
)
print("pr-submodules-recursive: no false positive when submodules: false: ok")


# ============================================================================
# Cross-scan diff — link table membership, previous-scan resolver, and diff
# set-algebra including severity-change classification.
# ============================================================================
import tempfile as _tempfile2  # noqa: E402
_diff_tmp = _tempfile2.mkdtemp(prefix="grafter-diff-smoke-")
_os.environ["GRAFTER_DATA_DIR"] = _diff_tmp
importlib.reload(_main_mod)
_main_mod._db_init()

# Seed two scans (scan_a, then scan_b) for the same org. Directly write
# rows into the `scans` table so we can control started/finished and
# ordering deterministically.
with _main_mod._db() as _c:
    _c.execute(
        "INSERT INTO scans (id, org, state, started, finished) VALUES (?,?,?,?,?)",
        ("scan_a", "acme/diff", "done", 1000.0, 1010.0),
    )
    _c.execute(
        "INSERT INTO scans (id, org, state, started, finished) VALUES (?,?,?,?,?)",
        ("scan_b", "acme/diff", "done", 2000.0, 2010.0),
    )

def _mk(
    id_: str,
    severity: str,
    confidence: int,
    title: str,
    category: str = "script-injection",
) -> _main_mod.Finding:
    return _main_mod.Finding(
        id=id_, repo="acme/diff", repo_url="https://github.com/acme/diff",
        workflow_path=".github/workflows/x.yml", workflow_url="",
        trigger="pull_request_target", severity=severity,
        exploitability="HIGHLY_EXPLOITABLE", confidence=confidence,
        title=title, why=["w"], evidence=["e"], remediation=["r"], snippet="s",
        category=category,
    )

# scan_a: A (CRITICAL, 90), B (HIGH, 82), C (HIGH, 85), and E in a
# different category used to prove partial scans do not report it fixed.
_main_mod.db_insert_findings("scan_a", [
    _mk("A", "CRITICAL", 90, "A"),
    _mk("B", "HIGH", 82, "B"),
    _mk("C", "HIGH", 85, "C"),
    _mk("E", "HIGH", 86, "E", "cache-poisoning"),
])
# scan_b: A (CRITICAL, 95 — confidence went up), B removed (fixed),
#         C (LOW, 85 — severity dropped), D (CRITICAL, 92 — new)
_main_mod.db_insert_findings("scan_b", [
    _mk("A", "CRITICAL", 95, "A"),
    _mk("C", "LOW", 85, "C"),
    _mk("D", "CRITICAL", 92, "D"),
])

# Previous-scan resolver: for scan_b, previous is scan_a.
prev_of_b = _main_mod.db_previous_completed_scan("acme/diff", "scan_b")
assert prev_of_b and prev_of_b["id"] == "scan_a", (
    f"previous of scan_b should be scan_a, got {prev_of_b}"
)
# For scan_a there is no earlier scan.
prev_of_a = _main_mod.db_previous_completed_scan("acme/diff", "scan_a")
assert prev_of_a is None, f"scan_a should have no baseline, got {prev_of_a}"
print("diff: previous-scan resolver picks correct baseline; None on first scan: ok")

# Cross-org isolation: a scan from a different org must not be picked.
with _main_mod._db() as _c:
    _c.execute(
        "INSERT INTO scans (id, org, state, started, finished) VALUES (?,?,?,?,?)",
        ("scan_other", "other/repo", "done", 500.0, 510.0),
    )
_main_mod.db_insert_findings("scan_other", [_mk("Z", "HIGH", 90, "Z")])
prev_of_b_again = _main_mod.db_previous_completed_scan("acme/diff", "scan_b")
assert prev_of_b_again and prev_of_b_again["id"] == "scan_a", (
    "cross-org baseline must not leak"
)
print("diff: cross-org isolation — previous only picks same-org scans: ok")

# db_diff_scans set membership.
diff = _main_mod.db_diff_scans("scan_b", "scan_a")
new_ids = {i["id"] for i in diff["new"]}
fixed_ids = {i["id"] for i in diff["fixed"]}
persistent_ids = {i["id"] for i in diff["persistent"]}
changed_ids = {i["id"] for i in diff["severity_changed"]}
assert new_ids == {"D"}, f"new set wrong: {new_ids}"
assert fixed_ids == {"B", "E"}, f"fixed set wrong: {fixed_ids}"
assert persistent_ids == {"A", "C"}, f"persistent set wrong: {persistent_ids}"
# A: confidence 90 -> 95 (delta +5), severity same -> in changed set
# C: severity HIGH -> LOW (delta down), confidence same -> in changed set
assert changed_ids == {"A", "C"}, f"severity_changed wrong: {changed_ids}"

# Severity delta classification.
a_row = next(i for i in diff["persistent"] if i["id"] == "A")
c_row = next(i for i in diff["persistent"] if i["id"] == "C")
assert a_row["severity_delta"] == "same", f"A severity_delta wrong: {a_row['severity_delta']}"
assert a_row["confidence_delta"] == 5, f"A confidence_delta wrong: {a_row['confidence_delta']}"
assert a_row["previous_severity"] == "CRITICAL"
assert a_row["previous_confidence"] == 90
assert c_row["severity_delta"] == "down", f"C severity_delta wrong: {c_row['severity_delta']}"
assert c_row["confidence_delta"] == 0, f"C confidence_delta wrong: {c_row['confidence_delta']}"
assert c_row["previous_severity"] == "HIGH"
print("diff: new/persistent/fixed/severity_changed sets + severity_delta values: ok")

scoped_diff = _main_mod.db_diff_scans(
    "scan_b",
    "scan_a",
    {"script-injection"},
)
assert {i["id"] for i in scoped_diff["fixed"]} == {"B"}
assert all(
    item["category"] == "script-injection"
    for group in ("new", "persistent", "fixed")
    for item in scoped_diff[group]
)
print("diff: partial rule scope does not report unselected categories fixed: ok")

# db_list_scans includes the finding_count. (We can't assert "newest first"
# strictly because _migrate_legacy_data may have copied a pre-existing user
# DB into the tempdir; we assert the shape of the record we control.)
scans_listing = _main_mod.db_list_scans(limit=100)
assert scans_listing, "scans listing should be non-empty"
scan_b_row = next((r for r in scans_listing if r["id"] == "scan_b"), None)
assert scan_b_row is not None, "scan_b must appear in db_list_scans output"
assert scan_b_row["findings_count"] == 3, (
    f"scan_b findings_count wrong: {scan_b_row['findings_count']}"
)
# Ordering: within our controlled scans, scan_b must come before scan_a
# (finished 2010 > 1010).
b_idx = next(i for i, r in enumerate(scans_listing) if r["id"] == "scan_b")
a_idx = next(i for i, r in enumerate(scans_listing) if r["id"] == "scan_a")
assert b_idx < a_idx, f"scan_b should appear before scan_a; got b={b_idx} a={a_idx}"
print("diff: db_list_scans returns finding_count; ordering within controlled scans is newest-first: ok")

# Fixed row must survive `findings` deletion — the diff must still name
# the finding by id even if the DB row for it is gone.
with _main_mod._db() as _c:
    _c.execute("DELETE FROM findings WHERE id = 'B'")
diff_after_delete = _main_mod.db_diff_scans("scan_b", "scan_a")
fixed_after = {i["id"] for i in diff_after_delete["fixed"]}
assert "B" in fixed_after, "fixed set must survive findings-row deletion"
b_row = next(i for i in diff_after_delete["fixed"] if i["id"] == "B")
# The severity/confidence come from the link table snapshot, not from
# the now-deleted findings row.
assert b_row["severity"] == "HIGH", f"link-snapshot severity wrong: {b_row['severity']}"
assert b_row["confidence"] == 82, f"link-snapshot confidence wrong: {b_row['confidence']}"
print("diff: fixed findings survive findings-row deletion (link-table snapshot): ok")


# ============================================================================
# Search bar recognises verdict tags — "true positive", "false positive",
# "unreviewed", `verdict:tp/fp/none`, plus the raw column form
# `true_positive` / `false_positive`.
# ============================================================================
from main import _extract_verdict_from_query  # noqa: E402

# Unit tests on the extractor.
assert _extract_verdict_from_query("") == ("", None)
assert _extract_verdict_from_query("script injection") == ("script injection", None)
# Natural-language forms.
assert _extract_verdict_from_query("true positive") == ("", "true_positive")
assert _extract_verdict_from_query("TRUE POSITIVE") == ("", "true_positive")
assert _extract_verdict_from_query("true_positive") == ("", "true_positive")
assert _extract_verdict_from_query("false positive") == ("", "false_positive")
assert _extract_verdict_from_query("false_positive") == ("", "false_positive")
assert _extract_verdict_from_query("unreviewed") == ("", "unreviewed")
assert _extract_verdict_from_query("not reviewed") == ("", "unreviewed")
# `verdict:` prefix forms.
assert _extract_verdict_from_query("verdict:tp") == ("", "true_positive")
assert _extract_verdict_from_query("verdict: tp") == ("", "true_positive")
assert _extract_verdict_from_query("verdict:false_positive") == ("", "false_positive")
assert _extract_verdict_from_query("verdict:none") == ("", "unreviewed")
# Combined with residual free text — verdict tokens are stripped, rest kept.
res, v = _extract_verdict_from_query("false positive script injection")
assert v == "false_positive", f"verdict wrong: {v}"
assert res == "script injection", f"residual wrong: {res!r}"
res, v = _extract_verdict_from_query("docker true positive gh pr")
assert v == "true_positive"
assert res == "docker gh pr", f"residual wrong: {res!r}"
# Bareword `tp` / `fp` are NOT auto-verdict (would collide with real content).
assert _extract_verdict_from_query("tp") == ("tp", None)
assert _extract_verdict_from_query("fp") == ("fp", None)
print("search: verdict extractor recognises natural-language + verdict: prefix; ignores bare tp/fp: ok")


# End-to-end: the search box filters by manual_verdict.
import tempfile as _tempfile3  # noqa: E402
_search_tmp = _tempfile3.mkdtemp(prefix="grafter-search-smoke-")
_os.environ["GRAFTER_DATA_DIR"] = _search_tmp
importlib.reload(_main_mod)
_main_mod._db_init()

def _mk_sf(id_: str, title: str) -> _main_mod.Finding:
    return _main_mod.Finding(
        id=id_, repo="acme/search", repo_url="https://github.com/acme/search",
        workflow_path=".github/workflows/x.yml", workflow_url="",
        trigger="pull_request_target", severity="CRITICAL",
        exploitability="HIGHLY_EXPLOITABLE", confidence=95,
        title=title, why=["w"], evidence=["e"], remediation=["r"], snippet="s",
        category="script-injection",
    )

_main_mod.db_insert_findings("scan_s", [
    _mk_sf("s_tp",  "TP finding involving docker build"),
    _mk_sf("s_fp",  "FP finding involving azure/login"),
    _mk_sf("s_un1", "Unreviewed with docker build"),
    _mk_sf("s_un2", "Unreviewed with azure/login"),
])
_main_mod.db_update_manual_verdict("s_tp", "true_positive")
_main_mod.db_update_manual_verdict("s_fp", "false_positive")

# 1) Plain search still works — no verdict token, filters by text only.
_, items_docker = _main_mod.db_query_findings(1, 50, q="docker")
docker_ids = {i.id for i in items_docker if i.id.startswith("s_")}
assert docker_ids == {"s_tp", "s_un1"}, f"docker search should return TP + unreviewed docker: {docker_ids}"
print("search: plain query still fans out to content columns: ok")

# 2) `false positive` alone → only FP findings.
_, items_fp = _main_mod.db_query_findings(1, 50, q="false positive")
fp_ids = {i.id for i in items_fp if i.id.startswith("s_")}
assert fp_ids == {"s_fp"}, f"'false positive' should filter to FP: {fp_ids}"
print("search: 'false positive' filters to manual_verdict=false_positive: ok")

# 3) `true positive` alone → only TP findings.
_, items_tp = _main_mod.db_query_findings(1, 50, q="true positive")
tp_ids = {i.id for i in items_tp if i.id.startswith("s_")}
assert tp_ids == {"s_tp"}, f"'true positive' should filter to TP: {tp_ids}"
# Same for the raw column value form.
_, items_tp_raw = _main_mod.db_query_findings(1, 50, q="true_positive")
tp_raw_ids = {i.id for i in items_tp_raw if i.id.startswith("s_")}
assert tp_raw_ids == {"s_tp"}, f"'true_positive' should also filter to TP: {tp_raw_ids}"
print("search: 'true positive' / 'true_positive' both filter to TP: ok")

# 4) `verdict:` prefix works.
_, items_v = _main_mod.db_query_findings(1, 50, q="verdict:fp")
v_ids = {i.id for i in items_v if i.id.startswith("s_")}
assert v_ids == {"s_fp"}, f"'verdict:fp' should filter to FP: {v_ids}"
print("search: 'verdict:fp' prefix filters to FP: ok")

# 5) `unreviewed` → only findings with manual_verdict IS NULL.
_, items_un = _main_mod.db_query_findings(1, 50, q="unreviewed")
un_ids = {i.id for i in items_un if i.id.startswith("s_")}
assert un_ids == {"s_un1", "s_un2"}, f"'unreviewed' should return only null-verdict findings: {un_ids}"
print("search: 'unreviewed' filters to manual_verdict IS NULL: ok")

# 6) Combined — verdict + residual text.
_, items_combo = _main_mod.db_query_findings(1, 50, q="false positive azure")
combo_ids = {i.id for i in items_combo if i.id.startswith("s_")}
assert combo_ids == {"s_fp"}, f"'false positive azure' should return only FP+azure: {combo_ids}"
_, items_un_docker = _main_mod.db_query_findings(1, 50, q="unreviewed docker")
un_docker_ids = {i.id for i in items_un_docker if i.id.startswith("s_")}
assert un_docker_ids == {"s_un1"}, f"'unreviewed docker' should return only unreviewed+docker: {un_docker_ids}"
print("search: combined verdict + residual text intersects both filters: ok")


# ============================================================================
# Export triage JSON — compact per-finding shape for LLM triage agents.
# Verify severity scoping, GitHub link with #L anchor, description
# composition, and filename encodes the severity slug.
# ============================================================================
from fastapi.testclient import TestClient  # noqa: E402
from main import app as _fastapi_app, _triage_finding_dict, _triage_link_for  # noqa: E402

# Build a synthetic finding with known fields to exercise the shape.
_fake = _main_mod.Finding(
    id="tri-1", repo="acme/triage",
    repo_url="https://github.com/acme/triage",
    workflow_path=".github/workflows/build.yml",
    workflow_url="https://github.com/acme/triage/blob/HEAD/.github/workflows/build.yml",
    trigger="pull_request", severity="CRITICAL",
    exploitability="HIGHLY_EXPLOITABLE", confidence=95,
    title="PR-controlled Dockerfile is built on self-hosted runner",
    why=[
        "docker build evaluates RUN instructions during build.",
        "After actions/checkout on a PR trigger, the Dockerfile is attacker-controlled.",
    ],
    evidence=[
        "uses: docker/build-push-action@v2",
        "runs-on: [self-hosted, gpu]",
    ],
    remediation=[
        "Do not build PR-controlled Dockerfiles on self-hosted runners.",
        "Gate the job by author_association.",
    ],
    snippet="  >> 15 |     run: docker buildx build --target output .",
    category="pr-controlled-dockerfile-build",
    tainted_expression="github.event.pull_request.head.sha",
    detected_sink_line="run: docker buildx build --target output .",
    line_number=15,
    gates_detected=["[medium] on.pull_request.branches restricts trigger"],
    manual_verdict=None,
    archived_state=None,
)

# Link builder appends #L anchor when line_number is known.
link = _triage_link_for(_fake)
assert link == "https://github.com/acme/triage/blob/HEAD/.github/workflows/build.yml#L15", (
    f"triage link wrong: {link}"
)

# Line-number None → link is the file URL with no anchor.
_fake_noline = _fake.model_copy(update={"line_number": None})
link_no_anchor = _triage_link_for(_fake_noline)
assert link_no_anchor.endswith("build.yml") and "#L" not in link_no_anchor, (
    f"triage link without line must not carry #L anchor: {link_no_anchor}"
)

# Dict shape — every required field for an agent to reason about the bug.
d = _triage_finding_dict(_fake)
required = {
    "id", "severity", "confidence", "exploitability", "category", "title",
    "repo", "workflow_path", "line", "trigger", "job", "step", "link",
    "tainted_expression", "detected_sink_line", "description", "evidence",
    "remediation", "gates_detected", "manual_verdict", "archived_state",
}
missing = required - set(d.keys())
assert not missing, f"triage dict missing keys: {missing}"
# Description prose ties source and sink together.
assert "docker build evaluates" in d["description"], "description must include why-lines"
assert "Source → sink" in d["description"] or "Source \u2192 sink" in d["description"], (
    "description must include source→sink footer"
)
assert d["tainted_expression"] in d["description"], "tainted expression must appear in description"
assert d["link"].endswith("#L15"), "link must contain #L15 anchor for line-anchored finding"
assert d["severity"] == "CRITICAL"
assert d["evidence"] == ["uses: docker/build-push-action@v2", "runs-on: [self-hosted, gpu]"]
print("triage export: _triage_finding_dict shape + link anchor + description compose: ok")

# End-to-end via TestClient: log in, seed findings, export by severity.
_client = TestClient(_fastapi_app)
_login = _client.post("/api/auth/login", json={"username": _main_mod.AUTH_USERNAME, "password": _main_mod.AUTH_PASSWORD})
assert _login.status_code == 200, f"login failed: {_login.status_code} {_login.text[:200]}"

# Seed two findings at different severities (uses the same tmpdir DB from the
# previous test block).
_main_mod.db_insert_findings("scan_tri", [
    _fake,
    _fake.model_copy(update={"id": "tri-2", "severity": "HIGH", "title": "High-sev sample"}),
])

# format=triage, no severity filter → both findings.
r_all = _client.get("/api/findings/export?format=triage&state=live")
assert r_all.status_code == 200, f"triage export failed: {r_all.status_code} {r_all.text[:200]}"
assert r_all.headers["content-type"].startswith("application/json"), (
    f"unexpected content-type: {r_all.headers['content-type']}"
)
assert "grafter-triage-all.json" in r_all.headers.get("content-disposition", ""), (
    f"filename slug for 'all' wrong: {r_all.headers.get('content-disposition')}"
)
payload_all = r_all.json()
tri_ids_all = {f["id"] for f in payload_all["findings"] if f["id"].startswith("tri-")}
assert tri_ids_all == {"tri-1", "tri-2"}, f"expected both findings without sev filter: {tri_ids_all}"

# format=triage, severity=CRITICAL → only tri-1.
r_crit = _client.get("/api/findings/export?format=triage&state=live&severity=CRITICAL")
assert r_crit.status_code == 200
assert "grafter-triage-critical.json" in r_crit.headers.get("content-disposition", ""), (
    "filename must encode the severity slug"
)
payload_crit = r_crit.json()
tri_ids_crit = {f["id"] for f in payload_crit["findings"] if f["id"].startswith("tri-")}
assert tri_ids_crit == {"tri-1"}, f"severity=CRITICAL should only include tri-1: {tri_ids_crit}"
# Payload records the filter applied so downstream tools know what was scoped.
assert payload_crit["filters"]["severity"] == "CRITICAL"
# Finding shape check inside the payload.
first = next(f for f in payload_crit["findings"] if f["id"] == "tri-1")
assert first["severity"] == "CRITICAL"
assert first["link"].endswith("#L15"), f"link must anchor to line 15: {first['link']}"
assert "docker build" in first["description"].lower()
assert first["tainted_expression"] == "github.event.pull_request.head.sha"
print("triage export: severity filter, filename slug, filter echo, JSON shape: ok")

# Invalid format returns 400.
r_bad = _client.get("/api/findings/export?format=bogus")
assert r_bad.status_code == 400, f"unknown format must return 400: {r_bad.status_code}"
print("triage export: unknown format rejected with 400: ok")
