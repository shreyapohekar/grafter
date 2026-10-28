"""Smoke tests for the two rules added from the Wiz GitHub Actions guide gap
analysis: `living-off-the-pipeline` and `secrets-context-wholesale`.

Run:  .venv\\Scripts\\python.exe _smoke_wiz_rules.py
"""
import sys

from main import analyze_workflow

REPO = "acme/x"
URL = "https://github.com/acme/x"
WF = ".github/workflows/x.yml"


def _find(findings, category):
    return [f for f in findings if f.category == category]


def _has(findings, category):
    return bool(_find(findings, category))


def _run(wf):
    return analyze_workflow(REPO, URL, WF, wf)


# ---------------------------------------------------------------------------
# LOTP
# ---------------------------------------------------------------------------

def test_lotp_prt_precommit_is_critical():
    wf = """
name: lint
on:
  pull_request_target:
jobs:
  lint:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: pre-commit run --all-files
"""
    f = _find(_run(wf), "living-off-the-pipeline")
    assert f, "expected LOTP finding for pull_request_target + pre-commit"
    assert f[0].severity == "CRITICAL", f[0].severity
    assert f[0].exploitability == "HIGHLY_EXPLOITABLE", f[0].exploitability
    assert ".pre-commit-config.yaml" in " ".join(f[0].evidence)
    print("PASS lotp_prt_precommit_is_critical", f[0].severity, f[0].confidence)


def test_lotp_pytest_conftest_self_hosted():
    wf = """
name: test
on:
  pull_request:
jobs:
  test:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v4
      - run: pytest -q
"""
    f = _find(_run(wf), "living-off-the-pipeline")
    assert f, "expected LOTP finding for self-hosted pytest"
    assert f[0].severity == "HIGH", f[0].severity
    assert "conftest.py" in " ".join(f[0].evidence)
    print("PASS lotp_pytest_conftest_self_hosted", f[0].severity, f[0].confidence)


def test_lotp_hosted_pr_no_creds_is_suppressed():
    """The Grafter philosophy case: real execution, but a throwaway sandbox
    with no credentials. Must be recorded but below the dashboard threshold."""
    wf = """
name: lint
on:
  pull_request:
jobs:
  lint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - run: eslint .
"""
    f = _find(_run(wf), "living-off-the-pipeline")
    assert f, "expected LOTP finding to be recorded"
    assert f[0].confidence < 80, f"should be below dashboard threshold, got {f[0].confidence}"
    assert f[0].severity == "LOW", f[0].severity
    print("PASS lotp_hosted_pr_no_creds_is_suppressed", f[0].severity, f[0].confidence)


def test_lotp_hosted_pr_with_oidc_capped_by_fork_blanking():
    """A hosted `pull_request` job is capped at MEDIUM by the global
    fork-PR downgrade even with `id-token: write` declared, because GitHub
    blanks secrets and read-onlys GITHUB_TOKEN for fork PRs. The rule must
    still fire and still record the credential context."""
    wf = """
name: build
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
      - run: ./gradlew build
"""
    f = _find(_run(wf), "living-off-the-pipeline")
    assert f, "expected LOTP finding for credentialed hosted PR job"
    assert f[0].severity == "MEDIUM", f[0].severity
    assert f[0].exploitability == "CONDITIONAL", f[0].exploitability
    assert any("build.gradle" in e for e in f[0].evidence), f[0].evidence
    print("PASS lotp_hosted_pr_with_oidc_capped_by_fork_blanking",
          f[0].severity, f[0].confidence)


def test_lotp_prt_with_oidc_stays_critical():
    """`pull_request_target` is NOT subject to the fork-blanking downgrade —
    base-repo secrets really are in scope."""
    wf = """
name: build
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: mvn verify
"""
    f = _find(_run(wf), "living-off-the-pipeline")
    assert f, "expected LOTP finding"
    assert f[0].severity == "CRITICAL", f[0].severity
    assert f[0].confidence >= 80, f[0].confidence
    print("PASS lotp_prt_with_oidc_stays_critical", f[0].severity, f[0].confidence)


def test_lotp_no_checkout_not_flagged():
    """No PR-controlled code => the tool only ever sees trusted config."""
    wf = """
name: lint
on:
  push:
    branches: [main]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pre-commit run --all-files
"""
    assert not _has(_run(wf), "living-off-the-pipeline"), \
        "push trigger must not produce a LOTP finding"
    print("PASS lotp_no_checkout_not_flagged")


def test_lotp_strong_gate_downgrades():
    """`author_association` is a STRONG gate (unlike `environment:`, which
    Grafter rates MEDIUM because required reviewers cannot be verified from
    the YAML alone)."""
    wf = """
name: lint
on:
  pull_request_target:
jobs:
  lint:
    runs-on: ubuntu-latest
    if: github.event.pull_request.author_association == 'MEMBER'
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: pytest
"""
    f = _find(_run(wf), "living-off-the-pipeline")
    assert f, "expected LOTP finding"
    assert f[0].exploitability == "CONDITIONAL", f[0].exploitability
    assert f[0].confidence <= 65, f[0].confidence
    print("PASS lotp_strong_gate_downgrades", f[0].severity, f[0].confidence)


def test_lotp_environment_gate_is_medium_not_strong():
    """Regression guard: `environment:` alone must NOT be treated as strong."""
    wf = """
name: lint
on:
  pull_request_target:
jobs:
  lint:
    runs-on: ubuntu-latest
    environment: manual-approval
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: pytest
"""
    f = _find(_run(wf), "living-off-the-pipeline")
    assert f, "expected LOTP finding"
    assert f[0].exploitability == "HIGHLY_EXPLOITABLE", f[0].exploitability
    print("PASS lotp_environment_gate_is_medium_not_strong",
          f[0].severity, f[0].confidence)


# ---------------------------------------------------------------------------
# toJSON(secrets)
# ---------------------------------------------------------------------------

def test_secrets_wholesale_tojson_env():
    wf = """
name: deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      ALL_SECRETS: ${{ toJSON(secrets) }}
    steps:
      - run: ./deploy.sh
"""
    f = _find(_run(wf), "secrets-context-wholesale")
    assert f, "expected toJSON(secrets) finding"
    assert "toJSON(secrets)" in " ".join(f[0].evidence)
    print("PASS secrets_wholesale_tojson_env", f[0].severity, f[0].confidence)


def test_secrets_wholesale_tojson_lowercase_spelling():
    wf = """
name: x
on:
  workflow_dispatch:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$BLOB"
        env:
          BLOB: ${{ toJson(secrets) }}
"""
    assert _has(_run(wf), "secrets-context-wholesale"), \
        "the `toJson` spelling must also be detected"
    print("PASS secrets_wholesale_tojson_lowercase_spelling")


def test_secrets_wholesale_with_pr_checkout_is_critical():
    wf = """
name: x
on:
  pull_request_target:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
        env:
          EVERYTHING: ${{ toJSON(secrets) }}
"""
    f = _find(_run(wf), "secrets-context-wholesale")
    assert f, "expected finding"
    assert f[0].severity == "CRITICAL", f[0].severity
    assert f[0].exploitability == "HIGHLY_EXPLOITABLE", f[0].exploitability
    print("PASS secrets_wholesale_with_pr_checkout_is_critical", f[0].confidence)


def test_secrets_named_access_not_flagged():
    wf = """
name: x
on:
  push:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
          OTHER: ${{ secrets.OTHER_TOKEN }}
"""
    assert not _has(_run(wf), "secrets-context-wholesale"), \
        "individually named secrets must NOT be flagged"
    print("PASS secrets_named_access_not_flagged")


def test_secrets_wholesale_bare_context():
    wf = """
name: x
on:
  push:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: some/action@v1
        with:
          creds: ${{ secrets }}
"""
    assert _has(_run(wf), "secrets-context-wholesale"), \
        "bare `${{ secrets }}` context must be detected"
    print("PASS secrets_wholesale_bare_context")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
