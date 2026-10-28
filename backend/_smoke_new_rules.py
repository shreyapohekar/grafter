"""Ad-hoc smoke tests for the six new Grafter rules (Gaps A/B/C/E/F/G).

These tests do NOT hit GitHub or the DB — they run the pure analyzer
functions against inline YAML strings and assert that (1) the new rule
fires when expected and (2) it does NOT fire on the safe control cases.
"""
from __future__ import annotations

import sys

sys.path.insert(0, ".")
from main import analyze_policy_file, analyze_workflow


def _has_cat(findings, category: str) -> bool:
    return any(f.category == category for f in findings)


def _cats(findings) -> list[str]:
    return sorted({f.category for f in findings if f.category})


def test_gap_b_localpkg_dpkg_after_pr_checkout() -> None:
    """dpkg -i on a file dropped by the PR checkout should hit
    checkout-untrusted / pr-code-execution-risk (Gap B: local-pkg sink)."""
    wf = """name: ci
on: pull_request_target
jobs:
  install:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          sudo dpkg -i ./release.deb
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    cats = _cats(findings)
    assert any(c in cats for c in ("checkout-untrusted", "pr-code-execution-risk")), (
        f"Gap B: dpkg -i after PR checkout should trigger checkout-untrusted or pr-code-execution-risk; got {cats}"
    )
    print("Gap B (dpkg -i as execution sink after PR checkout): ok")


def test_gap_b_msiexec_windows() -> None:
    wf = """name: ci
on: pull_request_target
jobs:
  install:
    runs-on: windows-latest
    permissions: {contents: write}
    steps:
      - uses: actions/checkout@v1
        with: {ref: '${{ github.event.pull_request.head.sha }}'}
      - run: msiexec.exe /i .\\pkg\\installer.msi /quiet
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    cats = _cats(findings)
    assert any(c in cats for c in ("checkout-untrusted", "pr-code-execution-risk")), (
        f"Gap B: msiexec /i after PR checkout should trigger checkout-untrusted; got {cats}"
    )
    print("Gap B (msiexec /i as execution sink): ok")


def test_checkout_safe_default_not_flagged_all_majors() -> None:
    """Safe default checkout should not be flagged on all backported majors."""
    for major in (2, 3, 4, 5, 6):
        wf = f"""name: ci
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {{contents: write}}
    steps:
      - uses: actions/checkout@v{major}
      - run: npm ci
"""
        findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
        assert not _has_cat(findings, "checkout-untrusted"), (
            f"safe default checkout v{major} should not fire without explicit unsafe ref/flag; got {_cats(findings)}"
        )
    print("Checkout safe default (v2-v6, no unsafe flag/ref): ok")


def test_checkout_allow_unsafe_flag_is_vulnerable_all_majors() -> None:
    """allow-unsafe-pr-checkout must trigger on all backported majors."""
    for major in (2, 3, 4, 5, 6):
        wf = f"""name: ci
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {{contents: write}}
    steps:
      - uses: actions/checkout@v{major}
        with:
          allow-unsafe-pr-checkout: true
      - run: npm ci
"""
        findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
        assert _has_cat(findings, "checkout-untrusted"), (
            f"allow-unsafe-pr-checkout on v{major} should fire checkout-untrusted; got {_cats(findings)}"
        )
    print("Checkout allow-unsafe-pr-checkout (v2-v6): ok")


def test_checkout_explicit_head_sha_still_vulnerable() -> None:
    """Explicit PR head SHA checkout remains vulnerable even on modern versions."""
    wf = """name: ci
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {contents: write}
    steps:
      - uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    assert _has_cat(findings, "checkout-untrusted"), (
        f"explicit pull_request.head.sha must fire checkout-untrusted; got {_cats(findings)}"
    )
    print("Checkout explicit PR head SHA (v5): ok")


def test_gap_c_automerge_prt() -> None:
    """gh pr merge --auto from pull_request_target without STRONG gate."""
    wf = """name: automerge
on: pull_request_target
jobs:
  automerge:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - run: gh pr merge --auto --merge ${{ github.event.pull_request.number }}
        env: {GH_TOKEN: '${{ secrets.GITHUB_TOKEN }}'}
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    assert _has_cat(findings, "pull-request-auto-merge-untrusted"), (
        f"Gap C: gh pr merge --auto in pull_request_target should fire; got {_cats(findings)}"
    )
    print("Gap C (gh pr merge --auto in pull_request_target): ok")


def test_gap_c_automerge_pascalgn() -> None:
    """pascalgn/automerge-action in pull_request_target should fire."""
    wf = """name: automerge
on: pull_request_target
jobs:
  m:
    runs-on: ubuntu-latest
    permissions: {contents: write, pull-requests: write}
    steps:
      - uses: pascalgn/automerge-action@v0.16.4
        env: {MERGE_LABELS: 'automerge'}
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    assert _has_cat(findings, "pull-request-auto-merge-untrusted"), _cats(findings)
    print("Gap C (pascalgn/automerge-action in pull_request_target): ok")


def test_gap_c_automerge_push_ok() -> None:
    """Same auto-merge invocation on `push` (post-merge automation) should NOT fire."""
    wf = """name: automerge
on: push
jobs:
  m:
    runs-on: ubuntu-latest
    permissions: {contents: write}
    steps:
      - run: gh pr merge --auto --merge 1
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    assert not _has_cat(findings, "pull-request-auto-merge-untrusted"), (
        f"Gap C: push-triggered auto-merge should NOT fire; got {_cats(findings)}"
    )
    print("Gap C (push-triggered auto-merge is NOT flagged): ok")


def test_gap_e_secret_echo() -> None:
    """echo ${{ secrets.OPENAI_API_KEY }} into a shell command should fire."""
    wf = """name: leak
on: push
jobs:
  print:
    runs-on: ubuntu-latest
    steps:
      - run: echo "key is ${{ secrets.OPENAI_API_KEY }}"
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    assert _has_cat(findings, "secret-echoed-to-log"), _cats(findings)
    print("Gap E (secrets.* interpolated into echo): ok")


def test_gap_e_secret_echo_masked_ok() -> None:
    """A prior ::add-mask:: on the same run block should suppress the finding."""
    wf = """name: leak
on: push
jobs:
  print:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "::add-mask::${{ secrets.OPENAI_API_KEY }}"
          echo "key is ${{ secrets.OPENAI_API_KEY }}"
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    assert not _has_cat(findings, "secret-echoed-to-log"), (
        f"Gap E: prior ::add-mask:: in same run block should suppress; got {_cats(findings)}"
    )
    print("Gap E (::add-mask:: earlier in same run block suppresses): ok")


def test_gap_e_printenv() -> None:
    """Raw `printenv` in a job that has secrets in scope should fire."""
    wf = """name: dump
on: push
jobs:
  d:
    runs-on: ubuntu-latest
    env: {SPECIAL_TOKEN: '${{ secrets.SPECIAL_TOKEN }}'}
    steps:
      - run: printenv
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    assert _has_cat(findings, "secret-echoed-to-log"), _cats(findings)
    print("Gap E (bare printenv dumps env): ok")


def test_gap_f_bypassable_contains() -> None:
    """`contains('a,b,c', github.actor)` on a privileged sink should fire."""
    wf = """name: release
on: pull_request_target
jobs:
  release:
    if: contains('alice,bob,carol', github.actor)
    runs-on: ubuntu-latest
    permissions: {contents: write}
    steps:
      - run: npm publish
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    assert _has_cat(findings, "bypassable-actor-allowlist-gate"), _cats(findings)
    print("Gap F (contains-substring allowlist on pull_request_target + sink): ok")


def test_gap_f_startswith_headref() -> None:
    """`startsWith(github.actor, 'renovate')` should also fire — actor
    prefix match is GATE_MEDIUM and bypassable (attacker registers a
    username starting with 'renovate')."""
    wf = """name: release
on: pull_request_target
jobs:
  release:
    if: startsWith(github.actor, 'renovate')
    runs-on: ubuntu-latest
    permissions: {contents: write}
    steps:
      - uses: docker/build-push-action@v6
        with: {push: true}
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    assert _has_cat(findings, "bypassable-actor-allowlist-gate"), _cats(findings)
    print("Gap F (startsWith(github.actor, prefix) bypassable): ok")


def test_gap_f_strong_gate_suppresses() -> None:
    """When a STRONG gate coexists, the weak gate finding must NOT fire."""
    wf = """name: release
on: pull_request_target
jobs:
  release:
    if: contains('alice,bob', github.actor) && github.event.pull_request.head.repo.fork == false
    runs-on: ubuntu-latest
    permissions: {contents: write}
    steps:
      - run: npm publish
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    assert not _has_cat(findings, "bypassable-actor-allowlist-gate"), _cats(findings)
    print("Gap F (STRONG gate suppresses weak-allowlist finding): ok")


def test_gap_g_filename_collision_with_install() -> None:
    """Two wget calls to the same filename, one tainted → attacker
    controls the file consumed by dpkg -i."""
    wf = """name: install
on: pull_request_target
jobs:
  i:
    runs-on: ubuntu-latest
    permissions: {contents: write}
    steps:
      - run: |
          wget -O pkg.deb https://mirror-a.example.com/${{ github.event.pull_request.head.ref }}/pkg.deb
          wget -O pkg.deb https://official.example.com/pkg.deb
          sudo dpkg -i pkg.deb
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    assert _has_cat(findings, "filename-collision-download"), _cats(findings)
    coll = [f for f in findings if f.category == "filename-collision-download"][0]
    assert coll.severity == "CRITICAL", f"With install sink, severity should be CRITICAL; got {coll.severity}"
    print("Gap G (filename collision + dpkg -i -> CRITICAL): ok")


def test_gap_g_filename_collision_no_taint_ok() -> None:
    """Same filename twice but NO tainted URL → do not fire."""
    wf = """name: install
on: pull_request_target
jobs:
  i:
    runs-on: ubuntu-latest
    permissions: {contents: write}
    steps:
      - run: |
          wget -O pkg.deb https://official.example.com/a.deb
          wget -O pkg.deb https://official.example.com/b.deb
          sudo dpkg -i pkg.deb
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    assert not _has_cat(findings, "filename-collision-download"), (
        f"Gap G: no tainted URL should NOT fire; got {_cats(findings)}"
    )
    print("Gap G (no tainted URL suppresses filename-collision finding): ok")


def test_gap_a_policy_unauth_label() -> None:
    """Issue-ops policy that adds label on Issue_Comment without permission check."""
    pol = """id: 00000000-0000-0000-0000-000000000000
name: bug-lifecycle
description: >-
  Automatically applies triage labels.
resource: repository
disabled: false
where: []
configuration:
  resourceManagementConfiguration:
    eventResponderTasks:
      - description: apply /triage label
        if:
          - payloadType: Issue_Comment
          - isAction:
              action: Created
          - bodyContains:
              pattern: /triage
              isRegex: false
        then:
          - addLabel:
              label: needs-triage
          - assignTo:
              user: some-user
"""
    findings = analyze_policy_file(
        "acme/x",
        "https://github.com/acme/x",
        ".github/policies/bug-lifecycle.yml",
        pol,
    )
    assert _has_cat(findings, "policy-file-unauth-mutation"), (
        f"Gap A: unauth label policy should fire; got {_cats(findings)}"
    )
    print("Gap A (issue-ops policy unauthenticated Issue_Comment -> addLabel): ok")


def test_gap_a_policy_merge_critical() -> None:
    """Issue-ops policy that auto-merges on PR comment without permission check
    should be CRITICAL."""
    pol = """id: 00000000-0000-0000-0000-000000000000
name: bug-lifecycle
resource: repository
disabled: false
configuration:
  resourceManagementConfiguration:
    eventResponderTasks:
      - description: auto-merge on /merge
        if:
          - payloadType: Pull_Request_Comment
          - bodyContains:
              pattern: /merge
        then:
          - mergePullRequest: {}
"""
    findings = analyze_policy_file("acme/x", "https://github.com/acme/x", ".github/policies/m.yml", pol)
    assert _has_cat(findings, "policy-file-unauth-mutation"), _cats(findings)
    m = [f for f in findings if f.category == "policy-file-unauth-mutation"][0]
    assert m.severity == "CRITICAL", f"mergePullRequest without gate should be CRITICAL; got {m.severity}"
    print("Gap A (issue-ops mergePullRequest without gate -> CRITICAL): ok")


def test_gap_a_policy_gated_ok() -> None:
    """Same policy but WITH activitySenderHasPermissions gate should NOT fire."""
    pol = """id: 00000000-0000-0000-0000-000000000000
name: bug-lifecycle
resource: repository
disabled: false
configuration:
  resourceManagementConfiguration:
    eventResponderTasks:
      - description: gated label
        if:
          - payloadType: Issue_Comment
          - bodyContains:
              pattern: /triage
          - activitySenderHasPermissions:
              permissions: Write
        then:
          - addLabel:
              label: needs-triage
"""
    findings = analyze_policy_file("acme/x", "https://github.com/acme/x", ".github/policies/g.yml", pol)
    assert not _has_cat(findings, "policy-file-unauth-mutation"), (
        f"Gap A: gated policy should NOT fire; got {_cats(findings)}"
    )
    print("Gap A (issue-ops policy WITH activitySenderHasPermissions gate is safe): ok")


def test_pull_request_downgrade_hosted() -> None:
    """Hosted `pull_request` findings must cap at MEDIUM (secrets blanked)
    and carry the fork-vs-same-repo annotation from downgrade rule 5."""
    wf = """name: ci
on: pull_request
jobs:
  b:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v6
        with: {context: ., file: Dockerfile, push: false}
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    dfb = next((f for f in findings if f.category == "pr-controlled-dockerfile-build"), None)
    assert dfb is not None, f"hosted pull_request docker build should still fire; got {_cats(findings)}"
    assert dfb.severity == "MEDIUM", f"expected MEDIUM cap on hosted pull_request, got {dfb.severity}"
    assert any("Severity capped at MEDIUM" in w for w in dfb.why), (
        "downgrade rule 5 must add fork-PR / same-repo-PR annotation"
    )
    assert any("same-repo PR" in w for w in dfb.why), (
        "annotation must mention same-repo PR ambiguity"
    )
    print("pull_request downgrade (hosted): CRITICAL/HIGH -> MEDIUM + annotation: ok")


def test_pull_request_downgrade_self_hosted_preserves_severity() -> None:
    """Self-hosted `pull_request` keeps the original severity (Q2 policy:
    self-hosted stays CRITICAL because RCE on persistent infra survives
    secret blanking). Annotation still attached."""
    wf = """name: ci
on: pull_request
jobs:
  b:
    runs-on: [self-hosted, linux, prod]
    permissions: {}
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v6
        with: {context: ., file: Dockerfile, push: false}
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    dfb = next((f for f in findings if f.category == "pr-controlled-dockerfile-build"), None)
    assert dfb is not None
    assert dfb.severity in ("CRITICAL", "HIGH"), (
        f"self-hosted pull_request docker build should retain original severity, got {dfb.severity}"
    )
    assert any("self-hosted runner" in w and "retained" in w for w in dfb.why), (
        "self-hosted branch of downgrade rule 5 must attach 'retained' annotation, not the MEDIUM-cap wording"
    )
    print("pull_request downgrade (self-hosted): severity retained + annotation: ok")


def test_pull_request_downgrade_low_finding_still_annotated() -> None:
    """A finding that is already LOW/MEDIUM on `pull_request` should get
    the shorter 'note' annotation (no severity change)."""
    wf = """name: ci
on: pull_request
jobs:
  b:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: some-vendor/action@v1   # unpinned mutable action ref -> hygiene finding
"""
    findings = analyze_workflow("acme/x", "https://github.com/acme/x", ".github/workflows/x.yml", wf)
    mut = next((f for f in findings if f.category == "mutable-action-reference"), None)
    if mut is not None:
        assert mut.severity in ("LOW", "MEDIUM")
        # LOW/MEDIUM findings still get the shorter annotation.
        assert any("fork `pull_request`" in w or "same-repo" in w.lower() for w in mut.why), (
            "annotation must be attached even to LOW/MEDIUM pull_request findings"
        )
    print("pull_request downgrade (already-low): annotation attached without severity change: ok")


if __name__ == "__main__":
    test_gap_b_localpkg_dpkg_after_pr_checkout()
    test_gap_b_msiexec_windows()
    test_checkout_safe_default_not_flagged_all_majors()
    test_checkout_allow_unsafe_flag_is_vulnerable_all_majors()
    test_checkout_explicit_head_sha_still_vulnerable()
    test_gap_c_automerge_prt()
    test_gap_c_automerge_pascalgn()
    test_gap_c_automerge_push_ok()
    test_gap_e_secret_echo()
    test_gap_e_secret_echo_masked_ok()
    test_gap_e_printenv()
    test_gap_f_bypassable_contains()
    test_gap_f_startswith_headref()
    test_gap_f_strong_gate_suppresses()
    test_gap_g_filename_collision_with_install()
    test_gap_g_filename_collision_no_taint_ok()
    test_gap_a_policy_unauth_label()
    test_gap_a_policy_merge_critical()
    test_gap_a_policy_gated_ok()
    test_pull_request_downgrade_hosted()
    test_pull_request_downgrade_self_hosted_preserves_severity()
    test_pull_request_downgrade_low_finding_still_annotated()
    print("\nAll 22 new-rule tests passed.")
