"""Drivers for `comment-command-pr-checkout` and `comment-trigger-write-scope`.

Attacker opens a draft PR (from a fork), then posts a comment on it
whose body matches the trigger phrase the workflow listens for
(`/deploy`, `/test`, `.bench`, etc.). The comment body carries the
marker in a way the vulnerable workflow will echo, and any privileged
step running under `GITHUB_TOKEN` is expected to leak the marker into
the run log.
"""
from __future__ import annotations

from ..attacker import PayloadFile
from .base import (
    Driver,
    DriverPreviewInfo,
    PayloadArtifact,
    SignalSpec,
    TriggerPlan,
    register,
)


def _marker_comment(marker: str, trigger_phrase: str) -> str:
    return (
        f"{trigger_phrase} GRAFTER_MARKER_{marker}\n\n"
        "grafter-poc probe — benign marker; no code changes."
    )


class CommentCommandDriver(Driver):
    category = "comment-command-pr-checkout"
    default_impact_tags = ["metadata_write", "rce"]

    def preview(self, finding: dict, marker: str) -> DriverPreviewInfo:
        signals = [
            SignalSpec(
                id="marker_in_log",
                signal_type="run_log_regex",
                tags=["metadata_write", "rce"],
                description=f"workflow run log contains `GRAFTER_MARKER_{marker}`",
                params={"regex": f"GRAFTER_MARKER_{marker}"},
            ),
            SignalSpec(
                id="side_effect_comment",
                signal_type="pr_comment_by_gh_token_regex",
                tags=["rce", "metadata_write"],
                description="base-repo GITHUB_TOKEN posted a comment mentioning the marker",
                params={"regex": f"GRAFTER_MARKER_{marker}"},
            ),
        ]
        return DriverPreviewInfo(
            claim=(
                "A PR comment from an unprivileged attacker triggers the "
                "privileged comment-driven workflow, which then checks out "
                "and/or executes code the attacker controls."
            ),
            impact_tags=list(self.default_impact_tags),
            signals=signals,
            success_requirement="marker_in_log",
            payload_summary=(
                "Open a placeholder draft PR from the attacker fork against "
                "the mirror, then post a comment whose body carries the "
                "marker after the trigger phrase (`/deploy GRAFTER_MARKER_…`)."
            ),
            supports_real_repo_mode=False,
        )

    def build_payload(self, finding: dict, marker: str) -> PayloadArtifact:
        return PayloadArtifact(
            files=[
                PayloadFile(
                    path="grafter-poc-placeholder.md",
                    content=b"grafter-poc placeholder file (no code change)\n",
                )
            ],
            commit_message=f"grafter-poc placeholder {marker}",
        )

    def build_trigger(self, finding: dict, marker: str) -> TriggerPlan:
        # We first open a PR, then add a comment on it — the orchestrator
        # currently only handles pr/issue/issue_comment kinds. Use the
        # kind `pr` and rely on the follow-up comment being added by the
        # driver-aware orchestrator when it recognises this category.
        # For MVP: signal via `comment_body` — orchestrator posts it after PR.
        return TriggerPlan(
            kind="pr",
            branch=f"grafter-poc-{marker}",
            base_branch="main",
            title=f"Grafter Live PoC comment-command {marker}",
            body="Grafter Live PoC — placeholder PR; marker will be posted as a comment.",
            comment_body=_marker_comment(marker, trigger_phrase="/deploy"),
        )


class CommentTriggerWriteScopeDriver(CommentCommandDriver):
    category = "comment-trigger-write-scope"


register(CommentCommandDriver())
register(CommentTriggerWriteScopeDriver())
