"""Driver ABC and shared datatypes.

A "driver" knows how to reproduce ONE category of finding end-to-end:
- what payload to inject (as PayloadFile / issue body / comment)
- how to trigger the vulnerable workflow
- which SignalSpecs the watcher should evaluate afterwards
- a boolean success requirement over those signals.

Impact tags are open-vocabulary strings. Any driver can invent a new
tag when a finding claims a new kind of impact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class SignalSpec:
    """Instruction for the watcher: 'observe this thing after the workflow
    completes'. The `signal_type` picks a handler in `poc/watcher.py`.
    """
    id: str  # short local id used by success_requirement
    signal_type: str  # "run_log_regex" | "pr_comment_by_identity_regex" | ...
    tags: list[str] = field(default_factory=list)  # impact tags this signal covers
    description: str = ""  # human-readable for Preview
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class DriverPreviewInfo:
    claim: str
    impact_tags: list[str]
    signals: list[SignalSpec]
    success_requirement: str  # boolean expression over signal ids ("A and (B or C)")
    payload_summary: str  # short human description of what will be pushed
    supports_real_repo_mode: bool = False


@dataclass
class PayloadArtifact:
    """Files the driver wants pushed to the attacker fork before trigger."""
    files: list[Any] = field(default_factory=list)  # list[attacker.PayloadFile]
    commit_message: str = "chore: grafter-poc payload"


@dataclass
class TriggerPlan:
    kind: str  # "pr" | "issue" | "issue_comment" | "workflow_dispatch" | "workflow_run"
    branch: Optional[str] = None
    base_branch: Optional[str] = None
    title: Optional[str] = None
    body: Optional[str] = None
    issue_number: Optional[int] = None
    comment_body: Optional[str] = None
    workflow_id_or_filename: Optional[str] = None
    ref: Optional[str] = None
    dispatch_inputs: Optional[dict] = None
    workflow_run_wait_after_pr: bool = False


class Driver:
    """Every category driver subclasses this."""

    category: str = ""
    default_impact_tags: list[str] = []
    supports_real_repo_mode: bool = False

    def preview(self, finding: dict, marker: str) -> DriverPreviewInfo:  # pragma: no cover - override
        raise NotImplementedError

    def build_payload(self, finding: dict, marker: str) -> PayloadArtifact:  # pragma: no cover
        raise NotImplementedError

    def build_trigger(self, finding: dict, marker: str) -> TriggerPlan:  # pragma: no cover
        raise NotImplementedError


# Registry populated by each driver module on import.
_REGISTRY: dict[str, Driver] = {}


def register(driver: Driver) -> Driver:
    if not driver.category:
        raise ValueError("driver.category must be non-empty")
    _REGISTRY[driver.category] = driver
    return driver


def driver_for(category: Optional[str]) -> Optional[Driver]:
    if not category:
        return None
    return _REGISTRY.get(category)


def registered_categories() -> list[str]:
    return sorted(_REGISTRY.keys())
