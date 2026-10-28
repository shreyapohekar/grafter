"""Pydantic models + shared enums for the Live PoC feature."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# States (state-machine)
# ---------------------------------------------------------------------------
STATE_QUEUED = "queued"
STATE_PREFLIGHT = "preflight"
STATE_MIRROR = "mirror"
STATE_INJECT = "inject"
STATE_TRIGGER = "trigger"
STATE_WATCH = "watch"
STATE_VERDICT = "verdict"
STATE_CLEANUP = "cleanup"
STATE_DONE = "done"
STATE_FAILED = "failed"
STATE_CANCELLED = "cancelled"

TERMINAL_STATES = frozenset({STATE_DONE, STATE_FAILED, STATE_CANCELLED})

STATE_ORDER = [
    STATE_QUEUED,
    STATE_PREFLIGHT,
    STATE_MIRROR,
    STATE_INJECT,
    STATE_TRIGGER,
    STATE_WATCH,
    STATE_VERDICT,
    STATE_CLEANUP,
    STATE_DONE,
]

# Verdicts
VERDICT_CONFIRMED = "confirmed"
VERDICT_WEAK_REPRO = "weak_repro"
VERDICT_NOT_REPRODUCED = "not_reproduced"
VERDICT_BLOCKED_BY_GATE = "blocked_by_gate"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_ERROR = "error"

VALID_VERDICTS = frozenset({
    VERDICT_CONFIRMED,
    VERDICT_WEAK_REPRO,
    VERDICT_NOT_REPRODUCED,
    VERDICT_BLOCKED_BY_GATE,
    VERDICT_INCONCLUSIVE,
    VERDICT_ERROR,
})


# ---------------------------------------------------------------------------
# Token store
# ---------------------------------------------------------------------------
class LivePocIdentity(BaseModel):
    """One of the two GitHub identities plus optional canary token."""
    login: Optional[str] = None
    preview: Optional[str] = None
    saved_at: Optional[float] = None


class LivePocCanary(BaseModel):
    kind: Optional[str] = None  # "aws" | "http" | "dns" | ...
    label: Optional[str] = None
    preview: Optional[str] = None
    history_url: Optional[str] = None
    saved_at: Optional[float] = None


class LivePocTokensInfo(BaseModel):
    maintainer: Optional[LivePocIdentity] = None
    attacker: Optional[LivePocIdentity] = None
    canary: Optional[LivePocCanary] = None


class SaveLivePocTokensRequest(BaseModel):
    maintainer_token: Optional[str] = None
    attacker_token: Optional[str] = None
    canary_token: Optional[str] = None
    canary_kind: Optional[str] = None
    canary_label: Optional[str] = None
    canary_history_url: Optional[str] = None


# ---------------------------------------------------------------------------
# Run models
# ---------------------------------------------------------------------------
class PocRunLogLine(BaseModel):
    ts: float
    phase: str
    level: str = "info"  # info | warn | error
    message: str


class PocRunSignal(BaseModel):
    """One observed piece of evidence during watch."""
    signal_type: str
    when: float
    where: Optional[str] = None
    matched_by: Optional[str] = None  # human-readable "which criterion"
    tags: list[str] = Field(default_factory=list)  # impact tags this signal covers
    details: dict[str, Any] = Field(default_factory=dict)


class PocRun(BaseModel):
    id: str
    finding_id: str
    category: Optional[str] = None
    claim: Optional[str] = None
    impact_class: list[str] = Field(default_factory=list)
    proven_impact: list[str] = Field(default_factory=list)
    success_requirement: Optional[str] = None
    mirror_mode: Optional[str] = None  # "full" | "minimal"
    mirror_manifest: Optional[list[dict[str, Any]]] = None
    state: str
    verdict: Optional[str] = None
    started: Optional[float] = None
    finished: Optional[float] = None
    marker: str
    mirror_owner: Optional[str] = None
    mirror_repo: Optional[str] = None
    attacker_owner: Optional[str] = None
    attacker_fork: Optional[str] = None
    workflow_run_id: Optional[int] = None
    workflow_run_url: Optional[str] = None
    logs: list[PocRunLogLine] = Field(default_factory=list)
    evidence: list[PocRunSignal] = Field(default_factory=list)
    opt_in_real_repo: bool = False
    canary_kind: Optional[str] = None
    error: Optional[str] = None


class StartLivePocRequest(BaseModel):
    use_real_repo: bool = False
    keep_repos: bool = False
    force_minimal_mirror: bool = False


class LivePocRunSummary(BaseModel):
    active: int
    terminal_last_24h: int
    stuck: int


class LivePocRunListItem(BaseModel):
    id: str
    finding_id: str
    finding_title: Optional[str] = None
    finding_repo: Optional[str] = None
    category: Optional[str] = None
    claim: Optional[str] = None
    state: str
    verdict: Optional[str] = None
    started: Optional[float] = None
    finished: Optional[float] = None
    proven_impact: list[str] = Field(default_factory=list)
    workflow_run_url: Optional[str] = None
    mirror_owner: Optional[str] = None
    mirror_repo: Optional[str] = None


class LivePocRunListPage(BaseModel):
    total: int
    items: list[LivePocRunListItem]


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
class PreflightCheck(BaseModel):
    name: str
    ok: bool
    detail: Optional[str] = None
    fix: Optional[str] = None


class PreflightResult(BaseModel):
    ok: bool
    checks: list[PreflightCheck]


# ---------------------------------------------------------------------------
# Driver preview
# ---------------------------------------------------------------------------
class DriverPreview(BaseModel):
    category: str
    claim: str
    impact_tags: list[str]
    success_criteria: list[str]  # human-readable list ("we will confirm this when...")
    signals: list[str]  # human-readable signal descriptions
    payload_summary: str
    supports_real_repo_mode: bool = False
