"""Live PoC orchestrator.

One entry point per PoC run. Owns a single `poc_runs` row from queued →
done/failed/cancelled with a `finally`-block cleanup. Runs in an
`asyncio.Task` background task; the API just kicks the task off and
polls `poc_runs` for state.
"""
from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from typing import Any, Optional

import httpx

from . import attacker as att
from . import db as pdb
from . import mirror as pm
from . import tokens as pt
from . import watcher as pw
from .drivers.base import Driver, TriggerPlan, driver_for
from .models import (
    PocRun,
    PreflightCheck,
    PreflightResult,
    STATE_CLEANUP,
    STATE_DONE,
    STATE_FAILED,
    STATE_INJECT,
    STATE_MIRROR,
    STATE_PREFLIGHT,
    STATE_TRIGGER,
    STATE_VERDICT,
    STATE_WATCH,
    VERDICT_CONFIRMED,
    VERDICT_ERROR,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_REPRODUCED,
    VERDICT_WEAK_REPRO,
)


DEFAULT_TIMEOUT_S = int(20 * 60)

# One in-flight PoC at a time per process (matches the plan).
_RUN_LOCK = asyncio.Lock()

# run_id -> asyncio.Task
_TASKS: dict[str, asyncio.Task] = {}


def _mk_marker() -> str:
    return uuid.uuid4().hex[:12]


def _log_factory(run_id: str, phase_holder: dict):
    def _log(level: str, message: str) -> None:
        pdb.append_log(run_id, phase_holder.get("phase", "?"), message, level=level)
    return _log


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
async def run_preflight(
    *,
    maintainer_token: Optional[str],
    attacker_token: Optional[str],
    driver_present: bool,
    finding_org: Optional[str],
    use_real_repo: bool,
) -> PreflightResult:
    checks: list[PreflightCheck] = []
    # 1. Driver
    checks.append(
        PreflightCheck(
            name="driver_registered",
            ok=driver_present,
            detail="A driver is registered for this category." if driver_present else "No driver for this category.",
            fix=None if driver_present else "Use the Guided mode from _steps_for()/_poc_for() until a driver is added.",
        )
    )
    # 2. git
    import shutil as _sh
    checks.append(
        PreflightCheck(
            name="git_available",
            ok=_sh.which("git") is not None,
            detail="`git` is on PATH.",
            fix=None if _sh.which("git") else "Install Git for Windows: https://git-scm.com/download/win",
        )
    )
    # 3. Maintainer PAT
    if not maintainer_token:
        checks.append(
            PreflightCheck(
                name="maintainer_pat",
                ok=False,
                detail="No maintainer PAT saved.",
                fix="Save a maintainer PAT via POST /api/live-poc/tokens.",
            )
        )
    else:
        try:
            login, scopes = await pt.validate_pat(maintainer_token)
            ok, missing = pt.scopes_ok(scopes, pt.REQUIRED_MAINTAINER_SCOPES)
            checks.append(
                PreflightCheck(
                    name="maintainer_pat",
                    ok=ok,
                    detail=(
                        f"login={login}, scopes={','.join(scopes) or '(none)'}"
                        + (f"; missing={','.join(missing)}" if missing else "")
                    ),
                    fix=(
                        None
                        if ok
                        else f"Re-issue the maintainer PAT with scopes: {', '.join(sorted(pt.REQUIRED_MAINTAINER_SCOPES))}."
                    ),
                )
            )
        except Exception as e:
            checks.append(PreflightCheck(name="maintainer_pat", ok=False, detail=str(e), fix="Re-save a valid maintainer PAT."))
    # 4. Attacker PAT
    if not attacker_token:
        checks.append(
            PreflightCheck(
                name="attacker_pat",
                ok=False,
                detail="No attacker PAT saved.",
                fix="Save an attacker PAT via POST /api/live-poc/tokens.",
            )
        )
    else:
        try:
            login, scopes = await pt.validate_pat(attacker_token)
            ok, missing = pt.scopes_ok(scopes, pt.REQUIRED_ATTACKER_SCOPES)
            checks.append(
                PreflightCheck(
                    name="attacker_pat",
                    ok=ok,
                    detail=f"login={login}, scopes={','.join(scopes) or '(none)'}",
                    fix=None if ok else f"Re-issue the attacker PAT with scopes: {', '.join(sorted(pt.REQUIRED_ATTACKER_SCOPES))}.",
                )
            )
        except Exception as e:
            checks.append(PreflightCheck(name="attacker_pat", ok=False, detail=str(e), fix="Re-save a valid attacker PAT."))
    # 5. Attacker != maintainer target org — advisory
    checks.append(
        PreflightCheck(
            name="real_repo_mode",
            ok=not use_real_repo,
            detail=("Mirror-only mode (safe)." if not use_real_repo else "Real-repo mode ENABLED — actions will hit the actual target repo."),
            fix=None,
        )
    )
    return PreflightResult(ok=all(c.ok for c in checks if c.name in ("driver_registered", "git_available", "maintainer_pat", "attacker_pat")), checks=checks)


# ---------------------------------------------------------------------------
# Orchestrator entry-point
# ---------------------------------------------------------------------------
async def start_run(
    *,
    finding: dict,
    use_real_repo: bool = False,
    keep_repos: bool = False,
    force_minimal_mirror: bool = False,
) -> str:
    """Create a poc_runs row, kick a background task, and return the run_id."""
    category = finding.get("category") or ""
    drv = driver_for(category)
    marker = _mk_marker()

    # Ask the driver for its preview so we can pre-record claim, tags, and
    # success_requirement onto the row for the UI.
    claim = ""
    impact_tags: list[str] = []
    success_req = ""
    if drv:
        pv = drv.preview(finding, marker)
        claim = pv.claim
        impact_tags = pv.impact_tags
        success_req = pv.success_requirement

    can = pt.load_canary_record() or {}
    run_id = pdb.create_run(
        finding_id=finding.get("id") or "",
        category=category,
        marker=marker,
        opt_in_real_repo=use_real_repo,
        claim=claim,
        impact_class=impact_tags,
        success_requirement=success_req,
        canary_kind=can.get("kind") if can else None,
    )
    task = asyncio.create_task(_execute_run(run_id, finding, force_minimal_mirror, keep_repos))
    _TASKS[run_id] = task
    task.add_done_callback(lambda _t, rid=run_id: _TASKS.pop(rid, None))
    return run_id


async def cancel_run(run_id: str) -> bool:
    task = _TASKS.get(run_id)
    if not task:
        return False
    task.cancel()
    return True


async def _execute_run(run_id: str, finding: dict, force_minimal: bool, keep_repos: bool) -> None:
    phase_holder = {"phase": STATE_PREFLIGHT}
    log = _log_factory(run_id, phase_holder)

    mirror_owner: Optional[str] = None
    mirror_repo: Optional[str] = None
    attacker_owner: Optional[str] = None
    attacker_fork_name: Optional[str] = None
    workflow_run_id: Optional[int] = None
    workflow_run_url: Optional[str] = None
    trigger_pr_number: Optional[int] = None
    trigger_issue_number: Optional[int] = None
    verdict: str = VERDICT_INCONCLUSIVE
    proven: list[str] = []
    error_message: Optional[str] = None

    try:
        async with _RUN_LOCK:
            # -----------------------------------------------------------------
            # Preflight
            # -----------------------------------------------------------------
            phase_holder["phase"] = STATE_PREFLIGHT
            pdb.update_run(run_id, state=STATE_PREFLIGHT)
            m_tok = pt.load_maintainer_token()
            a_tok = pt.load_attacker_token()
            drv = driver_for(finding.get("category") or "")
            pfr = await run_preflight(
                maintainer_token=m_tok,
                attacker_token=a_tok,
                driver_present=drv is not None,
                finding_org=(finding.get("repo") or "").split("/", 1)[0],
                use_real_repo=(finding.get("_use_real_repo") or False),
            )
            for c in pfr.checks:
                log("info" if c.ok else "error", f"preflight[{c.name}] ok={c.ok} — {c.detail or ''}")
            if not pfr.ok:
                raise RuntimeError("preflight failed; see logs")
            if drv is None:
                raise RuntimeError("no driver for this category")

            marker_row = pdb.get_run(run_id)
            marker = marker_row.marker if marker_row else _mk_marker()

            # -----------------------------------------------------------------
            # Mirror
            # -----------------------------------------------------------------
            phase_holder["phase"] = STATE_MIRROR
            pdb.update_run(run_id, state=STATE_MIRROR)
            mirror = await pm.build_mirror(
                maintainer_token=m_tok,
                source_repo=finding.get("repo") or "",
                workflow_path=finding.get("workflow_path") or "",
                finding_id=finding.get("id") or "",
                finding_evidence=finding.get("evidence") or [],
                finding_snippet=finding.get("snippet") or "",
                force_minimal=force_minimal,
                log=log,
            )
            mirror_owner = mirror.owner
            mirror_repo = mirror.repo
            pdb.update_run(
                run_id,
                mirror_mode=mirror.mode,
                mirror_owner=mirror_owner,
                mirror_repo=mirror_repo,
                mirror_manifest=[{"path": mf.path, "reason": mf.reason, "size": mf.size} for mf in mirror.manifest],
            )
            log("info", f"mirror ready: {mirror_owner}/{mirror_repo} (mode={mirror.mode})")

            # -----------------------------------------------------------------
            # Attacker prep + inject + trigger
            # -----------------------------------------------------------------
            phase_holder["phase"] = STATE_INJECT
            pdb.update_run(run_id, state=STATE_INJECT)
            plan: TriggerPlan = drv.build_trigger(finding, marker)
            trig_started_after = time.time()

            if plan.kind == "issue":
                # Just open an issue on the mirror as the attacker.
                phase_holder["phase"] = STATE_TRIGGER
                pdb.update_run(run_id, state=STATE_TRIGGER)
                issue = await att.open_issue(
                    attacker_token=a_tok,
                    mirror_owner=mirror_owner,
                    mirror_repo=mirror_repo,
                    title=plan.title or "",
                    body=plan.body or "",
                    log=log,
                )
                trigger_issue_number = issue.number
                pdb.update_run(run_id, workflow_run_url=issue.html_url)  # placeholder
                trigger_event = "issues"

            elif plan.kind == "issue_comment":
                phase_holder["phase"] = STATE_TRIGGER
                pdb.update_run(run_id, state=STATE_TRIGGER)
                issue = await att.open_issue(
                    attacker_token=a_tok,
                    mirror_owner=mirror_owner,
                    mirror_repo=mirror_repo,
                    title=plan.title or "grafter-poc",
                    body=plan.body or "",
                    log=log,
                )
                trigger_issue_number = issue.number
                await att.add_issue_comment(
                    attacker_token=a_tok,
                    mirror_owner=mirror_owner,
                    mirror_repo=mirror_repo,
                    issue_number=issue.number,
                    body=plan.comment_body or "",
                    log=log,
                )
                trigger_event = "issue_comment"

            elif plan.kind == "pr":
                # Fork + push payload + open PR.
                fork = await att.fork_mirror(
                    attacker_token=a_tok,
                    mirror_owner=mirror_owner,
                    mirror_repo=mirror_repo,
                    log=log,
                )
                attacker_owner = fork.owner
                attacker_fork_name = fork.name
                pdb.update_run(run_id, attacker_owner=attacker_owner, attacker_fork=attacker_fork_name)
                payload = drv.build_payload(finding, marker)
                await att.push_payload_branch(
                    attacker_token=a_tok,
                    fork=fork,
                    branch=plan.branch or f"grafter-poc-{marker}",
                    files=payload.files,
                    commit_message=payload.commit_message or f"grafter-poc {marker}",
                    log=log,
                )
                phase_holder["phase"] = STATE_TRIGGER
                pdb.update_run(run_id, state=STATE_TRIGGER)
                # Base branch: mirror's default. build_mirror preserves the
                # source default_branch.
                base_branch = mirror.source_default_branch or "main"
                pr = await att.open_pr(
                    attacker_token=a_tok,
                    mirror_owner=mirror_owner,
                    mirror_repo=mirror_repo,
                    fork=fork,
                    branch=plan.branch or f"grafter-poc-{marker}",
                    base_branch=base_branch,
                    title=plan.title or "grafter-poc",
                    body=plan.body or "",
                    draft=True,
                    log=log,
                )
                trigger_pr_number = pr.number
                trigger_event = "pull_request"
            else:
                raise RuntimeError(f"unsupported trigger plan kind: {plan.kind}")

            # -----------------------------------------------------------------
            # Watch
            # -----------------------------------------------------------------
            phase_holder["phase"] = STATE_WATCH
            pdb.update_run(run_id, state=STATE_WATCH)
            async with httpx.AsyncClient(
                base_url="https://api.github.com",
                headers={
                    "Authorization": f"Bearer {m_tok}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "Grafter-LivePoC/0.1",
                },
                timeout=30.0,
            ) as client:
                run = await pw.wait_for_run(
                    client=client,
                    mirror_owner=mirror_owner,
                    mirror_repo=mirror_repo,
                    trigger_event=trigger_event,
                    started_after=trig_started_after - 30,
                    log=log,
                )
                if not run:
                    log("warn", "no workflow run appeared within the wait budget")
                    verdict = VERDICT_INCONCLUSIVE
                else:
                    workflow_run_id = int(run.get("id") or 0)
                    workflow_run_url = run.get("html_url") or ""
                    pdb.update_run(run_id, workflow_run_id=workflow_run_id, workflow_run_url=workflow_run_url)
                    completed = await pw.wait_for_run_completion(
                        client=client,
                        mirror_owner=mirror_owner,
                        mirror_repo=mirror_repo,
                        run_id=workflow_run_id,
                        log=log,
                    )
                    if not completed:
                        log("warn", "workflow run did not complete within the wait budget")
                        verdict = VERDICT_INCONCLUSIVE
                    else:
                        # -------------------------------------------------
                        # Verdict
                        # -------------------------------------------------
                        phase_holder["phase"] = STATE_VERDICT
                        pdb.update_run(run_id, state=STATE_VERDICT)
                        canary_hist = (pt.load_canary_record() or {}).get("history_url")
                        ctx = await pw.gather_context(
                            maintainer_token=m_tok,
                            mirror_owner=mirror_owner,
                            mirror_repo=mirror_repo,
                            run_id=workflow_run_id,
                            trigger_pr_number=trigger_pr_number,
                            trigger_issue_number=trigger_issue_number,
                            canary_history_url=canary_hist,
                            log=log,
                        )
                        # Re-derive the driver's SignalSpecs for evaluation.
                        preview_info = drv.preview(finding, marker)
                        fired = await pw.evaluate_signals(
                            signals=preview_info.signals, ctx=ctx, log=log
                        )
                        for sig in fired:
                            pdb.append_signal(run_id, sig)
                        verdict, proven = pw.compute_verdict(
                            signals=preview_info.signals,
                            fired=fired,
                            success_requirement=preview_info.success_requirement,
                            run_conclusion=completed.get("conclusion"),
                            run_present=True,
                        )
                        pdb.update_run(run_id, proven_impact=proven)
                        log(
                            "info",
                            f"verdict={verdict} proven={proven} conclusion={completed.get('conclusion')}",
                        )

    except asyncio.CancelledError:
        error_message = "cancelled by user"
        pdb.update_run(run_id, state="cancelled", verdict="cancelled", error=error_message)
        raise
    except Exception as e:
        error_message = f"{type(e).__name__}: {e}"
        log("error", error_message)
        verdict = VERDICT_ERROR
    finally:
        # -----------------------------------------------------------------
        # Cleanup
        # -----------------------------------------------------------------
        phase_holder["phase"] = STATE_CLEANUP
        try:
            pdb.update_run(run_id, state=STATE_CLEANUP)
        except Exception:
            pass
        if not keep_repos and mirror_owner and mirror_repo:
            try:
                await pm.delete_mirror(
                    maintainer_token=pt.load_maintainer_token() or "",
                    mirror_owner=mirror_owner,
                    mirror_repo=mirror_repo,
                    attacker_token=pt.load_attacker_token(),
                    attacker_owner=attacker_owner,
                    attacker_fork_name=attacker_fork_name,
                    log=log,
                )
            except Exception as e:
                log("warn", f"cleanup failed: {e}")

        # Terminal state
        if error_message and verdict != VERDICT_CONFIRMED:
            pdb.update_run(run_id, state=STATE_FAILED, verdict=verdict, error=error_message)
        else:
            pdb.update_run(run_id, state=STATE_DONE, verdict=verdict)


# ---------------------------------------------------------------------------
# Boot-time housekeeping
# ---------------------------------------------------------------------------
def boot_housekeeping() -> None:
    """Called from main.py at startup."""
    pdb.init_schema()
    n = pdb.mark_nonterminal_as_failed_at_boot()
    if n:
        # Best-effort: this may leave orphan repos behind; the sweeper cleans.
        pass
