"""Signal observers + verdict scoring for Live PoC.

For each SignalSpec the driver requested, we dispatch to a handler that
inspects the mirror repo's Actions run / comments / artifacts / labels
and emits PocRunSignal records. Once all handlers finish, a small
boolean evaluator applies the driver's `success_requirement` expression
to decide CONFIRMED / WEAK_REPRO / NOT_REPRODUCED / BLOCKED_BY_GATE /
INCONCLUSIVE.
"""
from __future__ import annotations

import asyncio
import io
import re
import time
import zipfile
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

import httpx

from .drivers.base import SignalSpec
from .models import (
    PocRunSignal,
    VERDICT_BLOCKED_BY_GATE,
    VERDICT_CONFIRMED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_REPRODUCED,
    VERDICT_WEAK_REPRO,
)


GITHUB_API = "https://api.github.com"
DEFAULT_WATCH_TIMEOUT_S = int(60 * 20)  # 20 min


Logger = Callable[[str, str], None]


def _noop(_lvl: str, _msg: str) -> None:  # pragma: no cover
    pass


def _client(token: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=GITHUB_API,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Grafter-LivePoC/0.1",
        },
        timeout=30.0,
    )


# ---------------------------------------------------------------------------
# Find the workflow run created for the mirror by our trigger
# ---------------------------------------------------------------------------
async def wait_for_run(
    *,
    client: httpx.AsyncClient,
    mirror_owner: str,
    mirror_repo: str,
    trigger_event: str,
    head_sha: Optional[str] = None,
    started_after: float = 0,
    poll_s: float = 3.0,
    timeout_s: int = DEFAULT_WATCH_TIMEOUT_S,
    log: Logger = _noop,
) -> Optional[dict]:
    """Poll `/actions/runs` until a matching run appears. Returns the run
    JSON or None on timeout."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = await client.get(
                f"/repos/{mirror_owner}/{mirror_repo}/actions/runs",
                params={"per_page": 30},
            )
            if r.status_code == 200:
                runs = r.json().get("workflow_runs") or []
                candidates = []
                for run in runs:
                    if run.get("event") != trigger_event:
                        # `pull_request_target` fires the on-repo workflow, but
                        # GitHub reports the event as `pull_request_target`;
                        # allow either.
                        if not (trigger_event == "pull_request" and run.get("event") == "pull_request_target"):
                            continue
                    if head_sha and run.get("head_sha") and run["head_sha"][:12] != head_sha[:12]:
                        # For fork PRs, `head_sha` on the run points at the
                        # merge commit or the fork head — accept either.
                        pass
                    ts = _iso_to_epoch(run.get("created_at") or "")
                    if ts and ts + 5 < started_after:  # allow small clock skew
                        continue
                    candidates.append(run)
                if candidates:
                    candidates.sort(key=lambda r: r.get("id") or 0)
                    log("info", f"matched workflow run id={candidates[-1].get('id')}")
                    return candidates[-1]
        except Exception as e:
            log("warn", f"wait_for_run poll error: {e}")
        await asyncio.sleep(poll_s)
    return None


async def wait_for_run_completion(
    *,
    client: httpx.AsyncClient,
    mirror_owner: str,
    mirror_repo: str,
    run_id: int,
    poll_s: float = 5.0,
    timeout_s: int = DEFAULT_WATCH_TIMEOUT_S,
    log: Logger = _noop,
) -> Optional[dict]:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = await client.get(f"/repos/{mirror_owner}/{mirror_repo}/actions/runs/{run_id}")
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "completed":
                    log("info", f"run {run_id} completed with conclusion={data.get('conclusion')}")
                    return data
        except Exception as e:
            log("warn", f"wait_for_run_completion poll error: {e}")
        await asyncio.sleep(poll_s)
    return None


def _iso_to_epoch(s: str) -> float:
    if not s:
        return 0.0
    try:
        return time.mktime(time.strptime(s.rstrip("Z"), "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------
async def _fetch_run_logs(
    client: httpx.AsyncClient,
    mirror_owner: str,
    mirror_repo: str,
    run_id: int,
) -> str:
    r = await client.get(
        f"/repos/{mirror_owner}/{mirror_repo}/actions/runs/{run_id}/logs",
        follow_redirects=True,
    )
    if r.status_code != 200:
        return ""
    try:
        zf = zipfile.ZipFile(io.BytesIO(r.content))
    except Exception:
        return ""
    parts: list[str] = []
    for name in zf.namelist():
        try:
            data = zf.read(name).decode("utf-8", errors="replace")
        except Exception:
            continue
        parts.append(f"### {name}\n{data}")
    return "\n".join(parts)


async def _handle_run_log_regex(
    spec: SignalSpec,
    ctx: dict,
    log: Logger,
) -> Optional[PocRunSignal]:
    regex = (spec.params or {}).get("regex")
    if not regex:
        return None
    text = ctx.get("run_logs_text") or ""
    m = re.search(regex, text)
    if not m:
        return None
    return PocRunSignal(
        signal_type=spec.signal_type,
        when=time.time(),
        where=f"actions/runs/{ctx.get('run_id')}/logs",
        matched_by=spec.description or f"regex `{regex}` matched",
        tags=list(spec.tags),
        details={"snippet": _snippet_around(text, m.start(), m.end())},
    )


async def _handle_issue_or_pr_comment_regex(
    spec: SignalSpec,
    ctx: dict,
    log: Logger,
) -> Optional[PocRunSignal]:
    regex = (spec.params or {}).get("regex")
    require_bot = (spec.params or {}).get("require_gh_token_bot", False)
    if not regex:
        return None
    for c in ctx.get("comments") or []:
        body = c.get("body") or ""
        if not re.search(regex, body):
            continue
        if require_bot:
            author = (c.get("user") or {}).get("login") or ""
            if not (author.endswith("[bot]") or author.lower() == "github-actions[bot]"):
                continue
        return PocRunSignal(
            signal_type=spec.signal_type,
            when=time.time(),
            where=c.get("html_url"),
            matched_by=spec.description or f"comment regex `{regex}` matched",
            tags=list(spec.tags),
            details={
                "author": (c.get("user") or {}).get("login"),
                "body_excerpt": (body or "")[:400],
            },
        )
    return None


async def _handle_pr_comment_by_gh_token_regex(
    spec: SignalSpec,
    ctx: dict,
    log: Logger,
) -> Optional[PocRunSignal]:
    new_spec = SignalSpec(
        id=spec.id,
        signal_type=spec.signal_type,
        tags=list(spec.tags),
        description=spec.description,
        params={**(spec.params or {}), "require_gh_token_bot": True},
    )
    return await _handle_issue_or_pr_comment_regex(new_spec, ctx, log)


async def _handle_pr_label_by_identity(
    spec: SignalSpec,
    ctx: dict,
    log: Logger,
) -> Optional[PocRunSignal]:
    name_regex = (spec.params or {}).get("name_regex")
    if not name_regex:
        return None
    for lbl in ctx.get("pr_labels") or []:
        if re.search(name_regex, lbl.get("name") or ""):
            return PocRunSignal(
                signal_type=spec.signal_type,
                when=time.time(),
                where=ctx.get("pr_html_url"),
                matched_by=spec.description or f"label matches `{name_regex}`",
                tags=list(spec.tags),
                details={"label": lbl.get("name")},
            )
    return None


async def _handle_artifact_regex(
    spec: SignalSpec,
    ctx: dict,
    log: Logger,
) -> Optional[PocRunSignal]:
    name_regex = (spec.params or {}).get("name_regex")
    content_regex = (spec.params or {}).get("content_regex")
    if not (name_regex or content_regex):
        return None
    for art in ctx.get("artifacts") or []:
        if name_regex and not re.search(name_regex, art.get("name") or ""):
            continue
        # We already have the artifact contents in ctx["artifact_texts"][name] if any.
        text = (ctx.get("artifact_texts") or {}).get(art.get("name") or "") or ""
        if content_regex and not re.search(content_regex, text):
            continue
        return PocRunSignal(
            signal_type=spec.signal_type,
            when=time.time(),
            where=art.get("archive_download_url"),
            matched_by=spec.description or "artifact match",
            tags=list(spec.tags),
            details={"name": art.get("name")},
        )
    return None


async def _handle_canary_hit(
    spec: SignalSpec,
    ctx: dict,
    log: Logger,
) -> Optional[PocRunSignal]:
    hits = ctx.get("canary_hits") or []
    if not hits:
        return None
    return PocRunSignal(
        signal_type=spec.signal_type,
        when=time.time(),
        where=(ctx.get("canary_history_url") or ""),
        matched_by=spec.description or "canary hit observed",
        tags=list(spec.tags),
        details={"hits": hits[:5]},
    )


SignalHandler = Callable[[SignalSpec, dict, Logger], Awaitable[Optional[PocRunSignal]]]


_HANDLERS: dict[str, SignalHandler] = {
    "run_log_regex": _handle_run_log_regex,
    "issue_or_pr_comment_regex": _handle_issue_or_pr_comment_regex,
    "pr_comment_by_gh_token_regex": _handle_pr_comment_by_gh_token_regex,
    "pr_label_by_identity": _handle_pr_label_by_identity,
    "artifact_regex": _handle_artifact_regex,
    "canary_hit": _handle_canary_hit,
}


def _snippet_around(text: str, start: int, end: int, radius: int = 120) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    return text[lo:hi]


# ---------------------------------------------------------------------------
# Context gathering
# ---------------------------------------------------------------------------
async def gather_context(
    *,
    maintainer_token: str,
    mirror_owner: str,
    mirror_repo: str,
    run_id: int,
    trigger_pr_number: Optional[int] = None,
    trigger_issue_number: Optional[int] = None,
    canary_history_url: Optional[str] = None,
    log: Logger = _noop,
) -> dict:
    ctx: dict = {"run_id": run_id, "canary_history_url": canary_history_url}
    async with _client(maintainer_token) as client:
        # 1. Run logs (best effort).
        try:
            ctx["run_logs_text"] = await _fetch_run_logs(client, mirror_owner, mirror_repo, run_id)
        except Exception as e:
            log("warn", f"log fetch failed: {e}")
            ctx["run_logs_text"] = ""
        # 2. Artifacts + inline text for small text artifacts.
        try:
            r = await client.get(f"/repos/{mirror_owner}/{mirror_repo}/actions/runs/{run_id}/artifacts")
            arts = (r.json() if r.status_code == 200 else {}).get("artifacts") or []
        except Exception:
            arts = []
        ctx["artifacts"] = arts
        art_texts: dict[str, str] = {}
        for a in arts[:5]:
            try:
                dr = await client.get(a.get("archive_download_url") or "", follow_redirects=True)
                if dr.status_code == 200 and dr.headers.get("content-type", "").startswith(("application/zip", "application/octet-stream")):
                    zf = zipfile.ZipFile(io.BytesIO(dr.content))
                    parts = []
                    for name in zf.namelist():
                        try:
                            parts.append(zf.read(name).decode("utf-8", errors="replace"))
                        except Exception:
                            continue
                    art_texts[a.get("name") or ""] = "\n".join(parts)
            except Exception:
                continue
        ctx["artifact_texts"] = art_texts

        # 3. Comments and labels.
        comments: list[dict] = []
        pr_labels: list[dict] = []
        pr_html_url: Optional[str] = None
        try:
            target_number = trigger_pr_number or trigger_issue_number
            if target_number:
                cr = await client.get(
                    f"/repos/{mirror_owner}/{mirror_repo}/issues/{target_number}/comments",
                    params={"per_page": 100},
                )
                if cr.status_code == 200:
                    comments = cr.json() or []
                if trigger_pr_number:
                    pr = await client.get(f"/repos/{mirror_owner}/{mirror_repo}/pulls/{trigger_pr_number}")
                    if pr.status_code == 200:
                        pr_labels = (pr.json() or {}).get("labels") or []
                        pr_html_url = (pr.json() or {}).get("html_url")
        except Exception as e:
            log("warn", f"comment/label fetch failed: {e}")
        ctx["comments"] = comments
        ctx["pr_labels"] = pr_labels
        ctx["pr_html_url"] = pr_html_url

        # 4. Canary hits (best effort).
        canary_hits: list[dict] = []
        if canary_history_url:
            try:
                async with httpx.AsyncClient(timeout=10.0) as raw:
                    hr = await raw.get(canary_history_url)
                    if hr.status_code == 200:
                        try:
                            data = hr.json()
                            if isinstance(data, list):
                                canary_hits = data[:10]
                            elif isinstance(data, dict) and isinstance(data.get("hits"), list):
                                canary_hits = data["hits"][:10]
                        except Exception:
                            canary_hits = [{"raw": hr.text[:400]}]
            except Exception:
                pass
        ctx["canary_hits"] = canary_hits

    return ctx


async def evaluate_signals(
    *,
    signals: list[SignalSpec],
    ctx: dict,
    log: Logger = _noop,
) -> list[PocRunSignal]:
    fired: list[PocRunSignal] = []
    for spec in signals:
        handler = _HANDLERS.get(spec.signal_type)
        if not handler:
            log("warn", f"no handler for signal type `{spec.signal_type}`")
            continue
        try:
            result = await handler(spec, ctx, log)
        except Exception as e:
            log("warn", f"signal `{spec.id}` handler crashed: {e}")
            continue
        if result:
            log("info", f"signal `{spec.id}` fired: {result.matched_by}")
            fired.append(result)
    return fired


# ---------------------------------------------------------------------------
# Boolean requirement evaluation
# ---------------------------------------------------------------------------
_BOOL_TOKEN = re.compile(r"\s*(\(|\)|AND|OR|NOT|[A-Za-z0-9_]+)\s*", re.IGNORECASE)


def _tokenize_requirement(req: str) -> list[str]:
    out: list[str] = []
    pos = 0
    while pos < len(req):
        m = _BOOL_TOKEN.match(req, pos)
        if not m:
            raise ValueError(f"cannot tokenise requirement at pos {pos}: {req[pos:pos+40]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


def _eval_requirement(req: str, fired_ids: set[str]) -> bool:
    tokens = [t for t in _tokenize_requirement(req)]
    # Replace ids with true/false; keep parens and operators.
    py = []
    for t in tokens:
        u = t.upper()
        if u == "AND":
            py.append("and")
        elif u == "OR":
            py.append("or")
        elif u == "NOT":
            py.append("not")
        elif t in ("(", ")"):
            py.append(t)
        else:
            py.append("True" if t in fired_ids else "False")
    expr = " ".join(py)
    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))
    except Exception:
        return False


def compute_verdict(
    *,
    signals: list[SignalSpec],
    fired: list[PocRunSignal],
    success_requirement: str,
    run_conclusion: Optional[str],
    run_present: bool,
    generic_marker_signal_id: Optional[str] = "marker_in_log",
) -> tuple[str, list[str]]:
    """Returns (verdict, proven_impact_tags)."""
    if not run_present:
        return VERDICT_INCONCLUSIVE, []
    if run_conclusion == "skipped":
        return VERDICT_BLOCKED_BY_GATE, []

    # Which signal ids fired?
    fired_by_spec_id: set[str] = set()
    proven_tags: set[str] = set()
    for sig in fired:
        # Find spec whose description this signal cites, or fall back to
        # index match: signals fire in the same order they were provided,
        # so we intersect on signal_type + tag set.
        for spec in signals:
            if spec.signal_type == sig.signal_type and set(spec.tags) == set(sig.tags):
                fired_by_spec_id.add(spec.id)
                break
        proven_tags.update(sig.tags)

    try:
        confirmed = _eval_requirement(success_requirement, fired_by_spec_id) if success_requirement else False
    except Exception:
        confirmed = False

    if confirmed:
        return VERDICT_CONFIRMED, sorted(proven_tags)
    if fired:
        return VERDICT_WEAK_REPRO, sorted(proven_tags)
    if run_conclusion in ("failure", "success", "cancelled", "timed_out"):
        return VERDICT_NOT_REPRODUCED, []
    return VERDICT_INCONCLUSIVE, []
