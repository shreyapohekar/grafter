"""SQLite persistence for Live PoC runs.

Uses the same `findings.db` file the scanner uses so that the run
lifecycle can be joined against `findings` cheaply (e.g. "latest PoC
verdict per finding").
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from .models import (
    PocRun,
    PocRunLogLine,
    PocRunSignal,
    STATE_ORDER,
    STATE_QUEUED,
    STATE_FAILED,
    TERMINAL_STATES,
)


DATA_DIR = Path(os.environ.get("GRAFTER_DATA_DIR", str(Path(os.path.expanduser("~")) / ".grafter")))
DB_FILE = DATA_DIR / "findings.db"


def _conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_FILE))
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")
    c.execute("PRAGMA busy_timeout=10000;")
    return c


def init_schema() -> None:
    """Idempotent — safe to call at every backend boot."""
    with _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS poc_runs (
                id                    TEXT PRIMARY KEY,
                finding_id            TEXT NOT NULL,
                category              TEXT,
                claim                 TEXT,
                impact_class          TEXT,
                proven_impact         TEXT,
                success_requirement   TEXT,
                mirror_mode           TEXT,
                mirror_manifest_json  TEXT,
                state                 TEXT NOT NULL,
                verdict               TEXT,
                started               REAL,
                finished              REAL,
                marker                TEXT NOT NULL,
                mirror_owner          TEXT,
                mirror_repo           TEXT,
                attacker_owner        TEXT,
                attacker_fork         TEXT,
                workflow_run_id       INTEGER,
                workflow_run_url      TEXT,
                logs_json             TEXT,
                evidence_json         TEXT,
                opt_in_real_repo      INTEGER DEFAULT 0,
                canary_kind           TEXT,
                error                 TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_poc_finding
                ON poc_runs (finding_id, started DESC);
            CREATE INDEX IF NOT EXISTS idx_poc_state
                ON poc_runs (state, started DESC);
            CREATE INDEX IF NOT EXISTS idx_poc_started
                ON poc_runs (started DESC);
            """
        )


# ---------------------------------------------------------------------------
# Row (de)serialisation
# ---------------------------------------------------------------------------
def _row_to_run(row: sqlite3.Row) -> PocRun:
    def _jl(name: str) -> list[Any]:
        raw = row[name] if name in row.keys() else None
        if not raw:
            return []
        try:
            v = json.loads(raw)
            return v if isinstance(v, list) else []
        except Exception:
            return []

    logs_raw = _jl("logs_json")
    evidence_raw = _jl("evidence_json")
    manifest_raw = _jl("mirror_manifest_json")

    return PocRun(
        id=row["id"],
        finding_id=row["finding_id"],
        category=row["category"],
        claim=row["claim"],
        impact_class=_jl("impact_class"),
        proven_impact=_jl("proven_impact"),
        success_requirement=row["success_requirement"],
        mirror_mode=row["mirror_mode"],
        mirror_manifest=manifest_raw or None,
        state=row["state"],
        verdict=row["verdict"],
        started=row["started"],
        finished=row["finished"],
        marker=row["marker"],
        mirror_owner=row["mirror_owner"],
        mirror_repo=row["mirror_repo"],
        attacker_owner=row["attacker_owner"],
        attacker_fork=row["attacker_fork"],
        workflow_run_id=row["workflow_run_id"],
        workflow_run_url=row["workflow_run_url"],
        logs=[PocRunLogLine(**ll) for ll in logs_raw if isinstance(ll, dict)],
        evidence=[PocRunSignal(**e) for e in evidence_raw if isinstance(e, dict)],
        opt_in_real_repo=bool(row["opt_in_real_repo"]),
        canary_kind=row["canary_kind"],
        error=row["error"],
    )


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------
def create_run(
    *,
    finding_id: str,
    category: Optional[str],
    marker: str,
    opt_in_real_repo: bool = False,
    claim: Optional[str] = None,
    impact_class: Optional[list[str]] = None,
    success_requirement: Optional[str] = None,
    canary_kind: Optional[str] = None,
) -> str:
    run_id = uuid.uuid4().hex
    with _conn() as c:
        c.execute(
            """INSERT INTO poc_runs
               (id, finding_id, category, claim, impact_class, success_requirement,
                state, started, marker, opt_in_real_repo, canary_kind,
                logs_json, evidence_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', '[]')""",
            (
                run_id,
                finding_id,
                category,
                claim,
                json.dumps(impact_class or []),
                success_requirement,
                STATE_QUEUED,
                time.time(),
                marker,
                1 if opt_in_real_repo else 0,
                canary_kind,
            ),
        )
    return run_id


def _load_run_row(c: sqlite3.Connection, run_id: str) -> Optional[sqlite3.Row]:
    return c.execute("SELECT * FROM poc_runs WHERE id = ?", (run_id,)).fetchone()


def get_run(run_id: str) -> Optional[PocRun]:
    with _conn() as c:
        row = _load_run_row(c, run_id)
        return _row_to_run(row) if row else None


def has_active_run_for_finding(finding_id: str) -> Optional[str]:
    """Return the id of a non-terminal run for the finding, if any."""
    with _conn() as c:
        row = c.execute(
            """SELECT id FROM poc_runs
               WHERE finding_id = ? AND state NOT IN (?, ?, ?)
               ORDER BY started DESC LIMIT 1""",
            (finding_id, "done", "failed", "cancelled"),
        ).fetchone()
        return row["id"] if row else None


def _valid_transition(prev: str, nxt: str) -> bool:
    if prev == nxt:
        return True
    if nxt in ("failed", "cancelled"):
        return True
    # Verdict can be recorded from any non-terminal state.
    try:
        return STATE_ORDER.index(nxt) >= STATE_ORDER.index(prev)
    except ValueError:
        return True  # Unknown states → allow, we'll trust the caller.


def update_run(run_id: str, **kwargs: Any) -> Optional[PocRun]:
    """Selectively update columns of a run. Rejects invalid state transitions."""
    if not kwargs:
        return get_run(run_id)
    with _conn() as c:
        current = _load_run_row(c, run_id)
        if not current:
            return None
        if "state" in kwargs and not _valid_transition(current["state"], kwargs["state"]):
            raise ValueError(
                f"invalid state transition {current['state']!r} -> {kwargs['state']!r}"
            )
        cols: list[str] = []
        vals: list[Any] = []
        # JSON-serialised list columns
        for key in ("impact_class", "proven_impact"):
            if key in kwargs:
                cols.append(f"{key} = ?")
                vals.append(json.dumps(kwargs.pop(key) or []))
        if "mirror_manifest" in kwargs:
            cols.append("mirror_manifest_json = ?")
            vals.append(json.dumps(kwargs.pop("mirror_manifest") or []))
        if "opt_in_real_repo" in kwargs:
            cols.append("opt_in_real_repo = ?")
            vals.append(1 if kwargs.pop("opt_in_real_repo") else 0)
        # Direct columns
        for key in (
            "finding_id",
            "category",
            "claim",
            "success_requirement",
            "mirror_mode",
            "state",
            "verdict",
            "started",
            "finished",
            "marker",
            "mirror_owner",
            "mirror_repo",
            "attacker_owner",
            "attacker_fork",
            "workflow_run_id",
            "workflow_run_url",
            "canary_kind",
            "error",
        ):
            if key in kwargs:
                cols.append(f"{key} = ?")
                vals.append(kwargs.pop(key))
        if "state" in [c.split(" = ")[0] for c in cols]:
            # If transitioning to a terminal state and finished isn't set,
            # stamp finished automatically.
            new_state = next(
                (v for col, v in zip(cols, vals) if col == "state = ?"), None
            )
            if new_state in TERMINAL_STATES and "finished = ?" not in cols:
                cols.append("finished = ?")
                vals.append(time.time())
        if kwargs:
            # Unknown kwargs — dev-time bug. Ignore silently rather than
            # explode a background task, but log-load noise is fine.
            pass
        if not cols:
            return _row_to_run(current)
        vals.append(run_id)
        c.execute(f"UPDATE poc_runs SET {', '.join(cols)} WHERE id = ?", vals)
        row = _load_run_row(c, run_id)
        return _row_to_run(row) if row else None


def append_log(run_id: str, phase: str, message: str, level: str = "info") -> None:
    line = PocRunLogLine(ts=time.time(), phase=phase, level=level, message=message)
    with _conn() as c:
        row = _load_run_row(c, run_id)
        if not row:
            return
        existing: list[Any]
        try:
            existing = json.loads(row["logs_json"] or "[]")
        except Exception:
            existing = []
        existing.append(line.model_dump())
        # Keep the last 500 lines to bound memory.
        if len(existing) > 500:
            existing = existing[-500:]
        c.execute(
            "UPDATE poc_runs SET logs_json = ? WHERE id = ?",
            (json.dumps(existing), run_id),
        )


def append_signal(run_id: str, sig: PocRunSignal) -> None:
    with _conn() as c:
        row = _load_run_row(c, run_id)
        if not row:
            return
        existing: list[Any]
        try:
            existing = json.loads(row["evidence_json"] or "[]")
        except Exception:
            existing = []
        existing.append(sig.model_dump())
        c.execute(
            "UPDATE poc_runs SET evidence_json = ? WHERE id = ?",
            (json.dumps(existing), run_id),
        )


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------
def list_runs(
    *,
    state_filter: Optional[str] = None,  # "active" | "terminal" | "all" (default: all)
    finding_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[int, list[sqlite3.Row]]:
    where: list[str] = []
    params: list[Any] = []
    if finding_id:
        where.append("finding_id = ?")
        params.append(finding_id)
    if state_filter == "active":
        where.append("state NOT IN (?, ?, ?)")
        params.extend(["done", "failed", "cancelled"])
    elif state_filter == "terminal":
        where.append("state IN (?, ?, ?)")
        params.extend(["done", "failed", "cancelled"])
    wc = f"WHERE {' AND '.join(where)}" if where else ""
    with _conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM poc_runs {wc}", params).fetchone()[0]
        rows = c.execute(
            f"""SELECT * FROM poc_runs {wc}
                ORDER BY started DESC LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ).fetchall()
        return total, rows


def latest_run_per_finding(finding_ids: list[str]) -> dict[str, sqlite3.Row]:
    if not finding_ids:
        return {}
    placeholders = ",".join("?" for _ in finding_ids)
    with _conn() as c:
        rows = c.execute(
            f"""SELECT * FROM poc_runs
                WHERE finding_id IN ({placeholders})
                AND (finding_id, started) IN (
                    SELECT finding_id, MAX(started) FROM poc_runs
                    WHERE finding_id IN ({placeholders})
                    GROUP BY finding_id
                )""",
            (*finding_ids, *finding_ids),
        ).fetchall()
    return {row["finding_id"]: row for row in rows}


def summary_counts() -> dict[str, int]:
    """Cheap counts for the tab badge."""
    now = time.time()
    twenty_four_h = now - 24 * 3600
    stuck_deadline = now - 15 * 60
    with _conn() as c:
        active = c.execute(
            "SELECT COUNT(*) FROM poc_runs WHERE state NOT IN (?, ?, ?)",
            ("done", "failed", "cancelled"),
        ).fetchone()[0]
        term = c.execute(
            "SELECT COUNT(*) FROM poc_runs WHERE state IN (?, ?, ?) AND COALESCE(finished, started, 0) >= ?",
            ("done", "failed", "cancelled", twenty_four_h),
        ).fetchone()[0]
        stuck = c.execute(
            "SELECT COUNT(*) FROM poc_runs WHERE state = ? AND COALESCE(started, 0) < ?",
            ("watch", stuck_deadline),
        ).fetchone()[0]
    return {"active": int(active), "terminal_last_24h": int(term), "stuck": int(stuck)}


def delete_run(run_id: str) -> bool:
    with _conn() as c:
        cur = c.execute("DELETE FROM poc_runs WHERE id = ?", (run_id,))
        return cur.rowcount > 0


def mark_nonterminal_as_failed_at_boot() -> int:
    """On backend restart, mark any non-terminal run as failed so orphan repos
    can be cleaned up. Returns the number of rows updated."""
    with _conn() as c:
        cur = c.execute(
            """UPDATE poc_runs SET state = ?, verdict = ?, finished = ?, error = ?
               WHERE state NOT IN (?, ?, ?)""",
            (
                STATE_FAILED,
                "error",
                time.time(),
                "backend restarted while run was in flight",
                "done",
                "failed",
                "cancelled",
            ),
        )
        return cur.rowcount


def row_to_list_item(row: sqlite3.Row, finding_meta: Optional[dict] = None) -> dict:
    """Materialise a list-item friendly dict from a run row."""
    try:
        proven = json.loads(row["proven_impact"] or "[]") or []
    except Exception:
        proven = []
    return {
        "id": row["id"],
        "finding_id": row["finding_id"],
        "finding_title": (finding_meta or {}).get("title"),
        "finding_repo": (finding_meta or {}).get("repo"),
        "category": row["category"],
        "claim": row["claim"],
        "state": row["state"],
        "verdict": row["verdict"],
        "started": row["started"],
        "finished": row["finished"],
        "proven_impact": proven,
        "workflow_run_url": row["workflow_run_url"],
        "mirror_owner": row["mirror_owner"],
        "mirror_repo": row["mirror_repo"],
    }
