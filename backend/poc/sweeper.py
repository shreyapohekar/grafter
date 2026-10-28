"""Background sweeper for orphan Live PoC mirror repos.

Runs at process start and every 30 min: deletes any repo under the
maintainer identity that is tagged `grafter-poc` and older than
`GRAFTER_LIVE_POC_MIRROR_MAX_AGE_HOURS` (default 24). Also marks any
non-terminal poc_runs rows as failed on boot.
"""
from __future__ import annotations

import asyncio
import os

from . import db as pdb
from . import mirror as pm
from . import tokens as pt


DEFAULT_MAX_AGE_HOURS = int(os.environ.get("GRAFTER_LIVE_POC_MIRROR_MAX_AGE_HOURS", "24"))
SWEEP_INTERVAL_S = int(os.environ.get("GRAFTER_LIVE_POC_SWEEP_INTERVAL_S", str(30 * 60)))


async def _sweep_once() -> None:
    tok = pt.load_maintainer_token()
    if not tok:
        return
    try:
        await pm.sweep_orphan_mirrors(
            maintainer_token=tok,
            max_age_hours=DEFAULT_MAX_AGE_HOURS,
        )
    except Exception:
        # Swallow — the sweeper must never crash the server.
        pass


async def _loop() -> None:
    while True:
        await _sweep_once()
        await asyncio.sleep(SWEEP_INTERVAL_S)


_TASK: asyncio.Task | None = None


def start_sweeper() -> None:
    """Fire-and-forget background task. Call once from the startup hook."""
    global _TASK
    if _TASK is not None:
        return
    loop = asyncio.get_event_loop()
    _TASK = loop.create_task(_loop())


def boot() -> None:
    """Combined boot-time actions: schema init, orphan-flag, start sweeper."""
    pdb.init_schema()
    pdb.mark_nonterminal_as_failed_at_boot()
    try:
        start_sweeper()
    except Exception:
        pass
