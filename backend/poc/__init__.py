"""Grafter Live PoC package.

Everything under `poc/` implements the "Live PoC" feature that
mirror-clones a vulnerable repo, drives an attacker-role identity to
trigger a finding, and records CONFIRMED / WEAK_REPRO /
NOT_REPRODUCED / BLOCKED_BY_GATE / INCONCLUSIVE verdicts.

The package is intentionally self-contained: it opens its own sqlite
connection against the same `findings.db` used by `main.py`, calls the
GitHub API via `httpx` directly, and never imports scanner rules.
"""
from __future__ import annotations

__all__ = [
    "models",
    "tokens",
    "db",
    "mirror",
    "attacker",
    "watcher",
    "orchestrator",
    "drivers",
]
