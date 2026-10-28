"""Dual-PAT + canary token store for Live PoC.

Keeps the same on-disk shape as `~/.grafter/tokens.json` (which is
already produced by `main.py` for the single-PAT scanner) but promotes
the schema to hold three record types:

```json
{
    "token": "...",                       # legacy single-PAT (migrated on read)
    "login": "...",
    "saved_at": ...,
    "live_poc": {
        "maintainer": {"token": "...", "login": "...", "saved_at": ...},
        "attacker":   {"token": "...", "login": "...", "saved_at": ...},
        "canary":     {"token": "...", "kind": "http|aws|dns", "label": "...", "history_url": "...", "saved_at": ...}
    }
}
```

Legacy single-PAT records under `token`/`login` are left untouched — the
scanner-side code still uses them. Live PoC data lives under
`live_poc.*`. When either identity is missing we return None so callers
know to prompt the user.
"""
from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Optional

import httpx

from .models import LivePocIdentity, LivePocCanary, LivePocTokensInfo


DATA_DIR = Path(os.environ.get("GRAFTER_DATA_DIR", str(Path(os.path.expanduser("~")) / ".grafter")))
TOKEN_FILE = DATA_DIR / "tokens.json"


def _token_preview(tok: str) -> str:
    if not tok:
        return ""
    if len(tok) <= 8:
        return "•" * len(tok)
    return f"{tok[:4]}…{tok[-4:]}"


def _read() -> dict:
    try:
        if not TOKEN_FILE.exists():
            return {}
        return json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write(data: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(json.dumps(data), encoding="utf-8")
    try:
        if os.name == "posix":
            os.chmod(TOKEN_FILE, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def load_live_poc_tokens() -> tuple[Optional[dict], Optional[dict], Optional[dict]]:
    """Return (maintainer_record, attacker_record, canary_record) or (None, None, None)."""
    data = _read()
    lp = (data.get("live_poc") or {}) if isinstance(data, dict) else {}
    m = lp.get("maintainer") if isinstance(lp, dict) else None
    a = lp.get("attacker") if isinstance(lp, dict) else None
    c = lp.get("canary") if isinstance(lp, dict) else None
    return (
        m if isinstance(m, dict) and m.get("token") else None,
        a if isinstance(a, dict) and a.get("token") else None,
        c if isinstance(c, dict) and c.get("token") else None,
    )


def load_maintainer_token() -> Optional[str]:
    m, _, _ = load_live_poc_tokens()
    return m.get("token") if m else None


def load_attacker_token() -> Optional[str]:
    _, a, _ = load_live_poc_tokens()
    return a.get("token") if a else None


def load_canary_record() -> Optional[dict]:
    _, _, c = load_live_poc_tokens()
    return c


def get_tokens_info() -> LivePocTokensInfo:
    m, a, c = load_live_poc_tokens()
    info = LivePocTokensInfo()
    if m:
        info.maintainer = LivePocIdentity(
            login=m.get("login"),
            preview=_token_preview(m.get("token") or ""),
            saved_at=m.get("saved_at"),
        )
    if a:
        info.attacker = LivePocIdentity(
            login=a.get("login"),
            preview=_token_preview(a.get("token") or ""),
            saved_at=a.get("saved_at"),
        )
    if c:
        info.canary = LivePocCanary(
            kind=c.get("kind"),
            label=c.get("label"),
            preview=_token_preview(c.get("token") or ""),
            history_url=c.get("history_url"),
            saved_at=c.get("saved_at"),
        )
    return info


async def validate_pat(token: str) -> tuple[str, list[str]]:
    """Return `(login, scopes)` for a PAT. Raises RuntimeError on rejection."""
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "Grafter-LivePoC/0.1",
            },
        )
    if r.status_code != 200:
        raise RuntimeError(f"Token rejected by GitHub: {r.status_code} {r.text[:200]}")
    login = r.json().get("login") or "unknown"
    scope_hdr = r.headers.get("X-OAuth-Scopes") or ""
    scopes = [s.strip() for s in scope_hdr.split(",") if s.strip()]
    return login, scopes


def save_maintainer(token: str, login: str) -> None:
    data = _read() or {}
    lp = data.get("live_poc") or {}
    lp["maintainer"] = {"token": token, "login": login, "saved_at": time.time()}
    data["live_poc"] = lp
    _write(data)


def save_attacker(token: str, login: str) -> None:
    data = _read() or {}
    lp = data.get("live_poc") or {}
    lp["attacker"] = {"token": token, "login": login, "saved_at": time.time()}
    data["live_poc"] = lp
    _write(data)


def save_canary(
    token: str,
    kind: Optional[str] = None,
    label: Optional[str] = None,
    history_url: Optional[str] = None,
) -> None:
    data = _read() or {}
    lp = data.get("live_poc") or {}
    lp["canary"] = {
        "token": token,
        "kind": kind or "http",
        "label": label,
        "history_url": history_url,
        "saved_at": time.time(),
    }
    data["live_poc"] = lp
    _write(data)


def forget_all_live_poc() -> None:
    data = _read() or {}
    if "live_poc" in data:
        data.pop("live_poc", None)
        _write(data)


REQUIRED_MAINTAINER_SCOPES = frozenset({"repo", "workflow", "delete_repo"})
REQUIRED_ATTACKER_SCOPES = frozenset({"repo"})


def scopes_ok(scopes: list[str], required: frozenset[str]) -> tuple[bool, list[str]]:
    have = set(scopes)
    # Some GitHub PATs list `public_repo` instead of `repo` when only public
    # repos are in scope. For simple mirror flows we accept either.
    if "repo" in required and "public_repo" in have:
        have.add("repo")
    missing = sorted(required - have)
    return not missing, missing
