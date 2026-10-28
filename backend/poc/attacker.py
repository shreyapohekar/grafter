"""Attacker-role GitHub actions for Live PoC.

All operations happen under the attacker PAT. This module NEVER touches
the maintainer's repo directly — it only forks it, pushes to the fork,
and opens PRs / issues / comments back at the mirror.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import httpx

GITHUB_API = "https://api.github.com"

Logger = Callable[[str, str], None]


def _noop(_lvl: str, _msg: str) -> None:  # pragma: no cover
    pass


def _client(token: str, timeout: float = 30.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=GITHUB_API,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Grafter-LivePoC/0.1",
        },
        timeout=timeout,
    )


def _run(cmd: list[str], cwd: Optional[str] = None, env: Optional[dict] = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _authed_url(url: str, token: str) -> str:
    if url.startswith("https://"):
        return url.replace("https://", f"https://x-access-token:{token}@", 1)
    return url


@dataclass
class AttackerFork:
    owner: str
    name: str
    default_branch: str
    clone_url: str
    html_url: str


@dataclass
class PayloadFile:
    path: str
    content: bytes


@dataclass
class OpenedIssue:
    number: int
    html_url: str


@dataclass
class OpenedPR:
    number: int
    html_url: str
    head_sha: str


async def _get_login(client: httpx.AsyncClient) -> str:
    r = await client.get("/user")
    if r.status_code != 200:
        raise RuntimeError(f"cannot resolve attacker login: {r.status_code}")
    return r.json().get("login") or "attacker"


async def fork_mirror(
    *,
    attacker_token: str,
    mirror_owner: str,
    mirror_repo: str,
    log: Logger = _noop,
) -> AttackerFork:
    """Fork the mirror under the attacker identity, wait for it to become
    available, and return the fork coordinates."""
    async with _client(attacker_token) as client:
        r = await client.post(f"/repos/{mirror_owner}/{mirror_repo}/forks")
        if r.status_code not in (200, 201, 202):
            raise RuntimeError(f"fork failed: {r.status_code} {r.text[:300]}")
        # Fork creation is async on GitHub's side; poll until it lands.
        attacker_login = await _get_login(client)
        for _ in range(30):
            f = await client.get(f"/repos/{attacker_login}/{mirror_repo}")
            if f.status_code == 200:
                data = f.json()
                return AttackerFork(
                    owner=attacker_login,
                    name=data.get("name") or mirror_repo,
                    default_branch=data.get("default_branch") or "main",
                    clone_url=data.get("clone_url") or f"https://github.com/{attacker_login}/{mirror_repo}.git",
                    html_url=data.get("html_url") or f"https://github.com/{attacker_login}/{mirror_repo}",
                )
            await asyncio.sleep(2)
        raise RuntimeError(f"fork did not become available for {attacker_login}/{mirror_repo}")


async def push_payload_branch(
    *,
    attacker_token: str,
    fork: AttackerFork,
    branch: str,
    files: list[PayloadFile],
    commit_message: str,
    log: Logger = _noop,
) -> str:
    """Clone the attacker fork, apply payload files, push a payload branch.

    Returns the head sha of the newly-pushed branch.
    """
    tmp = tempfile.mkdtemp(prefix="grafter-poc-attacker-")
    try:
        r = _run(
            [
                "git",
                "clone",
                "--depth",
                "5",
                "--single-branch",
                "--branch",
                fork.default_branch,
                _authed_url(fork.clone_url, attacker_token),
                tmp,
            ],
            timeout=180,
        )
        if r.returncode != 0:
            raise RuntimeError(f"attacker git clone failed: {r.stderr[:300]}")
        _run(["git", "checkout", "-b", branch], cwd=tmp)
        for f in files:
            fp = os.path.join(tmp, f.path)
            os.makedirs(os.path.dirname(fp) or tmp, exist_ok=True)
            with open(fp, "wb") as fh:
                fh.write(f.content)
        _run(["git", "config", "user.email", "grafter-attacker@localhost"], cwd=tmp)
        _run(["git", "config", "user.name", "Grafter Attacker"], cwd=tmp)
        _run(["git", "add", "-A"], cwd=tmp)
        _run(["git", "commit", "-m", commit_message], cwd=tmp)
        push = _run(
            ["git", "push", "--force", "--set-upstream", "origin", branch],
            cwd=tmp,
            timeout=180,
        )
        if push.returncode != 0:
            raise RuntimeError(f"attacker git push failed: {push.stderr[:300]}")
        rev = _run(["git", "rev-parse", "HEAD"], cwd=tmp)
        return (rev.stdout or "").strip() or ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


async def open_pr(
    *,
    attacker_token: str,
    mirror_owner: str,
    mirror_repo: str,
    fork: AttackerFork,
    branch: str,
    base_branch: str,
    title: str,
    body: str,
    draft: bool = True,
    log: Logger = _noop,
) -> OpenedPR:
    async with _client(attacker_token) as client:
        r = await client.post(
            f"/repos/{mirror_owner}/{mirror_repo}/pulls",
            json={
                "title": title,
                "body": body,
                "head": f"{fork.owner}:{branch}",
                "base": base_branch,
                "draft": draft,
            },
        )
        if r.status_code not in (200, 201):
            raise RuntimeError(f"open_pr failed: {r.status_code} {r.text[:400]}")
        data = r.json()
        return OpenedPR(
            number=data.get("number") or 0,
            html_url=data.get("html_url") or "",
            head_sha=(data.get("head") or {}).get("sha") or "",
        )


async def open_issue(
    *,
    attacker_token: str,
    mirror_owner: str,
    mirror_repo: str,
    title: str,
    body: str,
    log: Logger = _noop,
) -> OpenedIssue:
    async with _client(attacker_token) as client:
        r = await client.post(
            f"/repos/{mirror_owner}/{mirror_repo}/issues",
            json={"title": title, "body": body},
        )
        if r.status_code not in (200, 201):
            raise RuntimeError(f"open_issue failed: {r.status_code} {r.text[:400]}")
        data = r.json()
        return OpenedIssue(
            number=data.get("number") or 0,
            html_url=data.get("html_url") or "",
        )


async def add_issue_comment(
    *,
    attacker_token: str,
    mirror_owner: str,
    mirror_repo: str,
    issue_number: int,
    body: str,
    log: Logger = _noop,
) -> str:
    async with _client(attacker_token) as client:
        r = await client.post(
            f"/repos/{mirror_owner}/{mirror_repo}/issues/{issue_number}/comments",
            json={"body": body},
        )
        if r.status_code not in (200, 201):
            raise RuntimeError(f"comment failed: {r.status_code} {r.text[:400]}")
        return r.json().get("html_url") or ""


async def dispatch_workflow(
    *,
    attacker_token: str,
    mirror_owner: str,
    mirror_repo: str,
    workflow_id_or_filename: str,
    ref: str,
    inputs: Optional[dict] = None,
    log: Logger = _noop,
) -> None:
    async with _client(attacker_token) as client:
        r = await client.post(
            f"/repos/{mirror_owner}/{mirror_repo}/actions/workflows/{workflow_id_or_filename}/dispatches",
            json={"ref": ref, "inputs": inputs or {}},
        )
        if r.status_code not in (200, 201, 204):
            raise RuntimeError(f"dispatch failed: {r.status_code} {r.text[:400]}")
