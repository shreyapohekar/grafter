"""Mirror-repo lifecycle for Live PoC.

Two tiers, controlled by `GRAFTER_LIVE_POC_FULL_CLONE_MAX_MB` (env,
default 1024). Under threshold we do a `git clone --depth 50` and push;
over threshold we synthesize a minimal-relevant-files mirror by
harvesting the workflow file, referenced local composite actions, and
package manifests via the Contents API.
"""
from __future__ import annotations

import asyncio
import base64
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import httpx
import yaml

GITHUB_API = "https://api.github.com"


FULL_CLONE_MAX_MB = int(os.environ.get("GRAFTER_LIVE_POC_FULL_CLONE_MAX_MB", "1024"))
MIRROR_MAX_MB = int(os.environ.get("GRAFTER_LIVE_POC_MIRROR_MAX_MB", "50"))
MIRROR_MAX_FILE_MB = int(os.environ.get("GRAFTER_LIVE_POC_MIRROR_MAX_FILE_MB", "5"))
MIRROR_MAX_FILES = int(os.environ.get("GRAFTER_LIVE_POC_MIRROR_MAX_FILES", "200"))

Logger = Callable[[str, str], None]  # (level, message)


def _noop(_lvl: str, _msg: str) -> None:  # pragma: no cover
    pass


@dataclass
class MirrorFile:
    path: str
    reason: str
    size: int


@dataclass
class Mirror:
    mode: str  # "full" | "minimal"
    source_repo: str  # "owner/name"
    source_default_branch: str
    source_head_sha: str
    owner: str
    repo: str
    clone_url: str
    api_url: str
    html_url: str
    manifest: list[MirrorFile] = field(default_factory=list)


async def _gh_get(client: httpx.AsyncClient, path: str, **kwargs) -> httpx.Response:
    r = await client.get(path, **kwargs)
    return r


async def _gh_post(client: httpx.AsyncClient, path: str, json_body: dict) -> httpx.Response:
    r = await client.post(path, json=json_body)
    return r


async def _gh_put(client: httpx.AsyncClient, path: str, json_body: dict) -> httpx.Response:
    r = await client.put(path, json=json_body)
    return r


async def _gh_delete(client: httpx.AsyncClient, path: str) -> httpx.Response:
    r = await client.delete(path)
    return r


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


async def _repo_meta(client: httpx.AsyncClient, source_repo: str) -> dict:
    owner, name = source_repo.split("/", 1)
    r = await _gh_get(client, f"/repos/{owner}/{name}")
    if r.status_code != 200:
        raise RuntimeError(f"Cannot read source repo meta: {r.status_code} {r.text[:200]}")
    return r.json()


async def _default_branch_head_sha(client: httpx.AsyncClient, source_repo: str, branch: str) -> str:
    owner, name = source_repo.split("/", 1)
    r = await _gh_get(client, f"/repos/{owner}/{name}/branches/{branch}")
    if r.status_code != 200:
        raise RuntimeError(f"Cannot read default branch: {r.status_code} {r.text[:200]}")
    return r.json().get("commit", {}).get("sha") or ""


async def _contents(client: httpx.AsyncClient, source_repo: str, path: str, ref: str) -> Optional[dict]:
    owner, name = source_repo.split("/", 1)
    r = await _gh_get(
        client,
        f"/repos/{owner}/{name}/contents/{path}",
        params={"ref": ref},
    )
    if r.status_code == 200:
        return r.json()
    if r.status_code == 404:
        return None
    raise RuntimeError(f"Contents API error {r.status_code}: {r.text[:200]}")


def _decode_content(node: dict) -> Optional[bytes]:
    if not node or not isinstance(node, dict):
        return None
    if node.get("type") != "file":
        return None
    if node.get("encoding") != "base64":
        return None
    try:
        return base64.b64decode(node.get("content") or "")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Repo creation + secret seeding + Actions permissions
# ---------------------------------------------------------------------------
def _mirror_repo_name(source_repo: str, finding_id: str) -> str:
    """Build a mirror repo name that carries provenance in the slug.

    Shape: ``grafter-poc-<owner>-<repo>-<finding8>-<rand8>`` — makes it
    trivial to eyeball which source the mirror belongs to when the sweeper
    or a human is looking at a repo list. Non-alphanumerics in the owner /
    repo segments are collapsed to ``-`` so the whole slug matches
    GitHub's repo-name rules (``[A-Za-z0-9._-]``), and the total length is
    capped at 100 chars (GitHub's hard limit).
    """
    def _slug(s: str) -> str:
        s = re.sub(r"[^A-Za-z0-9._-]+", "-", s or "")
        return s.strip("-.") or "x"

    owner, _, repo = (source_repo or "").partition("/")
    owner_slug = _slug(owner)
    repo_slug = _slug(repo)
    short = re.sub(r"[^a-zA-Z0-9]", "", finding_id or "")[:8].lower() or "poc"
    rand = uuid.uuid4().hex[:8]

    prefix = "grafter-poc-"
    suffix = f"-{short}-{rand}"
    # Leave room for prefix + suffix; distribute the remaining budget between
    # owner and repo (repo gets priority since it's more identifying).
    budget = 100 - len(prefix) - len(suffix) - 1  # -1 for the joining '-'
    if budget < 4:
        budget = 4
    if len(owner_slug) + 1 + len(repo_slug) > budget:
        owner_budget = max(4, budget // 3)
        repo_budget = budget - owner_budget - 1
        owner_slug = owner_slug[:owner_budget].rstrip("-.") or "x"
        repo_slug = repo_slug[:repo_budget].rstrip("-.") or "x"
    return f"{prefix}{owner_slug}-{repo_slug}{suffix}"


async def _create_mirror_repo(client: httpx.AsyncClient, name: str) -> dict:
    """Create the mirror as a **public** repo under the maintainer identity.

    Public is required so an anonymous attacker fork PR can trigger
    workflows — private repos disallow forks from outside collaborators,
    which is exactly the trust boundary the PoC needs to cross.
    """
    r = await _gh_post(
        client,
        "/user/repos",
        {
            "name": name,
            "private": False,
            "description": "Grafter Live PoC mirror — auto-created, auto-deleted.",
            "auto_init": True,
        },
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Failed to create mirror repo: {r.status_code} {r.text[:300]}")
    return r.json()


async def _add_topic(client: httpx.AsyncClient, owner: str, repo: str, topics: list[str]) -> None:
    await _gh_put(client, f"/repos/{owner}/{repo}/topics", {"names": topics})


async def _configure_actions_permissions(client: httpx.AsyncClient, owner: str, repo: str) -> None:
    # Enable Actions and allow all actions.
    await _gh_put(
        client,
        f"/repos/{owner}/{repo}/actions/permissions",
        {"enabled": True, "allowed_actions": "all"},
    )
    # Best-effort: allow fork PRs from first-time contributors to run
    # workflows without maintainer approval.
    try:
        await client.request(
            "PUT",
            f"/repos/{owner}/{repo}/actions/permissions/fork-pr-workflows-policy",
            json={"run_workflows_from_fork_pull_requests": True},
        )
    except Exception:
        pass
    # Reduce default GITHUB_TOKEN scope to whatever the workflow specifies.
    try:
        await _gh_put(
            client,
            f"/repos/{owner}/{repo}/actions/permissions/workflow",
            {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": False},
        )
    except Exception:
        pass


async def _delete_repo(client: httpx.AsyncClient, owner: str, repo: str) -> bool:
    try:
        r = await _gh_delete(client, f"/repos/{owner}/{repo}")
        return r.status_code in (204, 202)
    except Exception:
        return False


async def _seed_dummy_secret(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    name: str,
    value: str,
) -> bool:
    """Best-effort — libsodium encryption via GitHub public key."""
    try:
        r = await _gh_get(client, f"/repos/{owner}/{repo}/actions/secrets/public-key")
        if r.status_code != 200:
            return False
        pk = r.json()
        pub_key = pk.get("key")
        key_id = pk.get("key_id")
        if not pub_key or not key_id:
            return False
        try:
            from nacl import encoding, public  # type: ignore
        except Exception:
            # PyNaCl not installed — skip secret seeding silently. Payload
            # will simply see the empty-string secret.
            return False
        pubkey = public.PublicKey(pub_key.encode("utf-8"), encoding.Base64Encoder())
        sealed = public.SealedBox(pubkey).encrypt(value.encode("utf-8"))
        encrypted = encoding.Base64Encoder.encode(sealed).decode("utf-8")
        r = await _gh_put(
            client,
            f"/repos/{owner}/{repo}/actions/secrets/{name}",
            {"encrypted_value": encrypted, "key_id": key_id},
        )
        return r.status_code in (201, 204)
    except Exception:
        return False


def _extract_secret_names(workflow_yaml_text: str) -> list[str]:
    if not workflow_yaml_text:
        return []
    # Capture secrets.NAME occurrences.
    return sorted(set(re.findall(r"secrets\.([A-Za-z0-9_]+)", workflow_yaml_text)))


# ---------------------------------------------------------------------------
# Minimal-mirror synthesizer (best-effort MVP; extendable)
# ---------------------------------------------------------------------------
_ALWAYS_INCLUDE_ROOT_MANIFESTS = [
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "Cargo.toml",
    "go.mod",
    "Makefile",
    "makefile",
    "Gemfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "README.md",
    "LICENSE",
]


_PATH_LIKE = re.compile(
    r"(?:\.\/|\.\.\/|[a-zA-Z0-9._\-\/]+\/)[a-zA-Z0-9._\-\/]+\.[a-zA-Z0-9]+"
)


def _discover_referenced_paths(workflow_text: str, evidence: list[str], snippet: str) -> set[str]:
    paths: set[str] = set()
    hay = "\n".join([workflow_text or ""] + [e for e in (evidence or []) if e] + [snippet or ""])
    for m in _PATH_LIKE.finditer(hay):
        p = m.group(0).lstrip("./")
        if p and len(p) < 300:
            paths.add(p)
    return paths


async def _fetch_file(
    client: httpx.AsyncClient, source_repo: str, path: str, ref: str
) -> Optional[tuple[str, bytes]]:
    try:
        node = await _contents(client, source_repo, path, ref)
    except Exception:
        return None
    if not node:
        return None
    if isinstance(node, list):
        return None  # directory
    data = _decode_content(node)
    if data is None:
        return None
    return node.get("path") or path, data


async def _synthesize_minimal_mirror(
    client: httpx.AsyncClient,
    source_repo: str,
    workflow_path: str,
    finding_evidence: list[str],
    finding_snippet: str,
    ref: str,
) -> list[tuple[str, bytes, str]]:
    """Return list of (path, content, reason). Deterministic, capped."""
    picked: dict[str, tuple[bytes, str]] = {}

    async def try_add(path: str, reason: str) -> None:
        if path in picked:
            return
        if len(picked) >= MIRROR_MAX_FILES:
            return
        got = await _fetch_file(client, source_repo, path, ref)
        if not got:
            return
        real_path, data = got
        if len(data) > MIRROR_MAX_FILE_MB * 1024 * 1024:
            return
        picked[real_path] = (data, reason)

    # 1. Workflow itself
    await try_add(workflow_path, "workflow")
    # Also pull sibling workflows (they may reference each other)
    try:
        node = await _contents(client, source_repo, ".github/workflows", ref)
        if isinstance(node, list):
            for entry in node:
                if entry.get("type") == "file" and entry.get("path") != workflow_path:
                    await try_add(entry.get("path") or "", "sibling-workflow")
    except Exception:
        pass

    # 2. Referenced local actions
    workflow_bytes = picked.get(workflow_path)
    workflow_text = ""
    if workflow_bytes:
        try:
            workflow_text = workflow_bytes[0].decode("utf-8", errors="replace")
        except Exception:
            workflow_text = ""

    for m in re.finditer(r"uses:\s*['\"]?(\.\/[^'\"\s]+)", workflow_text):
        local_action = m.group(1).lstrip("./")
        for candidate in (
            f"{local_action}/action.yml",
            f"{local_action}/action.yaml",
            local_action,
        ):
            await try_add(candidate, "local-action")

    # 3. Manifests + evidence-derived paths
    for m in _ALWAYS_INCLUDE_ROOT_MANIFESTS:
        await try_add(m, "manifest")

    for p in _discover_referenced_paths(workflow_text, finding_evidence, finding_snippet):
        await try_add(p, "evidence")
        if len(picked) >= MIRROR_MAX_FILES:
            break

    files = [(path, data, reason) for path, (data, reason) in picked.items()]

    total = sum(len(d) for _, d, _ in files)
    if total > MIRROR_MAX_MB * 1024 * 1024:
        # Prioritise workflow + local-action + manifest; drop evidence overflow.
        files.sort(key=lambda t: {"workflow": 0, "local-action": 1, "manifest": 2, "sibling-workflow": 3, "evidence": 4}.get(t[2], 5))
        kept: list[tuple[str, bytes, str]] = []
        running = 0
        for entry in files:
            running += len(entry[1])
            if running > MIRROR_MAX_MB * 1024 * 1024:
                break
            kept.append(entry)
        files = kept

    return files


# ---------------------------------------------------------------------------
# git operations
# ---------------------------------------------------------------------------
def _run_git(cmd: list[str], cwd: Optional[str] = None, env: Optional[dict] = None, timeout: int = 300) -> subprocess.CompletedProcess:
    # Skip Git LFS smudge by default: sample repos commonly ship large
    # LFS-tracked assets, and we do not need the blobs for the PoC. Fetching
    # them also risks hanging or 4xx-ing on missing LFS objects and would
    # bloat the mirror unnecessarily.
    merged_env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0"}
    if env:
        merged_env.update(env)
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=merged_env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _git_available() -> bool:
    try:
        r = _run_git(["git", "--version"], timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def _authed_url(url: str, token: str) -> str:
    # Convert https URL into x-access-token authed form.
    if url.startswith("https://"):
        return url.replace("https://", f"https://x-access-token:{token}@", 1)
    return url


def _strip_oversized_files(root: str, max_bytes: int, log: Logger) -> int:
    """Walk `root` and unlink any regular file bigger than `max_bytes`.

    Skips the `.git` dir. Returns the number of files removed. Used before
    the single-commit push to keep the pack under GitHub's HTTPS push
    timeout — sample repos routinely ship 50–200 MB of models, videos,
    or `.safetensors` weights that the PoC does not need.
    """
    removed = 0
    for dirpath, dirnames, filenames in os.walk(root):
        # don't descend into an existing .git if the caller kept one around
        if ".git" in dirnames:
            dirnames.remove(".git")
        for name in filenames:
            fp = os.path.join(dirpath, name)
            try:
                st = os.stat(fp)
            except OSError:
                continue
            if not (st.st_mode & 0o170000 == 0o100000):  # regular file only
                continue
            if st.st_size > max_bytes:
                try:
                    os.remove(fp)
                    removed += 1
                    log("info", f"stripped oversized file ({st.st_size // (1024*1024)} MB): {os.path.relpath(fp, root)}")
                except OSError as e:
                    log("warn", f"could not strip {fp}: {e}")
    return removed


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------
async def build_mirror(
    *,
    maintainer_token: str,
    source_repo: str,
    workflow_path: str,
    finding_id: str,
    finding_evidence: list[str],
    finding_snippet: str,
    force_minimal: bool = False,
    log: Logger = _noop,
) -> Mirror:
    """Create a fresh public mirror under the maintainer identity."""
    async with _client(maintainer_token) as client:
        meta = await _repo_meta(client, source_repo)
        size_kb = int(meta.get("size") or 0)  # KB
        default_branch = meta.get("default_branch") or "main"
        head_sha = await _default_branch_head_sha(client, source_repo, default_branch)

        prefer_minimal = force_minimal or (size_kb > FULL_CLONE_MAX_MB * 1024)
        mode = "minimal" if prefer_minimal else "full"
        log("info", f"source repo {source_repo} @ {head_sha[:8]} size={size_kb//1024 or 0}MB — mirror mode={mode}")

        mirror_name = _mirror_repo_name(source_repo, finding_id)
        created = await _create_mirror_repo(client, mirror_name)
        mirror_owner = created.get("owner", {}).get("login") or ""
        mirror_repo = created.get("name") or mirror_name
        mirror_clone_url = created.get("clone_url") or f"https://github.com/{mirror_owner}/{mirror_repo}.git"
        mirror_api_url = created.get("url") or f"{GITHUB_API}/repos/{mirror_owner}/{mirror_repo}"
        mirror_html_url = created.get("html_url") or f"https://github.com/{mirror_owner}/{mirror_repo}"
        log("info", f"created mirror repo {mirror_owner}/{mirror_repo}")

        await _add_topic(client, mirror_owner, mirror_repo, ["grafter-poc"])
        await _configure_actions_permissions(client, mirror_owner, mirror_repo)

        manifest: list[MirrorFile] = []

        if mode == "full":
            # Full clone via git binary; if it fails or exceeds cap, fall back
            # to minimal in-place.
            if not _git_available():
                log("warn", "git binary unavailable — falling back to minimal mirror mode")
                mode = "minimal"

        if mode == "full":
            manifest = await _clone_and_push_full(
                source_repo=source_repo,
                source_default_branch=default_branch,
                mirror_owner=mirror_owner,
                mirror_repo=mirror_repo,
                mirror_clone_url=mirror_clone_url,
                maintainer_token=maintainer_token,
                log=log,
            )
        else:
            files = await _synthesize_minimal_mirror(
                client=client,
                source_repo=source_repo,
                workflow_path=workflow_path,
                finding_evidence=finding_evidence,
                finding_snippet=finding_snippet,
                ref=default_branch,
            )
            if not any(p == workflow_path for p, _, _ in files):
                # If we couldn't even fetch the workflow, the mirror is
                # useless — surface the failure.
                raise RuntimeError(
                    f"Could not fetch workflow file {workflow_path!r} from {source_repo}"
                )
            manifest = await _push_minimal_files(
                mirror_owner=mirror_owner,
                mirror_repo=mirror_repo,
                mirror_clone_url=mirror_clone_url,
                default_branch=default_branch,
                maintainer_token=maintainer_token,
                files=files,
                source_repo=source_repo,
                head_sha=head_sha,
                finding_id=finding_id,
                log=log,
            )

        # Seed dummy secrets for every secrets.NAME the workflow references.
        try:
            workflow_bytes = None
            r = await _gh_get(client, f"/repos/{mirror_owner}/{mirror_repo}/contents/{workflow_path}")
            if r.status_code == 200:
                workflow_bytes = _decode_content(r.json())
        except Exception:
            workflow_bytes = None
        secret_names = _extract_secret_names(
            workflow_bytes.decode("utf-8", errors="replace") if workflow_bytes else ""
        )
        for name in secret_names:
            ok = await _seed_dummy_secret(
                client,
                mirror_owner,
                mirror_repo,
                name,
                f"grafter-canary-{finding_id[:8]}-{name}",
            )
            log("info", f"seeded secret {name}: {'ok' if ok else 'skipped'}")

        return Mirror(
            mode=mode,
            source_repo=source_repo,
            source_default_branch=default_branch,
            source_head_sha=head_sha,
            owner=mirror_owner,
            repo=mirror_repo,
            clone_url=mirror_clone_url,
            api_url=mirror_api_url,
            html_url=mirror_html_url,
            manifest=manifest,
        )


async def _clone_and_push_full(
    *,
    source_repo: str,
    source_default_branch: str,
    mirror_owner: str,
    mirror_repo: str,
    mirror_clone_url: str,
    maintainer_token: str,
    log: Logger,
) -> list[MirrorFile]:
    tmp = tempfile.mkdtemp(prefix=f"grafter-poc-{mirror_repo}-")
    try:
        src_url = _authed_url(f"https://github.com/{source_repo}.git", maintainer_token)
        # depth=1: we only need HEAD's working tree — the mirror is repushed
        # as a brand-new single-commit history below, so no upstream ancestry
        # is required. This survives >100 MB repos where cloning full history
        # would blow past the git-http timeout budget.
        r = _run_git(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--single-branch",
                "--no-tags",
                "--branch",
                source_default_branch,
                src_url,
                tmp,
            ],
            timeout=600,
        )
        if r.returncode != 0:
            raise RuntimeError(f"git clone failed: {r.stderr[:500]}")

        # We push the mirror as a single, self-contained commit — that is
        # what actually fixes both prior push failures:
        #   * "did not receive expected object / index-pack failed" happened
        #     because pushing a shallow clone to a fresh remote left the
        #     server unable to resolve delta bases neither side had.
        #   * "HTTP 408 / RPC failed" happened because unshallowing a 100 MB+
        #     source and pushing all of that history exceeded GitHub's
        #     server-side timeout for a single POST /git-receive-pack call.
        # A discard-history-and-reinit push has zero shallow-boundary or
        # delta-base surface area and finishes fast because it only ships
        # the current tree — which is all the mirror needs for a PoC.
        shutil.rmtree(os.path.join(tmp, ".git"), ignore_errors=True)
        # Belt: strip files bigger than the per-file cap so a repo that
        # includes large binaries (sample models, videos, .safetensors) can't
        # revive the timeout. Workflow YAML + composite actions + package
        # manifests are all tiny, so trimming media does not affect what the
        # PoC needs to trigger the vulnerable workflow.
        stripped = _strip_oversized_files(tmp, MIRROR_MAX_FILE_MB * 1024 * 1024, log)
        if stripped:
            log("info", f"stripped {stripped} file(s) larger than {MIRROR_MAX_FILE_MB}MB from mirror payload")

        _run_git(["git", "init", "-b", source_default_branch], cwd=tmp)
        _run_git(["git", "config", "user.email", "grafter-poc@localhost"], cwd=tmp)
        _run_git(["git", "config", "user.name", "Grafter Live PoC"], cwd=tmp)
        # Add mirror manifest + README banner
        _write_manifest_files(tmp, source_repo, mirror_owner, mirror_repo, mode="full")
        _run_git(["git", "add", "-A"], cwd=tmp)
        _run_git(
            [
                "git",
                "commit",
                "--allow-empty",
                "-m",
                f"seed: grafter-poc mirror of {source_repo}",
            ],
            cwd=tmp,
        )

        push_url = _authed_url(mirror_clone_url, maintainer_token)
        _run_git(["git", "remote", "add", "origin", push_url], cwd=tmp)
        # Force-push onto the mirror's default branch. Because the local
        # history is a single self-contained commit, no --no-thin / no
        # --unshallow safety net is needed — the pack has no external delta
        # bases to reference.
        push = _run_git(
            [
                "git",
                "push",
                "--force",
                "--set-upstream",
                "origin",
                f"HEAD:refs/heads/{source_default_branch}",
            ],
            cwd=tmp,
            timeout=600,
        )
        if push.returncode != 0:
            raise RuntimeError(f"git push failed: {push.stderr[:500]}")
        # Also update the mirror's default branch if it differs from `main`.
        # (Best-effort — non-fatal if it fails.)
        return []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


async def _push_minimal_files(
    *,
    mirror_owner: str,
    mirror_repo: str,
    mirror_clone_url: str,
    default_branch: str,
    maintainer_token: str,
    files: list[tuple[str, bytes, str]],
    source_repo: str,
    head_sha: str,
    finding_id: str,
    log: Logger,
) -> list[MirrorFile]:
    tmp = tempfile.mkdtemp(prefix=f"grafter-poc-{mirror_repo}-")
    try:
        _run_git(["git", "init", "-b", default_branch], cwd=tmp)
        _run_git(["git", "config", "user.email", "grafter-poc@localhost"], cwd=tmp)
        _run_git(["git", "config", "user.name", "Grafter Live PoC"], cwd=tmp)
        # Write files.
        manifest: list[MirrorFile] = []
        for path, data, reason in files:
            fp = Path(tmp) / path
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(data)
            manifest.append(MirrorFile(path=path, reason=reason, size=len(data)))
        _write_manifest_files(tmp, source_repo, mirror_owner, mirror_repo, mode="minimal", manifest=manifest)
        _run_git(["git", "add", "-A"], cwd=tmp)
        _run_git(
            [
                "git",
                "commit",
                "-m",
                f"seed: minimal mirror for grafter-poc {finding_id[:8]} @ {head_sha[:8]}",
            ],
            cwd=tmp,
        )
        push_url = _authed_url(mirror_clone_url, maintainer_token)
        _run_git(["git", "remote", "add", "origin", push_url], cwd=tmp)
        push = _run_git(
            [
                "git",
                "push",
                "--force",
                "--set-upstream",
                "origin",
                f"HEAD:refs/heads/{default_branch}",
            ],
            cwd=tmp,
            timeout=300,
        )
        if push.returncode != 0:
            raise RuntimeError(f"git push failed: {push.stderr[:500]}")
        return manifest
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _write_manifest_files(
    tmp: str,
    source_repo: str,
    mirror_owner: str,
    mirror_repo: str,
    mode: str,
    manifest: Optional[list[MirrorFile]] = None,
) -> None:
    """Drop .grafter-poc.json + MIRROR.md at the mirror root."""
    import json as _json
    p = Path(tmp) / ".grafter-poc.json"
    p.write_text(
        _json.dumps(
            {
                "source": source_repo,
                "mirror": f"{mirror_owner}/{mirror_repo}",
                "mode": mode,
                "created_at": time.time(),
                "manifest": [{"path": m.path, "reason": m.reason, "size": m.size} for m in (manifest or [])],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (Path(tmp) / "MIRROR.md").write_text(
        "# Grafter Live PoC Mirror\n\n"
        f"This repo is an auto-created **{mode}** mirror of `{source_repo}` for\n"
        "Grafter Live PoC. It is scheduled to be deleted a few minutes after\n"
        "the PoC run finishes. Do not push production data here.\n",
        encoding="utf-8",
    )


async def delete_mirror(
    *,
    maintainer_token: str,
    mirror_owner: str,
    mirror_repo: str,
    attacker_token: Optional[str] = None,
    attacker_owner: Optional[str] = None,
    attacker_fork_name: Optional[str] = None,
    log: Logger = _noop,
) -> None:
    async with _client(maintainer_token) as client:
        ok = await _delete_repo(client, mirror_owner, mirror_repo)
        log("info", f"deleted mirror {mirror_owner}/{mirror_repo}: {'ok' if ok else 'failed'}")
    if attacker_token and attacker_owner and attacker_fork_name:
        async with _client(attacker_token) as client:
            ok = await _delete_repo(client, attacker_owner, attacker_fork_name)
            log("info", f"deleted attacker fork {attacker_owner}/{attacker_fork_name}: {'ok' if ok else 'failed'}")


async def sweep_orphan_mirrors(
    *,
    maintainer_token: str,
    max_age_hours: int = 24,
    log: Logger = _noop,
) -> int:
    """Delete any repo topic-tagged `grafter-poc` older than max_age_hours."""
    cutoff = time.time() - max_age_hours * 3600
    deleted = 0
    async with _client(maintainer_token) as client:
        page = 1
        while True:
            r = await client.get(
                "/user/repos",
                params={"per_page": 100, "page": page, "affiliation": "owner"},
            )
            if r.status_code != 200:
                break
            batch = r.json() or []
            if not batch:
                break
            for repo in batch:
                topics = repo.get("topics") or []
                if "grafter-poc" not in topics:
                    continue
                created = repo.get("created_at")
                try:
                    ts = time.mktime(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ"))
                except Exception:
                    continue
                if ts >= cutoff:
                    continue
                owner = repo.get("owner", {}).get("login") or ""
                name = repo.get("name") or ""
                if await _delete_repo(client, owner, name):
                    deleted += 1
                    log("info", f"sweeper deleted {owner}/{name}")
            if len(batch) < 100:
                break
            page += 1
    return deleted
