"""Smoke test for PAT token-pool rotation in GitHubClient.

Uses monkeypatched `_probe_token_rate_limit` / `client.get` so no real
network calls are made. Validates:
  1. Single-token construction still works (backward compat).
  2. Multi-token pool de-dupes and starts on the first token.
  3. check_rate_limit() proactively rotates away from a low-quota token.
  4. _get() reactively rotates on a 403 rate-limit response instead of
     raising immediately, and only raises once the whole pool is exhausted.
"""
import asyncio
import types
from unittest.mock import patch

import httpx

import main as m


def _resp(status_code, headers=None, json_body=None, text=""):
    r = httpx.Response(
        status_code=status_code,
        headers=headers or {},
        json=json_body,
        text=text if json_body is None else None,
        request=httpx.Request("GET", "https://api.github.com/x"),
    )
    return r


async def _run():
    # --- 1. Backward-compat single token ---
    gh = m.GitHubClient(token="tok-a", concurrency=2)
    assert gh.token_pool_size == 1
    assert gh.token == "tok-a"
    assert gh.client.headers["Authorization"] == "Bearer tok-a"
    await gh.close()
    print("single-token construction: ok")

    # --- 2. Multi-token pool + de-dupe ---
    gh = m.GitHubClient(tokens=["tok-a", "tok-b", "tok-a", "tok-c"])
    assert gh.token_pool_size == 3, gh.token_pool_size
    assert gh.token == "tok-a"
    await gh.close()
    print("multi-token pool de-dupe: ok")

    # --- 3. Proactive rotation in check_rate_limit() ---
    gh = m.GitHubClient(tokens=["tok-a", "tok-b"])

    async def fake_get(url, params=None):
        assert url == "/rate_limit"
        return _resp(200, headers={}, json_body={"resources": {"core": {"limit": 5000, "remaining": 10, "reset": 111}}})

    gh.client.get = fake_get

    async def fake_probe(tok):
        assert tok == "tok-b"
        return 5000, 4000, 222.0

    gh._probe_token_rate_limit = fake_probe
    limit, remaining, reset = await gh.check_rate_limit()
    assert gh.token == "tok-b", gh.token
    assert gh.client.headers["Authorization"] == "Bearer tok-b"
    assert gh.rotation_count == 1
    assert remaining == 4000, remaining
    await gh.close()
    print("proactive rotation on low quota: ok")

    # --- 4. Reactive rotation inside _get() on 403 rate-limit, then success ---
    gh = m.GitHubClient(tokens=["tok-a", "tok-b"])
    calls = {"n": 0}

    async def fake_client_get(url, params=None, *, follow_redirects=False):
        calls["n"] += 1
        if gh.token == "tok-a":
            return _resp(
                403,
                headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Limit": "60", "X-RateLimit-Reset": "999"},
                text="API rate limit exceeded",
            )
        return _resp(200, headers={"X-RateLimit-Remaining": "59", "X-RateLimit-Limit": "60"}, text="ok")

    gh.client.get = fake_client_get

    async def fake_probe2(tok):
        assert tok == "tok-b"
        return 60, 59, 888.0

    gh._probe_token_rate_limit = fake_probe2
    r = await gh._get("/some/endpoint")
    assert r.status_code == 200
    assert gh.token == "tok-b"
    assert gh.client.headers["Authorization"] == "Bearer tok-b"
    assert gh.rotation_count == 1
    assert 0 in gh._exhausted_token_idx
    await gh.close()
    print("reactive rotation on 403 rate-limit: ok")

    # --- 5. Whole pool exhausted -> raises GitHubRateLimitExceeded ---
    gh = m.GitHubClient(tokens=["tok-a", "tok-b"])

    async def fake_client_get_all_exhausted(url, params=None, *, follow_redirects=False):
        return _resp(
            403,
            headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Limit": "60", "X-RateLimit-Reset": "999"},
            text="API rate limit exceeded",
        )

    gh.client.get = fake_client_get_all_exhausted

    async def fake_probe_none(tok):
        return None, None, None

    gh._probe_token_rate_limit = fake_probe_none
    try:
        await gh._get("/some/endpoint")
        raise AssertionError("expected GitHubRateLimitExceeded")
    except m.GitHubRateLimitExceeded:
        pass
    await gh.close()
    print("whole-pool exhaustion raises GitHubRateLimitExceeded: ok")

    with patch.object(m, "load_saved_tokens", return_value=[
        {"token": "tok-a", "login": "alice"}, {"token": "tok-b", "login": "bob"},
    ]):
        gh = m.GitHubClient(tokens=["tok-a", "tok-b"])
    gh.client.get = fake_get
    gh._probe_token_rate_limit = fake_probe
    await gh.check_rate_limit()
    quota = gh.pool_quota()
    assert quota["pool_rate_limit_limit"] == 10000
    assert quota["pool_rate_limit_remaining"] == 4010
    assert quota["pool_tokens_checked"] == 2
    gh._token_accounts = ["alice", "alice"]
    assert gh.pool_quota()["pool_rate_limit_limit"] == 5000
    assert gh.pool_quota()["pool_rate_limit_remaining"] == 10
    gh._record_token_quota(0, None, None, None)
    assert gh.pool_quota()["pool_tokens_checked"] == 1
    await gh.close()
    print("combined account quotas, shared-account de-duplication and partial coverage: ok")

    gh = m.GitHubClient(tokens=["tok-a", "tok-b"], concurrency=2)
    both_started = asyncio.Event()
    rotated = asyncio.Event()
    old_calls = 0

    async def concurrent_get(url, **kwargs):
        nonlocal old_calls
        if gh.token == "tok-a":
            old_calls += 1
            call = old_calls
            if old_calls == 2:
                both_started.set()
            await both_started.wait()
            if call == 2:
                await rotated.wait()
            return _resp(403, headers={
                "X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "100",
            }, text="API rate limit exceeded")
        return _resp(200, headers={
            "X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "1",
            "X-RateLimit-Reset": "200",
        })

    async def concurrent_probe(tok):
        assert tok == "tok-b"
        rotated.set()
        return 5000, 2, 200.0

    gh.client.get = concurrent_get
    gh._probe_token_rate_limit = concurrent_probe
    responses = await asyncio.wait_for(
        asyncio.gather(gh._get("/first"), gh._get("/second")), timeout=2,
    )
    assert all(response.status_code == 200 for response in responses)
    assert gh.rotation_count == 1 and gh._exhausted_token_idx == {0}
    assert gh.client.headers["Authorization"] == "Bearer tok-b"
    assert gh._rate_limit_exhausted is None and gh.rate_limit_remaining == 1
    assert gh.pool_quota()["pool_rate_limit_limit"] == 10000
    await gh.close()
    print("concurrent late responses preserve rotation and use low-but-usable second token: ok")

    gh = m.GitHubClient(tokens=["tok-a", "tok-b"])
    gh.client.get = fake_client_get_all_exhausted

    async def exhausted_probe(tok):
        return 5000, 0, 2000.0

    gh._probe_token_rate_limit = exhausted_probe
    try:
        await gh._get("/all-exhausted")
        raise AssertionError("Expected pool exhaustion")
    except m.GitHubRateLimitExceeded as exc:
        assert exc.reset_epoch == 999
    assert gh.pool_quota()["pool_rate_limit_remaining"] == 0
    await gh.close()
    print("pool exhaustion uses the earliest account reset: ok")

    gh = m.GitHubClient(tokens=["tok-a", "tok-b"])
    gh._record_token_quota(0, 5000, 3334, m.time.time() + 1800)
    gh._record_token_quota(1, 5000, 0, m.time.time() - 1)
    gh._exhausted_token_idx.add(1)

    async def reset_probe(tok):
        assert tok == "tok-b"
        return 5000, 5000, m.time.time() + 3600

    gh._probe_token_rate_limit = reset_probe
    assert await gh._rotate_to_next_token()
    assert gh.token == "tok-b" and 1 not in gh._exhausted_token_idx
    assert gh.pool_quota()["pool_rate_limit_remaining"] == 8334
    await gh.close()
    print("previously exhausted tokens become eligible again after their reset: ok")

    gh = m.GitHubClient(tokens=["tok-a", "tok-b"])
    # The interval is shortened only for this test, with active quota kept fresh.
    gh.POOL_REFRESH_SECONDS = 0.01
    refreshed = asyncio.Event()
    probes = 0

    async def live_get(url, **kwargs):
        return _resp(200, json_body={"resources": {"core": {
            "limit": 5000, "remaining": 3334, "reset": m.time.time() + 1800,
        }}})

    async def live_probe(tok):
        nonlocal probes
        if tok == "tok-a":
            return 5000, 3334, m.time.time() + 1800
        probes += 1
        if probes == 1:
            return 5000, 0, m.time.time() - 1
        refreshed.set()
        return 5000, 5000, m.time.time() + 3600

    gh.client.get = live_get
    gh._probe_token_rate_limit = live_probe
    await gh.check_rate_limit()
    gh._exhausted_token_idx.add(1)
    assert gh.pool_quota()["pool_rate_limit_remaining"] == 3334
    refresh_task = gh._quota_refresh_task
    await asyncio.wait_for(refreshed.wait(), timeout=2)
    assert gh.pool_quota()["pool_rate_limit_remaining"] == 8334
    assert 1 not in gh._exhausted_token_idx
    assert len(gh.pool_quota()["pool_accounts"]) == 2
    await gh.close()
    assert refresh_task.done() and gh._quota_refresh_task is None
    print("running clients refresh inactive account quotas without UI polling and stop on close: ok")

    # --- 6. Legacy token-file format upgrades transparently ---
    import tempfile, pathlib, json as _json
    old_file = m.TOKEN_FILE
    old_dir = m.TOKEN_DIR
    with tempfile.TemporaryDirectory() as d:
        m.TOKEN_DIR = pathlib.Path(d)
        m.TOKEN_FILE = m.TOKEN_DIR / "tokens.json"
        m.TOKEN_FILE.write_text(_json.dumps({"token": "legacy-tok", "login": "legacy-user", "saved_at": 1.0}))
        pool = m.load_saved_tokens()
        assert len(pool) == 1 and pool[0]["token"] == "legacy-tok", pool
        rec = m.load_saved_token()
        assert rec["token"] == "legacy-tok"
        m.save_token("new-tok", "new-user")
        pool = m.load_saved_tokens()
        assert len(pool) == 2, pool
        assert pool[0]["token"] == "new-tok"
        removed = m.remove_saved_token(login="legacy-user")
        assert removed
        pool = m.load_saved_tokens()
        assert len(pool) == 1 and pool[0]["login"] == "new-user"
    m.TOKEN_DIR = old_dir
    m.TOKEN_FILE = old_file
    print("legacy token-file upgrade + pool CRUD: ok")

    print("\nAll token-rotation smoke tests passed.")


if __name__ == "__main__":
    asyncio.run(_run())
