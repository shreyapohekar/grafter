import asyncio
import os
import shutil
import tempfile
from unittest.mock import AsyncMock, patch

import httpx

data_dir = tempfile.mkdtemp(prefix="grafter-queue-smoke-")
os.environ["GRAFTER_DATA_DIR"] = data_dir

import main as m


async def check_live_progress():
    gh = m.GitHubClient(token="not-stored", concurrency=1)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def slow_get(url, **kwargs):
        entered.set()
        await release.wait()
        return httpx.Response(200, headers={
            "X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "3999",
        })

    gh.client.get = slow_get
    job, _ = m.db_create_scan_job(
        "live-telemetry", m.ScanRequest(org="telemetry", token="not-stored"),
    )
    m.db_update_scan_job(job["id"], state="running")
    state = m.ScanState(
        id=job["scan_id"], job_id=job["id"], github_client=gh,
        activity="telemetry/one: Downloading workflow", activity_updated_at=1,
        repository_activity={"telemetry/one": "Downloading workflow"},
        workflows_scanned=3,
    )
    m.SCANS[state.id] = state
    first = asyncio.create_task(gh._get("/first"))
    await asyncio.wait_for(entered.wait(), timeout=2)
    second = asyncio.create_task(gh._get("/second"))
    await asyncio.sleep(0)
    try:
        page = await m.list_scan_jobs_endpoint()
        live = next(item for item in page.items if item.id == job["id"])
        assert live.requests_queued == 1 and live.requests_in_flight == 1, live
        assert live.activity == state.activity and live.active_repositories == 1
        assert live.workflows_scanned == 3 and live.repos_completed == 0
        second.cancel()
        await asyncio.gather(second, return_exceptions=True)
        assert gh.requests_queued == 0 and gh.requests_in_flight == 1
        release.set()
        await first
        live = await m.get_scan_job_endpoint(job["id"])
        assert live.requests_completed == 1 and live.last_response_at
        assert live.rate_limit_remaining == 3999 and live.rate_limit_limit == 5000
        assert live.requests_in_flight == live.requests_queued == 0

        attempts = 0
        backing_off = asyncio.Event()

        async def retry_get(url, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                backing_off.set()
                return httpx.Response(
                    403, text="secondary rate limit",
                    headers={"Retry-After": "0.05", "X-RateLimit-Remaining": "3998"},
                )
            return httpx.Response(200)

        gh.client.get = retry_get
        retry = asyncio.create_task(gh._get("/retry"))
        await asyncio.wait_for(backing_off.wait(), timeout=2)
        live = await m.get_scan_job_endpoint(job["id"])
        assert live.requests_backing_off == 1 and live.requests_in_flight == 1
        await retry
        assert gh.requests_backing_off == gh.requests_in_flight == 0
        assert gh.requests_completed == 3

        entered.clear()
        release.clear()
        gh.client.get = slow_get
        cancelled = asyncio.create_task(gh._get("/cancel"))
        await asyncio.wait_for(entered.wait(), timeout=2)
        cancelled.cancel()
        await asyncio.gather(cancelled, return_exceptions=True)
        assert gh.requests_queued == gh.requests_in_flight == 0

        async def failed_get(url, **kwargs):
            raise httpx.ConnectError("offline")

        gh.client.get = failed_get
        with patch.object(gh, "_wait_before_retry", new=AsyncMock()):
            try:
                await gh._get("/offline")
                raise AssertionError("Expected a connection failure")
            except httpx.ConnectError:
                pass
        assert gh.requests_queued == gh.requests_in_flight == 0

        entered.clear()
        release.clear()
        exhausted_calls = 0

        async def exhausted_get(url, **kwargs):
            nonlocal exhausted_calls
            exhausted_calls += 1
            entered.set()
            await release.wait()
            return httpx.Response(403, text="API rate limit exceeded", headers={
                "X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "1",
            })

        gh.client.get = exhausted_get
        exhausted = asyncio.create_task(gh._get("/exhausted"))
        await asyncio.wait_for(entered.wait(), timeout=2)
        queued = asyncio.create_task(gh._get("/queued-after-exhaustion"))
        await asyncio.sleep(0)
        assert gh.requests_queued == 1
        release.set()
        results = await asyncio.gather(exhausted, queued, return_exceptions=True)
        assert all(isinstance(result, m.GitHubRateLimitExceeded) for result in results)
        assert exhausted_calls == 1, "Queued requests must not spend time calling an exhausted API"
        try:
            await gh._get("/new-after-exhaustion")
            raise AssertionError("Expected immediate quota exhaustion")
        except m.GitHubRateLimitExceeded:
            pass
        assert exhausted_calls == 1
        assert gh.requests_queued == gh.requests_in_flight == 0
        live = await m.get_scan_job_endpoint(job["id"])
        assert "All GitHub tokens are exhausted" in live.activity

        m.db_update_scan_job(job["id"], state="waiting_rate_limit")
        waiting = await m.get_scan_job_endpoint(job["id"])
        assert waiting.activity is None and waiting.requests_completed == 0
        m.db_update_scan_job(job["id"], state="cancelled")
        await m.delete_scan_job_endpoint(job["id"])
        print("live queue activity, request counters, retries and cancellation: ok")
    finally:
        release.set()
        first.cancel()
        second.cancel()
        await asyncio.gather(first, second, return_exceptions=True)
        m.SCANS.pop(state.id, None)
        await gh.close()


class FakeGitHubClient:
    fail_second_repo = True

    def __init__(self, token=None, concurrency=8, tokens=None):
        self.rate_limit_limit = 5000
        self.rate_limit_remaining = 4000
        self.rate_limit_reset = 0.0
        self.token_pool_size = len(tokens or [token])
        self.rotation_count = 0
        self._exhausted_token_idx = set()

    def pool_quota(self):
        return {
            "token_pool_size": self.token_pool_size,
            "token_rotations": self.rotation_count,
            "pool_tokens_checked": self.token_pool_size,
            "pool_rate_limit_limit": self.rate_limit_limit,
            "pool_rate_limit_remaining": self.rate_limit_remaining,
            "pool_rate_limit_reset": self.rate_limit_reset,
        }

    async def check_rate_limit(self):
        return self.rate_limit_limit, self.rate_limit_remaining, self.rate_limit_reset

    async def list_org_repos(self, org, include_forks, max_repos):
        return [
            {
                "owner": {"login": org},
                "name": "one",
                "full_name": f"{org}/one",
                "html_url": f"https://github.com/{org}/one",
                "default_branch": "main",
            },
            {
                "owner": {"login": org},
                "name": "two",
                "full_name": f"{org}/two",
                "html_url": f"https://github.com/{org}/two",
                "default_branch": "main",
            },
        ][:max_repos]

    async def list_workflows(self, owner, name):
        live = next(
            (item for item in (await m.list_scan_jobs_endpoint()).items
             if item.org == owner and item.state == "running"),
            None,
        )
        assert live and live.activity == f"{owner}/{name}: Listing workflow files", live
        assert live.active_repositories > 0
        if name == "two" and self.fail_second_repo:
            self.rate_limit_remaining = 0
            self.rate_limit_reset = 1
            raise m.GitHubRateLimitExceeded(5000, 0, 1)
        return []

    async def list_policies(self, owner, name):
        return []

    async def list_candidate_secret_files(self, owner, name, ref):
        return []

    async def close(self):
        return None


async def check_transport_retries():
    gh = m.GitHubClient(token="not-stored", concurrency=1)
    try:
        for failure in (httpx.ConnectError, httpx.ReadError, httpx.ReadTimeout, httpx.RemoteProtocolError):
            attempts = 0

            async def recover(url, **kwargs):
                nonlocal attempts
                attempts += 1
                if attempts < 3:
                    raise failure("temporary network failure")
                return httpx.Response(200)

            gh.client.get = recover
            with patch.object(gh, "_wait_before_retry", new=AsyncMock()) as backoff:
                assert (await gh._get("/recover")).status_code == 200
                assert attempts == 3 and backoff.await_count == 2
                assert gh.requests_in_flight == gh.requests_queued == gh.requests_backing_off == 0

        for status in (503, 429, 403, 401):
            attempts = 0

            async def unavailable(url, **kwargs):
                nonlocal attempts
                attempts += 1
                return httpx.Response(
                    status, text="secondary rate limit" if status == 429 else "unavailable",
                    request=httpx.Request("GET", "https://api.github.com/test"),
                )

            gh.client.get = unavailable
            with patch.object(gh, "_wait_before_retry", new=AsyncMock()):
                try:
                    await gh.list_workflows("test", "repo")
                    raise AssertionError(f"HTTP {status} must not become a successful empty scan")
                except httpx.HTTPStatusError:
                    pass
            assert attempts == (5 if status in (503, 429) else 1), (status, attempts)
    finally:
        await gh.close()
    print("bounded network retries and exhausted HTTP retries fail visibly: ok")


async def check_failed_retry_findings():
    workflow = """name: Vulnerable test
on: pull_request_target
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"""

    class FindingClient(FakeGitHubClient):
        fail_policy = True
        scanned = []

        async def list_workflows(self, owner, name):
            self.scanned.append(name)
            return [{"path": ".github/workflows/test.yml"}]

        async def fetch_file(self, owner, name, path):
            return workflow

        async def list_policies(self, owner, name):
            if name == "two" and self.fail_policy:
                raise httpx.ReadTimeout("policy discovery interrupted after finding was saved")
            return []

    req = m.ScanRequest(
        org="findings-retry", token="not-stored", validate_secrets=False,
        selected_rules=["script-injection"],
    )
    job, _ = m.db_create_scan_job("findings-retry-scan", req)
    m.SCANS[job["scan_id"]] = m.ScanState(id=job["scan_id"], job_id=job["id"])
    with patch.object(m, "GitHubClient", FindingClient), patch.object(
        m, "load_saved_tokens", return_value=[{"token": "not-stored", "login": "tester"}],
    ):
        await m.run_scan(job["scan_id"], req, job["id"])
        failed = await m.get_scan_job_endpoint(job["id"])
        assert failed.state == "failed" and failed.repos_completed == failed.repos_failed == 1
        with m._db() as db:
            before = [tuple(row) for row in db.execute(
                "SELECT id, created_at FROM findings WHERE scan_id=? ORDER BY id", (job["scan_id"],),
            )]
        assert before and failed.findings_count == len(before)
        assert {m.db_get_finding(row[0]).repo for row in before} == {"findings-retry/one", "findings-retry/two"}

        retried = await m.retry_scan_job_endpoint(job["id"])
        assert retried.scan_id == job["scan_id"] and retried.findings_count == len(before)
        FindingClient.fail_policy = False
        m._launch_scan_job(m.db_get_scan_job(job["id"]))
        await m.SCAN_JOB_TASKS[job["id"]]
        completed = await m.get_scan_job_endpoint(job["id"])
        assert completed.state == "completed" and completed.repos_completed == 2
        assert FindingClient.scanned == ["one", "two", "two"], FindingClient.scanned
        with m._db() as db:
            after = [tuple(row) for row in db.execute(
                "SELECT id, created_at FROM findings WHERE scan_id=? ORDER BY id", (job["scan_id"],),
            )]
            checkpoints = [tuple(row) for row in db.execute(
                "SELECT name, attempt_count FROM scan_job_repos WHERE job_id=? ORDER BY name", (job["id"],),
            )]
        assert before == after and checkpoints == [("one", 1), ("two", 2)], (before, after, checkpoints)
        assert completed.findings_count == len(before)
        assert len(m.SCANS[job["scan_id"]].findings) < len(before), "Durable counts must include previous attempts"
        page = await m.list_scan_jobs_endpoint()
        assert next(item for item in page.items if item.id == job["id"]).findings_count == len(before)
    print("real findings survive failed-job Retry without duplication; completed repositories are skipped: ok")


async def check_interrupted_workers():
    started = asyncio.Event()
    active = 0
    stopped = 0

    class InterruptedClient(FakeGitHubClient):
        async def list_workflows(self, owner, name):
            nonlocal active, stopped
            active += 1
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                active -= 1
                stopped += 1

    req = m.ScanRequest(org="interrupted", token="not-stored", concurrency=1, validate_secrets=False)
    job, _ = m.db_create_scan_job("interrupted-scan", req)
    m.SCANS[job["scan_id"]] = m.ScanState(id=job["scan_id"], job_id=job["id"])
    with patch.object(m, "GitHubClient", InterruptedClient):
        task = asyncio.create_task(m.run_scan(job["scan_id"], req, job["id"]))
        await asyncio.wait_for(started.wait(), timeout=2)
        await asyncio.sleep(0)
        assert active == 1
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert active == 0 and stopped == 1
    assert all(row["state"] == "pending" for row in m.db_list_unfinished_job_repos(job["id"]))
    assert m.SCANS[job["scan_id"]].github_client is None
    m.db_update_scan_job(job["id"], state="cancelled")
    print("repository concurrency is bounded and interrupted workers drain into durable pending checkpoints: ok")


async def check_queued_token_pool():
    class PoolClient(m.GitHubClient):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

            async def get(url, **request_kwargs):
                if url == "/rate_limit":
                    return httpx.Response(200, json={
                        "resources": {"core": {"limit": 5000, "remaining": 100, "reset": 2000}},
                    })
                if self.token == "pool-first":
                    return httpx.Response(403, text="API rate limit exceeded", headers={
                        "X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": "2000",
                    })
                assert self.token == "pool-second"
                return httpx.Response(200, headers={
                    "X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "24",
                    "X-RateLimit-Reset": "3000",
                })

            self.client.get = get

        async def _probe_token_rate_limit(self, token):
            assert token == "pool-second"
            return 5000, 25, 3000.0

        async def list_org_repos(self, org, include_forks, max_repos):
            return await FakeGitHubClient.list_org_repos(self, org, include_forks, max_repos)

        async def list_workflows(self, owner, name):
            response = await self._get("/workflows")
            assert response.status_code == 200
            return []

        async def list_policies(self, owner, name):
            return []

    records = [
        {"token": "pool-first", "login": "alice"},
        {"token": "pool-second", "login": "bob"},
    ]
    req = m.ScanRequest(org="pool-org", max_repos=1, validate_secrets=False)
    job, _ = m.db_create_scan_job("queued-pool-scan", req)
    m.SCANS[job["scan_id"]] = m.ScanState(id=job["scan_id"], job_id=job["id"])
    with patch.object(m, "load_saved_tokens", return_value=records), patch.object(m, "GitHubClient", PoolClient):
        restored_req = m._request_from_scan_job(job)
        assert restored_req.token_pool == ["pool-first", "pool-second"]
        await m.run_scan(job["scan_id"], restored_req, job["id"])
    saved = m.db_get_scan_job(job["id"])
    assert saved["state"] == "completed" and saved["retry_count"] == 0, saved
    assert "pool-first" not in saved["token_pool_json"] and "pool-second" not in saved["token_pool_json"]
    queued = await m.get_scan_job_endpoint(job["id"])
    assert queued.token_pool_size == queued.pool_tokens_checked == 2
    assert queued.pool_rate_limit_limit == 10000 and queued.pool_rate_limit_remaining == 24
    assert queued.token_rotations == 1
    m.SCANS.pop(job["scan_id"])
    restored_status = await m.get_scan(job["scan_id"])
    assert restored_status.pool_rate_limit_remaining == queued.pool_rate_limit_remaining
    assert restored_status.pool_rate_limit_limit == queued.pool_rate_limit_limit
    assert restored_status.token_pool_size == queued.token_pool_size
    m.db_update_scan_job(
        job["id"], state="waiting_rate_limit", next_attempt_at=m.time.time() + 3600,
    )
    with patch.object(m, "load_saved_tokens", return_value=records), patch.object(m, "GitHubClient", PoolClient):
        await m._refresh_waiting_scan_pool()
    refreshed = m.db_get_scan_job(job["id"])
    assert refreshed["state"] == "pending" and refreshed["next_attempt_at"] is None
    refreshed_item = await m.get_scan_job_endpoint(job["id"])
    assert refreshed_item.pool_rate_limit_remaining == 125
    assert refreshed_item.token_rotations == 1
    m.db_update_scan_job(job["id"], state="completed")
    print("queued full-pool rotation, persisted combined quota and restored main-screen parity: ok")


async def main():
    m._db_init()
    await check_live_progress()
    await check_transport_retries()
    await check_queued_token_pool()
    await check_failed_retry_findings()
    await check_interrupted_workers()
    original_client = m.GitHubClient
    original_load_tokens = m.load_saved_tokens
    m.GitHubClient = FakeGitHubClient
    m.load_saved_tokens = lambda: [{"token": "not-stored", "login": "octocat", "saved_at": 1}]
    try:
        req = m.ScanRequest(
            org="octocat",
            token="not-stored",
            token_pool=["not-stored"],
            selected_rules=["script-injection"],
        )
        job, created = m.db_create_scan_job("scan-queue-smoke", req)
        assert created
        assert "not-stored" not in job["options_json"]
        assert job["selected_rules"] == ["script-injection"]
        assert not job["all_rules"] and job["selected_rule_count"] == 1
        state = m.ScanState(id="scan-queue-smoke", job_id=job["id"])
        m.SCANS[state.id] = state

        await m.run_scan(state.id, req, job["id"])
        waiting = m.db_get_scan_job(job["id"])
        assert waiting["state"] == "waiting_rate_limit", waiting
        repos = m.db_list_unfinished_job_repos(job["id"])
        assert [repo["full_name"] for repo in repos] == ["octocat/two"], repos
        assert waiting["repos_completed"] == 1

        FakeGitHubClient.fail_second_repo = False
        m.db_update_scan_job(job["id"], state="starting", next_attempt_at=None)
        resumed = m.ScanRequest(
            org="octocat",
            token="not-stored",
            token_pool=["not-stored"],
            selected_rules=["script-injection"],
        )
        await m.run_scan(state.id, resumed, job["id"])
        completed = m.db_get_scan_job(job["id"])
        assert completed["state"] == "completed", completed
        assert completed["repos_completed"] == 2

        duplicate, duplicate_created = m.db_create_scan_job("other-scan", resumed)
        assert duplicate_created
        again, again_created = m.db_create_scan_job("third-scan", resumed)
        assert not again_created and again["id"] == duplicate["id"]
        different_scope, different_scope_created = m.db_create_scan_job(
            "different-scope-scan",
            m.ScanRequest(
                org="octocat",
                token="not-stored",
                selected_rules=["cache-poisoning"],
            ),
        )
        assert different_scope_created and different_scope["id"] != duplicate["id"]
        m.db_update_scan_job(different_scope["id"], state="cancelled", finished_at=1)

        m.db_update_scan_job(duplicate["id"], state="pending")
        restored = await m.get_scan(duplicate["scan_id"])
        assert restored.state == "pending" and restored.job_id == duplicate["id"]
        assert not restored.all_rules and restored.selected_rules == ["script-injection"]

        control_req = m.ScanRequest(org="octocat", token="not-stored", max_repos=1)
        control, control_created = m.db_create_scan_job("control-scan", control_req)
        assert control_created
        m.db_update_scan_job(control["id"], state="pending")
        await m.cancel_scan_job_endpoint(control["id"])
        assert m.db_get_scan_job(control["id"])["state"] == "cancelled"
        retried = await m.retry_scan_job_endpoint(control["id"])
        assert retried.state == "pending"

        later_req = m.ScanRequest(org="octocat", token="not-stored", max_repos=3)
        later, later_created = m.db_create_scan_job("later-scan", later_req)
        assert later_created
        m.db_update_scan_job(later["id"], state="pending")
        moved = await m.move_scan_job_endpoint(later["id"], m.MoveScanJobRequest(direction="up"))
        assert moved.state == "pending"
        m.db_update_scan_job(later["id"], state="cancelled", finished_at=1)
        deleted = await m.delete_scan_job_endpoint(later["id"])
        assert deleted["deleted"] and m.db_get_scan_job(later["id"]) is None

        m.QUEUE_STOP_EVENT.clear()
        m.QUEUE_WAKE_EVENT.clear()
        scheduler = asyncio.create_task(m._scan_queue_scheduler())
        for _ in range(100):
            scheduled = m.db_get_scan_job(duplicate["id"])
            if scheduled["state"] == "completed":
                break
            await asyncio.sleep(0.02)
        assert scheduled["state"] == "completed", scheduled
        m.QUEUE_STOP_EVENT.set()
        m.QUEUE_WAKE_EVENT.set()
        await asyncio.wait_for(scheduler, timeout=2)
        print("queue persistence and resume: ok")
    finally:
        m.GitHubClient = original_client
        m.load_saved_tokens = original_load_tokens
        shutil.rmtree(data_dir, ignore_errors=True)


asyncio.run(main())
