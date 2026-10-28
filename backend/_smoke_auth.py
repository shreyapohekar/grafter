import asyncio
import os
import subprocess
import sys
from unittest.mock import patch

from fastapi import Response

import main as m


async def main():
    for configured, expected in ((None, "password"), ("custom-test-password", "custom-test-password")):
        env = dict(os.environ)
        env.pop("GRAFTER_ADMIN_PASSWORD", None)
        if configured is not None:
            env["GRAFTER_ADMIN_PASSWORD"] = configured
        subprocess.run(
            [sys.executable, "-c", f"import main; assert main.AUTH_PASSWORD == {expected!r}"],
            env=env,
            check=True,
        )

    minimum = 3 * 24 * 60 * 60
    for configured, expected in ((None, minimum), ("3600", minimum), ("345600", 345600)):
        env = dict(os.environ)
        env.pop("GRAFTER_SESSION_TTL_SECONDS", None)
        if configured is not None:
            env["GRAFTER_SESSION_TTL_SECONDS"] = configured
        subprocess.run(
            [sys.executable, "-c", f"import main; assert main.SESSION_TTL_SECONDS == {expected}"],
            env=env,
            check=True,
        )

    now = 1_000_000
    with patch.object(m.time, "time", return_value=now):
        response = Response()
        result = await m.auth_login(
            m.LoginRequest(username=m.AUTH_USERNAME, password=m.AUTH_PASSWORD), response,
        )
        assert result.authenticated
        assert f"Max-Age={m.SESSION_TTL_SECONDS}" in response.headers["set-cookie"]
        token = m._make_session_cookie(m.AUTH_USERNAME)
        assert m._session_username(token) == m.AUTH_USERNAME
        assert m._session_username(token + "tampered") is None
        logout = Response()
        await m.auth_logout(logout)
        assert "Max-Age=0" in logout.headers["set-cookie"]

    with patch.object(m.time, "time", return_value=now + m.SESSION_TTL_SECONDS - 1):
        assert m._session_username(token) == m.AUTH_USERNAME
    with patch.object(m.time, "time", return_value=now + m.SESSION_TTL_SECONDS):
        assert m._session_username(token) is None
    with patch.object(m.time, "time", return_value=now + m.SESSION_TTL_SECONDS + 1):
        assert m._session_username(token) is None
    print("three-day session minimum, cookie lifetime, expiry and logout: ok")


if __name__ == "__main__":
    asyncio.run(main())
