"""M4 acceptance-criteria tests for the guardrails (CLAUDE.md §7 "Per-IP
rate limit (429 on excess) and per-session token cap", §10.3 "Rate limit
returns 429; token cap stops a session cleanly").

Human-approved settings this file binds to (given in the M4 test-engineer
brief, not yet reflected anywhere in CLAUDE.md prose):

- `RATE_LIMIT_PER_MIN` default 600, per-IP.
- `SESSION_TOKEN_CAP` default 0 = disabled.
- `POST /api/reset` does NOT clear accumulated token spend.
- `TRUSTED_PROXY_HOPS` default 0 (bare Cloud Run -- no trusted proxy hops
  ahead of the app beyond Google's own front end).

None of `app._db_path()`'s secure-directory behaviour, `app.client_key`,
`app.reset_rate_limits`, `app.MAX_CONCURRENT_RUNS`, `app.reset_run_slots`,
`iter_scenario(..., budget=...)`, or `app.reset_token_budgets` exist yet as
of M4's red state. Every test below is expected to fail with AttributeError
(a missing name) or a plain assertion failure (current behaviour doesn't
match the contract) -- not an import error or a fixture bug.

T7 is a distinct bug found in review, not a guardrail per se, but it lives
here because it is discovered by, and blocks, this milestone's replay-mode
work: `scripts/eval.py` reads `usage` from a `model` trace event's `detail`,
but `iter_scenario` never put it there, so every committed recording has
`usage: {input_tokens: 0, output_tokens: 0}` and a token cap can never trip
in replay mode.
"""
import concurrent.futures
import json
import os
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import sqlite3

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

import app
import clients
import store

REPO_ROOT = Path(__file__).resolve().parent.parent

NO_DEFENSES = {"D1": False, "D2": False, "D3": False}
ALL_DEFENSES = {"D1": True, "D2": True, "D3": True}

_BASE_RUN_PARAMS = {"scenario": "S1", "arm": "undefended", "stage": 1, "mode": "mock"}


def _client() -> TestClient:
    return TestClient(app.app)


def _parse_sse(text: str) -> list[dict]:
    """Same frame parser as tests/test_sse.py, duplicated locally so this
    file has no cross-file test dependency."""
    frames = []
    for block in text.strip("\n").split("\n\n"):
        if not block.strip():
            continue
        if all(line.startswith(":") for line in block.splitlines() if line.strip()):
            continue
        frame_id, event, data_lines = None, None, []
        for line in block.splitlines():
            if line.startswith("id:"):
                frame_id = line[len("id:"):].strip()
            elif line.startswith("event:"):
                event = line[len("event:"):].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:"):].strip())
        assert len(data_lines) == 1
        frames.append({"id": frame_id, "event": event, "data": json.loads(data_lines[0])})
    return frames


class _CountingClient:
    """A scripted client (D-008's "scripted", not "gullible" mode) that
    counts its own `.complete()` calls, so a test can assert the model was
    never invoked at all -- not just that its output was ignored.

    Deliberately not `clients.MockClient(script=...)` directly: that raises
    `MockExhausted` on overrun, which is a fine failure signal but a less
    direct one than a plain call-count assertion.
    """

    name = "counting"

    def __init__(self, completions):
        self._completions = list(completions)
        self.calls = 0

    def complete(self, **kwargs) -> clients.Completion:
        if self.calls >= len(self._completions):
            raise AssertionError(
                f"complete() called {self.calls + 1} times; only "
                f"{len(self._completions)} completions were scripted -- the "
                "token cap did not stop the loop where it should have"
            )
        completion = self._completions[self.calls]
        self.calls += 1
        return completion


# =============================================================================
# T1 -- database path not world-readable
# =============================================================================
#
# DECISIONS.md "Notes carried to M4": "$TMPDIR/memory-firewall.db is
# world-readable on Linux and is shared by every process using that
# tempdir." The fix is a dedicated directory the process creates itself with
# mode 0o700, so the corpus and every session's memory are not readable by
# another local user/process.



@pytest.fixture(autouse=True)
def _frozen_minute(monkeypatch):
    """Pin the rate-limit window's clock for every test in this file.

    The limit uses a fixed one-minute window replaced wholesale when the
    minute rolls (D-048). A test that sends 601 requests to prove the 601st
    is refused fails whenever real time crosses a minute boundary mid-test —
    intermittently, for a reason that has nothing to do with the code. A
    flaky guardrail test is worse than none: it teaches whoever sees it red
    to re-run rather than to look.
    """
    monkeypatch.setattr(app.time, "time", lambda: 1_700_000_000.0)


def test_t1_1_default_db_path_parent_dir_is_created_mode_0700(tmp_path, monkeypatch):
    """T1: with DB_PATH unset, app._db_path() must not simply hand back
    tempfile.gettempdir() itself (the shared, world-writable /tmp on
    Linux) -- it must resolve to a path inside a directory the PROCESS
    ITSELF creates with mode 0o700.

    tempfile.gettempdir() is monkeypatched to a fresh, world-writable
    directory rather than relied on as-is: on macOS the per-user $TMPDIR is
    already 0o700 by the OS's own doing, which would let this assertion
    pass with zero lines of the actual fix and hide the exact Linux
    vulnerability DECISIONS.md's "Notes carried to M4" describes.
    """
    monkeypatch.delenv("DB_PATH", raising=False)
    fake_shared_tmp = tmp_path / "shared_tmp"
    fake_shared_tmp.mkdir()
    os.chmod(fake_shared_tmp, 0o777)
    monkeypatch.setattr(app.tempfile, "gettempdir", lambda: str(fake_shared_tmp))
    app.reset_db()
    try:
        path = app._db_path()
        app.get_db().close()
        parent = os.path.dirname(path)
        assert os.path.abspath(parent) != os.path.abspath(str(fake_shared_tmp)), (
            "the corpus file sits directly in the shared tempdir -- the app must "
            "create its own subdirectory instead of writing next to every other "
            "process's files"
        )
        assert os.path.isdir(parent), f"{parent} was never created"
        if os.name != "nt":
            mode = stat.S_IMODE(os.stat(parent).st_mode)
            assert mode == 0o700, f"{parent} has mode {oct(mode)}, expected 0o700"
    finally:
        app.reset_db()


def test_t1_2_db_path_env_var_still_overrides_and_creates_no_directory(tmp_path, monkeypatch):
    """T1: an explicit DB_PATH is honoured as-is and must NOT trigger the
    default path's directory-creation dance -- a deployer who sets DB_PATH
    owns that location's permissions themselves."""
    target = tmp_path / "custom_corpus.sqlite3"
    before = set(os.listdir(tmp_path))
    monkeypatch.setenv("DB_PATH", str(target))
    app.reset_db()
    try:
        assert app._db_path() == str(target)
        app.get_db().close()
        assert target.exists(), "get_db() did not build the corpus at DB_PATH"
        after = set(os.listdir(tmp_path))
        new_dirs = [e for e in (after - before) if (tmp_path / e).is_dir()]
        assert not new_dirs, f"DB_PATH override created a directory: {new_dirs}"
    finally:
        app.reset_db()
        monkeypatch.delenv("DB_PATH", raising=False)
        app.reset_db()


def test_t1_3_reset_db_still_unlinks_wal_and_shm_and_a_later_get_db_rebuilds(monkeypatch):
    """T1: reset_db() must still unlink the corpus file plus its -wal/-shm
    siblings under the new default-path scheme, and a later get_db() must
    rebuild a working corpus from scratch."""
    monkeypatch.delenv("DB_PATH", raising=False)
    app.reset_db()
    try:
        conn = app.get_db()
        conn.close()
        path = app._db_path()
        assert os.path.exists(path)

        app.reset_db()
        for suffix in ("", "-wal", "-shm"):
            assert not os.path.exists(path + suffix), f"{path}{suffix} survived reset_db()"

        conn2 = app.get_db()
        try:
            count = conn2.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
            assert count > 0, "get_db() after reset_db() did not rebuild the corpus"
        finally:
            conn2.close()
    finally:
        app.reset_db()


def test_t1_4_m0_import_time_guard_still_passes():
    """T1: the M0 import-time guard (tests/test_health.py) must still pass
    against whatever DB_PATH/directory-creation logic this milestone adds --
    the directory setup has to stay lazy, on first get_db(), not at import.
    Re-run as its own subprocess/pytest invocation (same pattern as T1 in
    tests/test_db_concurrency.py) rather than re-implemented here, so there
    is exactly one place that defines what "no import-time side effects"
    means.
    """
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest", "-q",
            "tests/test_health.py::test_import_app_with_no_env_has_no_import_time_side_effects",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        "the M0 import-time guard regressed under the T1 DB-path changes:\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )


# =============================================================================
# T2 -- per-IP rate limit returning 429
# =============================================================================
#
# Contract: app.client_key(request) -> str; app.reset_rate_limits();
# middleware over /api/* only, /health and / exempt; RATE_LIMIT_PER_MIN read
# at request time; 0 disables; unparseable/negative falls back to the
# default (600), never to disabled. 429 body is exactly
# {"detail": "rate limit exceeded"} with Retry-After 1..60 and no echo of
# the client key.


def _request(headers=None, client_host="203.0.113.7", path="/api/config"):
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "headers": raw_headers,
        "client": (client_host, 51000) if client_host is not None else None,
        "method": "GET",
        "path": path,
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
    }
    return Request(scope)


# --- client_key: XFF trust direction --------------------------------------


def test_t2_1_client_key_trusts_the_rightmost_xff_hop_by_default(monkeypatch):
    """T2 AC1: with TRUSTED_PROXY_HOPS unset, Google's front end appends
    what IT observed as the last hop, so trust flows from the right -- the
    leftmost entry is attacker-controlled and must NOT be used."""
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    req = _request({"X-Forwarded-For": "1.2.3.4, 5.6.7.8"}, client_host="169.254.1.1")
    assert app.client_key(req) == "5.6.7.8"


def test_t2_2_trusted_proxy_hops_1_reads_one_hop_further_left(monkeypatch):
    """T2 AC2."""
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    req = _request({"X-Forwarded-For": "1.2.3.4, 5.6.7.8"}, client_host="169.254.1.1")
    assert app.client_key(req) == "1.2.3.4"


def test_t2_3_unparseable_xff_falls_back_to_request_client_host(monkeypatch):
    """T2 AC3: the chosen value must be validated through
    ipaddress.ip_address, so an attacker-chosen string cannot become an
    unbounded dict key."""
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    req = _request({"X-Forwarded-For": "not-an-ip"}, client_host="203.0.113.5")
    assert app.client_key(req) == "203.0.113.5"


def test_t2_3b_absurd_xff_value_also_falls_back_safely(monkeypatch):
    """Same AC3 property, adversarial shape: a very long / injection-shaped
    header must not reach ipaddress.ip_address unguarded (e.g. crash, or
    become the dict key verbatim)."""
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    req = _request({"X-Forwarded-For": "'; DROP TABLE sessions;--"}, client_host="203.0.113.5")
    assert app.client_key(req) == "203.0.113.5"


def test_t2_4_no_xff_uses_request_client_host(monkeypatch):
    """T2 AC4."""
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    req = _request({}, client_host="203.0.113.6")
    assert app.client_key(req) == "203.0.113.6"


def test_t2_4b_no_client_on_the_request_still_returns_a_nonempty_string(monkeypatch):
    """T2 AC4: request.client is None (a valid ASGI scope shape) must not
    raise -- a caller with no discoverable address still needs a key."""
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    req = _request({}, client_host=None)
    key = app.client_key(req)
    assert isinstance(key, str) and key != ""


def test_reset_rate_limits_exists_and_is_callable():
    assert callable(app.reset_rate_limits)
    app.reset_rate_limits()  # must not raise


# --- the /api/* middleware itself ------------------------------------------

RATE_LIMITED_TARGET = "/api/config"


def test_t2_5_the_fourth_request_in_a_window_is_429_with_the_exact_body(monkeypatch):
    """T2 AC5, AC6: RATE_LIMIT_PER_MIN=3 -- the first three succeed, the
    fourth is 429 with the documented body and a valid Retry-After, and the
    body echoes nothing about the caller."""
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "3")
    c = _client()
    for i in range(3):
        r = c.get(RATE_LIMITED_TARGET)
        assert r.status_code == 200, f"request {i} unexpectedly rate-limited"

    r = c.get(RATE_LIMITED_TARGET)
    assert r.status_code == 429
    assert r.json() == {"detail": "rate limit exceeded"}
    retry_after = r.headers.get("retry-after")
    assert retry_after is not None, "no Retry-After header on a 429"
    assert 1 <= int(retry_after) <= 60


def test_t2_7_forging_a_different_leftmost_xff_each_time_buys_no_fresh_allowance(monkeypatch):
    """T2 AC7: 50 requests, each with a DIFFERENT forged leftmost hop but the
    SAME trusted (rightmost) hop, must still exhaust the same window -- the
    limiter keys on the hop it trusts, not the one an attacker controls."""
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "3")
    c = _client()
    statuses = [
        c.get(RATE_LIMITED_TARGET, headers={"X-Forwarded-For": f"9.9.9.{i}, 5.6.7.8"}).status_code
        for i in range(50)
    ]
    assert statuses[:3] == [200, 200, 200], statuses[:5]
    assert all(s == 429 for s in statuses[3:]), (
        f"forging a fresh leftmost XFF bought extra allowance: {statuses}"
    )


def test_t2_8_health_stays_200_after_the_limit_is_exhausted(monkeypatch):
    """T2 AC8: /health is exempt from the /api/* limiter entirely."""
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "1")
    c = _client()
    for i in range(20):
        r = c.get("/health")
        assert r.status_code == 200, f"/health was rate-limited on call {i}"


def test_t2_8b_index_route_is_also_exempt(monkeypatch):
    """Contract statement, not a numbered AC on its own: "/health and / are
    exempt" -- the root page must load even with the limiter fully spent."""
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "1")
    c = _client()
    for i in range(5):
        r = c.get("/")
        assert r.status_code == 200, f"/ was rate-limited on call {i}"


def test_t2_9_rate_limit_per_min_zero_disables_limiting(monkeypatch):
    """T2 AC9."""
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "0")
    c = _client()
    for i in range(50):
        r = c.get(RATE_LIMITED_TARGET)
        assert r.status_code == 200, f"request {i} was limited despite RATE_LIMIT_PER_MIN=0"


@pytest.mark.parametrize("raw", ["abc", "-5"])
def test_t2_10_unparseable_or_negative_falls_back_to_the_default_600_not_disabled(monkeypatch, raw):
    """T2 AC10: 'abc' and '-5' must behave as the default (600), never as
    disabled -- exactly 600 requests succeed and the 601st in the same
    window is 429."""
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", raw)
    c = _client()
    for i in range(600):
        r = c.get(RATE_LIMITED_TARGET)
        assert r.status_code == 200, (
            f"request {i} was rejected under the RATE_LIMIT_PER_MIN={raw!r} fallback "
            "(expected the default of 600/min)"
        )
    r = c.get(RATE_LIMITED_TARGET)
    assert r.status_code == 429, (
        f"the 601st request succeeded under RATE_LIMIT_PER_MIN={raw!r} -- looks disabled, "
        "not falling back to the default 600"
    )


def test_t2_11_thirty_concurrent_requests_at_limit_ten_yield_exactly_ten_successes(monkeypatch):
    """T2 AC11."""
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "10")
    c = _client()

    def _hit(_):
        return c.get(RATE_LIMITED_TARGET).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        statuses = list(pool.map(_hit, range(30)))

    assert statuses.count(200) == 10, statuses
    assert statuses.count(429) == 20, statuses


def test_t2_12_api_run_is_rate_limited_too_and_the_429_is_json_not_sse(monkeypatch):
    """T2 AC12: at RATE_LIMIT_PER_MIN=1, the second /api/run in the window
    is a JSON 429, not a (possibly truncated) SSE stream."""
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "1")
    c = _client()
    r1 = c.get("/api/run", params=_BASE_RUN_PARAMS)
    assert r1.status_code == 200
    assert r1.headers.get("content-type", "").startswith("text/event-stream")

    r2 = c.get("/api/run", params=_BASE_RUN_PARAMS)
    assert r2.status_code == 429
    assert not r2.headers.get("content-type", "").startswith("text/event-stream")
    assert r2.json() == {"detail": "rate limit exceeded"}


# =============================================================================
# T3 -- concurrent-run cap
# =============================================================================
#
# Contract: app.MAX_CONCURRENT_RUNS (default 4), app.reset_run_slots().
#
# AC1 and AC3 need a real in-progress stream racing a second HTTP request --
# not reachable through TestClient's plain .get(), which fully drains a
# streaming response before returning (confirmed against this app's own
# test_t4_9 in tests/test_sse.py). Rather than TestClient's .stream()
# context manager (which, empirically, blocks on __exit__ until the ASGI
# generator itself finishes or times out -- so it can't model a client that
# actually walks away), these use a real uvicorn subprocess over a real TCP
# socket, exactly like test_t4_9.


def test_t3_0_max_concurrent_runs_defaults_to_four():
    # Raised from 4 in the M4 review: a global-only cap of 4 collided
    # between two ordinary visitors. The per-client cap is what bounds
    # one caller now.
    assert app.MAX_CONCURRENT_RUNS == 12
    assert app.MAX_CONCURRENT_RUNS_PER_CLIENT == 3


def test_reset_run_slots_exists_and_is_callable():
    assert callable(app.reset_run_slots)
    app.reset_run_slots()  # must not raise


def _start_guardrail_server(tmp_path, extra_setup: str, model_delay: float):
    """A real uvicorn subprocess serving `app.app`, with `app.make_client`
    replaced by a client that sleeps `model_delay` seconds before returning
    a normal end_turn completion -- long enough to hold a run "in progress"
    while a second request races it, and short enough to keep the test fast.
    """
    repo_root = str(REPO_ROOT)
    stub = tmp_path / "guardrail_server.py"
    stub.write_text(
        f"""
import sys, time
sys.path.insert(0, {repo_root!r})
import app, clients

class Slow:
    name = "slow"
    def complete(self, **kwargs):
        time.sleep({model_delay})
        return clients.Completion(
            text="", tool_calls=[], stop_reason="end_turn", usage={{}}
        )

app.make_client = lambda *a, **kw: Slow()
{extra_setup}
application = app.app
"""
    )

    with __import__("socket").socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "--app-dir", str(tmp_path),
         "guardrail_server:application", "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1).read()
            break
        except Exception:
            if proc.poll() is not None:
                raise AssertionError("the guardrail test server exited during startup")
            time.sleep(0.2)
    else:
        proc.terminate()
        raise AssertionError("the guardrail test server never became healthy")
    return proc, port


def test_t3_1_and_2_second_run_429_while_first_in_progress_then_200_once_it_ends(tmp_path):
    """T3 AC1, AC2: with MAX_CONCURRENT_RUNS monkeypatched to 1, a second
    /api/run opened while the first stream is unfinished is 429 with body
    {"detail": "too many runs in progress"} and a Retry-After header; once
    the first stream is consumed to event: done, a new run is 200."""
    proc, port = _start_guardrail_server(tmp_path, "app.MAX_CONCURRENT_RUNS = 1", model_delay=1.5)
    try:
        run_url = f"http://127.0.0.1:{port}/api/run?scenario=S1&arm=undefended&stage=1&mode=mock"

        first_events = []
        first_done = threading.Event()
        first_error = []

        def _consume_first():
            try:
                with urllib.request.urlopen(run_url, timeout=30) as response:
                    for raw in response:
                        line = raw.decode("utf-8", "replace")
                        if line.startswith("event:"):
                            first_events.append(line[len("event:"):].strip())
                            if first_events[-1] == "done":
                                first_done.set()
            except Exception as exc:  # noqa: BLE001
                first_error.append(exc)

        t = threading.Thread(target=_consume_first)
        t.start()
        # Long enough for run_started+retrieval to arrive and the model call
        # (slept 1.5s) to be in flight, short enough that it can't have
        # finished yet.
        time.sleep(0.5)
        assert t.is_alive(), "the first run finished before the race could happen"

        try:
            urllib.request.urlopen(run_url, timeout=10)
            raise AssertionError("a second concurrent run was not rejected")
        except urllib.error.HTTPError as exc:
            assert exc.code == 429, f"expected 429, got {exc.code}"
            body = json.loads(exc.read().decode("utf-8"))
            assert body == {"detail": "too many runs in progress"}
            retry_after = exc.headers.get("Retry-After")
            assert retry_after is not None
            assert 1 <= int(retry_after) <= 60
            assert not (exc.headers.get("content-type") or "").startswith("text/event-stream")

        t.join(timeout=15)
        assert not first_error, f"the first run's stream errored: {first_error}"
        assert first_done.is_set(), "the first run never reached done"

        # AC2: the slot is free now that the first run finished.
        with urllib.request.urlopen(run_url, timeout=30) as response:
            assert response.status == 200
            for _ in response:
                pass
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_t3_3_a_stream_abandoned_before_done_still_releases_its_slot(tmp_path):
    """T3 AC3: a client that walks away mid-stream (closes the connection
    without ever reading a terminal done) must not permanently hold its
    concurrency slot."""
    proc, port = _start_guardrail_server(tmp_path, "app.MAX_CONCURRENT_RUNS = 1", model_delay=3.0)
    try:
        run_url = f"http://127.0.0.1:{port}/api/run?scenario=S1&arm=undefended&stage=1&mode=mock"

        response = urllib.request.urlopen(run_url, timeout=30)
        seen = []
        for raw in response:
            line = raw.decode("utf-8", "replace")
            if line.startswith("event:"):
                seen.append(line[len("event:"):].strip())
                if len(seen) >= 2:
                    break
        response.close()
        assert "done" not in seen, "the run reached done before it could be abandoned"

        deadline = time.monotonic() + 12
        last_code = None
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(run_url, timeout=6) as r2:
                    last_code = r2.status
                    for _ in r2:
                        pass
                break
            except urllib.error.HTTPError as exc:
                last_code = exc.code
                time.sleep(0.3)
        assert last_code == 200, (
            f"a new run never succeeded after the first was abandoned "
            f"(last status seen: {last_code}) -- an abandoned stream must still "
            "release its concurrency slot"
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_t3_4_a_run_that_raises_emits_error_then_done_and_releases_its_slot(monkeypatch):
    """T3 AC4: an exception inside iter_scenario must still emit event:
    error then a terminal event: done (already pinned for the pre-guardrail
    behaviour by tests/test_sse.py), and the failed run's slot must not
    stay held -- a second run right after, with the cap at 1, must still
    succeed."""

    class _RaisingClient:
        name = "raising-client"

        def complete(self, **kwargs):
            raise RuntimeError("boom")

    monkeypatch.setattr(app, "MAX_CONCURRENT_RUNS", 1, raising=False)
    monkeypatch.setattr(app, "make_client", lambda *a, **kw: _RaisingClient())

    c = _client()
    r1 = c.get("/api/run", params=_BASE_RUN_PARAMS)
    assert r1.status_code == 200
    frames = _parse_sse(r1.text)
    types = [f["event"] for f in frames]
    assert "error" in types
    assert types[-1] == "done"
    assert types.index("error") < len(types) - 1

    r2 = c.get("/api/run", params=_BASE_RUN_PARAMS)
    assert r2.status_code == 200, (
        "a run that raised did not release its concurrency slot: the next "
        f"run (cap=1) was rejected with {r2.status_code}"
    )


# =============================================================================
# T4 -- per-session token cap
# =============================================================================
#
# Contract: iter_scenario(..., budget=None) where None means unlimited (all
# pre-M4 tests must stay green); the check happens at the TOP of each model
# turn BEFORE client.complete(); on trip the loop breaks to the normal done
# emission with outcome["reason"] == "token_cap" and
# detail == {"cap": N, "used": M}; spend is keyed on the BASE session id
# (sid.split("#")[0]) so the two arms share one budget; app.reset_token_budgets()
# exists.
#
# "The check happens at the TOP of each model turn" is read literally,
# including turn 1: a budget of 0 is smaller than any real completion's
# (strictly positive) token usage, so it trips before the very first call --
# which is exactly AC1's "cap smaller than the first turn's usage".


def test_t4_0_budget_parameter_exists_and_defaults_to_none():
    import inspect

    sig = inspect.signature(app.iter_scenario)
    assert "budget" in sig.parameters, "iter_scenario has no budget parameter"
    assert sig.parameters["budget"].default is None


def test_reset_token_budgets_exists_and_is_callable():
    assert callable(app.reset_token_budgets)
    app.reset_token_budgets()  # must not raise


def test_t4_1_and_2_zero_budget_trips_before_the_first_call_with_the_documented_done(monkeypatch):
    """T4 AC1, AC2: budget=0 (smaller than any real turn's usage) -- exactly
    run_started, retrieval, then a terminal done, no model event, and the
    scripted client is never called. That done carries
    reason == "token_cap" and detail == {"cap": 0, "used": 0}."""
    app.reset_token_budgets()
    conn = store.build_db(":memory:")
    try:
        client = _CountingClient([
            clients.Completion(
                text="hi", tool_calls=[], stop_reason="end_turn",
                usage={"input_tokens": 500, "output_tokens": 100},
            ),
        ])
        events = app.run_scenario(
            "S1", client, defenses=NO_DEFENSES, session_id="t4-1#undefended",
            conn=conn, budget=0,
        )
        types = [e["type"] for e in events]
        assert types[0] == "run_started"
        assert "retrieval" in types
        assert "model" not in types
        assert types[-1] == "done"
        assert client.calls == 0

        done = events[-1]
        assert done["outcome"]["reason"] == "token_cap"
        assert done["detail"] == {"cap": 0, "used": 0}
    finally:
        conn.close()
        app.reset_token_budgets()


def test_t4_3_a_budget_allowing_exactly_one_turn_gives_one_model_event_then_token_cap(monkeypatch):
    """T4 AC3."""
    app.reset_token_budgets()
    conn = store.build_db(":memory:")
    try:
        call = clients.ToolCall(id="call-1", name="search_logs", input={"query": "ALR-1001"})
        client = _CountingClient([
            clients.Completion(
                text="looking", tool_calls=[call], stop_reason="tool_use",
                usage={"input_tokens": 70, "output_tokens": 30},
            ),
        ])
        events = app.run_scenario(
            "S1", client, defenses=NO_DEFENSES, session_id="t4-3#undefended",
            conn=conn, budget=100,
        )
        types = [e["type"] for e in events]
        assert types.count("model") == 1, types
        assert types[-1] == "done"
        assert events[-1]["outcome"]["reason"] == "token_cap"
        assert client.calls == 1
    finally:
        conn.close()
        app.reset_token_budgets()


def test_t4_4_spend_is_cumulative_across_runs_in_one_session(monkeypatch):
    """T4 AC4: a second run in the same session, with a budget already
    exhausted by the first, must trip immediately (zero model calls) --
    which only happens if spend persisted between the two run_scenario
    calls."""
    app.reset_token_budgets()
    conn = store.build_db(":memory:")
    try:
        base = "t4-4"
        budget = 100
        client1 = _CountingClient([
            clients.Completion(
                text="ok", tool_calls=[], stop_reason="end_turn",
                usage={"input_tokens": 60, "output_tokens": 40},
            ),
        ])
        events1 = app.run_scenario(
            "S1", client1, defenses=NO_DEFENSES, session_id=f"{base}#undefended",
            conn=conn, budget=budget,
        )
        assert events1[-1]["outcome"]["reason"] != "token_cap"
        assert client1.calls == 1

        client2 = _CountingClient([
            clients.Completion(
                text="should not run", tool_calls=[], stop_reason="end_turn",
                usage={"input_tokens": 1, "output_tokens": 1},
            ),
        ])
        events2 = app.run_scenario(
            "S1", client2, defenses=NO_DEFENSES, session_id=f"{base}#undefended",
            conn=conn, budget=budget,
        )
        assert client2.calls == 0, "spend from run 1 was not carried into run 2"
        assert events2[-1]["outcome"]["reason"] == "token_cap"
        assert events2[-1]["detail"] == {"cap": budget, "used": 100}
    finally:
        conn.close()
        app.reset_token_budgets()


def test_t4_5_spend_is_shared_across_arms_via_the_base_session_id(monkeypatch):
    """T4 AC5: the undefended arm's spend reduces the defended arm's
    remaining budget in the same cookie session -- both share one base id
    (sid.split("#")[0])."""
    app.reset_token_budgets()
    conn = store.build_db(":memory:")
    try:
        base = "t4-5"
        budget = 100
        client1 = _CountingClient([
            clients.Completion(
                text="ok", tool_calls=[], stop_reason="end_turn",
                usage={"input_tokens": 60, "output_tokens": 40},
            ),
        ])
        events1 = app.run_scenario(
            "S1", client1, defenses=NO_DEFENSES, session_id=f"{base}#undefended",
            conn=conn, budget=budget,
        )
        assert events1[-1]["outcome"]["reason"] != "token_cap"

        client2 = _CountingClient([
            clients.Completion(
                text="should not run", tool_calls=[], stop_reason="end_turn",
                usage={"input_tokens": 1, "output_tokens": 1},
            ),
        ])
        events2 = app.run_scenario(
            "S1", client2, defenses=ALL_DEFENSES, session_id=f"{base}#defended",
            conn=conn, budget=budget,
        )
        assert client2.calls == 0, (
            "the defended arm did not see the undefended arm's spend -- "
            "budgets are not shared across arms of the same session"
        )
        assert events2[-1]["outcome"]["reason"] == "token_cap"
    finally:
        conn.close()
        app.reset_token_budgets()


def test_t4_6_sse_stream_with_the_cap_tripped_stays_200_and_ends_on_done(monkeypatch):
    """T4 AC6."""
    # These drive the cap through mock mode, which no longer draws it down
    # (a run that calls no model costs nothing). The cap mechanism is still
    # the thing under test, so bill this run explicitly.
    monkeypatch.setattr(app, "bills_tokens", lambda client: True)
    monkeypatch.setenv("SESSION_TOKEN_CAP", "1")
    c = _client()
    r = c.get("/api/run", params=_BASE_RUN_PARAMS)
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("text/event-stream")
    frames = _parse_sse(r.text)
    assert frames
    assert frames[-1]["event"] == "done"
    assert frames[-1]["data"]["outcome"]["reason"] == "token_cap"


def test_t4_7_post_api_reset_does_not_clear_accumulated_token_spend(monkeypatch):
    """T4 AC7: per the human-approved settings, /api/reset clears memory
    (§3), not token spend."""
    # These drive the cap through mock mode, which no longer draws it down
    # (a run that calls no model costs nothing). The cap mechanism is still
    # the thing under test, so bill this run explicitly.
    monkeypatch.setattr(app, "bills_tokens", lambda client: True)
    monkeypatch.setenv("SESSION_TOKEN_CAP", "1")
    c = _client()
    r1 = c.get("/api/run", params=_BASE_RUN_PARAMS)
    frames1 = _parse_sse(r1.text)
    assert frames1[-1]["data"]["outcome"]["reason"] == "token_cap"

    reset_r = c.post("/api/reset")
    assert reset_r.status_code == 200

    r2 = c.get("/api/run", params=_BASE_RUN_PARAMS)
    frames2 = _parse_sse(r2.text)
    assert frames2[-1]["data"]["outcome"]["reason"] == "token_cap", (
        "POST /api/reset appears to have cleared accumulated token spend -- "
        "it must not, per the human-approved M4 settings"
    )


def test_t4_8_session_token_cap_unset_or_zero_means_no_cap_over_ten_runs(monkeypatch):
    """T4 AC8."""
    for env_value in (None, "0"):
        if env_value is None:
            monkeypatch.delenv("SESSION_TOKEN_CAP", raising=False)
        else:
            monkeypatch.setenv("SESSION_TOKEN_CAP", env_value)
        c = _client()
        for i in range(10):
            r = c.get("/api/run", params=_BASE_RUN_PARAMS)
            frames = _parse_sse(r.text)
            assert frames[-1]["data"]["outcome"]["reason"] != "token_cap", (
                f"run {i} tripped the token cap with SESSION_TOKEN_CAP={env_value!r}"
            )


def test_t4_9_unparseable_session_token_cap_is_treated_as_disabled(monkeypatch):
    """T4 AC9."""
    monkeypatch.setenv("SESSION_TOKEN_CAP", "abc")
    c = _client()
    for i in range(5):
        r = c.get("/api/run", params=_BASE_RUN_PARAMS)
        frames = _parse_sse(r.text)
        assert frames[-1]["data"]["outcome"]["reason"] != "token_cap", (
            f"run {i} tripped the token cap with SESSION_TOKEN_CAP='abc'"
        )


# =============================================================================
# T7 -- replay recordings must carry real token usage
# =============================================================================
#
# Bug found in review: scripts/eval.py's record_representative() reads
# e["detail"].get("usage") off each `model` trace event, but iter_scenario's
# `model` event only ever put {"text", "stop_reason", "tool_calls",
# "fallback"} in `detail` -- never `usage` -- so every recorded completion in
# replays/*.json has usage {input_tokens: 0, output_tokens: 0}, and T4's
# token cap (measured against real usage) can never trip when a demo is
# served from replay mode.


def test_t7_a_every_model_event_detail_carries_int_usage():
    """(a): a fresh run's `model` events must each carry
    detail["usage"] == {"input_tokens": int, "output_tokens": int} -- the
    field scripts/eval.py already (wrongly, until this is fixed) assumes is
    there."""
    conn = store.build_db(":memory:")
    try:
        client = clients.MockClient(gullible=True)
        events = app.run_scenario(
            "S1", client, defenses=NO_DEFENSES, session_id="t7a#undefended", conn=conn,
        )
        model_events = [e for e in events if e["type"] == "model"]
        assert model_events, "no model events were produced by the S1 run"
        for e in model_events:
            usage = e["detail"].get("usage")
            assert isinstance(usage, dict), f"model event has no detail.usage: {e['detail']}"
            assert isinstance(usage.get("input_tokens"), int), usage
            assert isinstance(usage.get("output_tokens"), int), usage
    finally:
        conn.close()


def test_t7_b_every_committed_replay_has_a_completion_with_nonzero_tokens():
    """(b): this will fail until the eight replays/*.json recordings are
    regenerated against the T7-a fix -- today every one of them has
    usage == {"input_tokens": 0, "output_tokens": 0} on every completion."""
    replay_dir = REPO_ROOT / "replays"
    files = sorted(replay_dir.glob("*.json"))
    assert files, "no replay recordings found under replays/"

    offenders = []
    for path in files:
        with open(path, "r", encoding="utf-8") as fh:
            recording = json.load(fh)
        completions = recording.get("completions", [])
        totals = [
            int((c.get("usage") or {}).get("input_tokens", 0))
            + int((c.get("usage") or {}).get("output_tokens", 0))
            for c in completions
        ]
        if not any(t > 0 for t in totals):
            offenders.append(path.name)

    assert not offenders, (
        f"these recordings have zero token usage on every completion: {offenders} -- "
        "re-record with `scripts/eval.py --dry-run --record` after the T7-a fix lands"
    )


# =============================================================================
# M4 review findings
# =============================================================================


def test_a_full_key_map_does_not_lock_out_new_clients(monkeypatch):
    """Finding: an overflowing key map refused every *new* client while the
    keys already in it kept their full allowance.

    An attacker with one IPv6 /64 fills the map with addresses that are each
    under the per-key limit — so none is ever throttled — and `/api/*` closes
    to every new visitor for the rest of the minute. Overflow keys now share a
    bucket instead of being excluded.
    """
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "600")
    monkeypatch.setattr(app, "RATE_LIMIT_MAX_KEYS", 8)
    app.reset_rate_limits()

    for i in range(8):
        allowed, _ = app._rate_limit_check(f"filler-{i}")
        assert allowed

    allowed, _ = app._rate_limit_check("a-brand-new-visitor")
    assert allowed, "a new client was refused because the key map was full"

    allowed, _ = app._rate_limit_check("filler-0")
    assert allowed, "an existing client should be unaffected"


def test_overflow_keys_stay_bounded(monkeypatch):
    """...and the map must still not grow without bound, or the fix trades a
    denial of service for a memory leak."""
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "600")
    monkeypatch.setattr(app, "RATE_LIMIT_MAX_KEYS", 8)
    app.reset_rate_limits()

    for i in range(500):
        app._rate_limit_check(f"client-{i}")

    assert len(app._RATE_WINDOW["counts"]) <= 8 + 64


def test_client_key_reads_every_forwarded_header_not_just_the_first():
    """Finding: `headers.get` returns the FIRST X-Forwarded-For header.

    A proxy that appends as a separate header line rather than in place would
    invert the trust-from-the-right design (D-047) — the attacker's own value
    becomes the key, which buys unlimited requests or lets them pin a victim's
    address. Latent behind Cloud Run, which appends in place, and the one
    assumption the whole guardrail rests on.
    """
    from starlette.datastructures import Headers

    class _Request:
        def __init__(self, raw):
            self.headers = Headers(raw=raw)
            self.client = SimpleNamespace(host="10.0.0.1")

    request = _Request([
        (b"x-forwarded-for", b"9.9.9.9"),
        (b"x-forwarded-for", b"203.0.113.10"),
    ])
    assert app.client_key(request) == "203.0.113.10", (
        "the trusted entry is the last one across ALL forwarded headers"
    )


def test_a_rate_limited_client_recovers_when_the_window_rolls(monkeypatch):
    """The frozen clock these tests use would let a 'refused forever'
    regression pass: nothing else advances time, and the reset fixture hides
    it between tests."""
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "2")
    app.reset_rate_limits()

    now = [1_700_000_000.0]
    monkeypatch.setattr(app.time, "time", lambda: now[0])

    assert app._rate_limit_check("steady-client")[0]
    assert app._rate_limit_check("steady-client")[0]
    assert not app._rate_limit_check("steady-client")[0], "the 3rd request should be refused"

    now[0] += 60
    assert app._rate_limit_check("steady-client")[0], (
        "the client never recovered after the window rolled"
    )


def test_a_failure_before_the_stream_releases_its_run_slot(monkeypatch):
    """Finding: the slot was released only in the generator's `finally`, so
    anything raising between acquiring it and returning the response held it
    forever. Four transient database errors wedged /api/run at 429 for the
    life of the process — and with --max-instances 1 nothing restarts it.
    """
    from fastapi.testclient import TestClient

    app.reset_run_slots()
    client = TestClient(app.app, raise_server_exceptions=False)

    def boom():
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(app, "get_db", boom)
    for _ in range(6):
        client.get("/api/run", params={"scenario": "S1", "arm": "undefended",
                                       "stage": 1, "mode": "mock"})

    assert app._RUNS_IN_FLIGHT["n"] == 0, (
        f"{app._RUNS_IN_FLIGHT['n']} run slot(s) leaked after failures before the stream"
    )

    # And the endpoint still works once the underlying problem clears.
    monkeypatch.undo()
    r = client.get("/api/run", params={"scenario": "S1", "arm": "undefended",
                                       "stage": 1, "mode": "mock"})
    assert r.status_code == 200


def test_token_spend_is_not_accumulated_when_no_cap_is_configured():
    """The rate limiter got a bounded key map; this one had nothing, and wrote
    an entry for every cookie ever seen."""
    app.reset_token_budgets()
    conn = store.build_db(":memory:")
    try:
        app.run_scenario("S1", clients.MockClient(gullible=True), defenses=NO_DEFENSES,
                         session_id="untracked#undefended", conn=conn, budget=None)
        assert app.tokens_spent("untracked") == 0
        assert not app._TOKENS_SPENT
    finally:
        conn.close()


def test_one_client_cannot_hold_every_run_slot(monkeypatch):
    """Finding: the run cap was global only, so two visitors clicking at the
    same moment exhausted it — and one client holding slow-read streams could
    deny everyone with four requests, which the per-minute limit does not
    bound.

    The held state is simulated rather than produced with real concurrent
    streams: TestClient buffers a response fully before returning it, so a
    stream opened through it has already finished and freed its slot.
    """
    from fastapi.testclient import TestClient

    app.reset_run_slots()
    monkeypatch.setattr(app, "MAX_CONCURRENT_RUNS_PER_CLIENT", 2)
    monkeypatch.setattr(app, "MAX_CONCURRENT_RUNS", 12)

    client = TestClient(app.app)
    params = {"scenario": "S1", "arm": "undefended", "stage": 1, "mode": "mock"}

    # Two runs already in flight for this caller, ten slots free globally.
    with app._RUN_LOCK:
        app._RUNS_IN_FLIGHT["n"] = 2
        app._RUNS_PER_CLIENT["testclient"] = 2
    try:
        greedy = client.get("/api/run", params=params)
        assert greedy.status_code == 429, "one client exceeded its own run allowance"
        assert greedy.json() == {"detail": "too many runs in progress"}

        other = client.get(
            "/api/run", params=params, headers={"X-Forwarded-For": "203.0.113.7"}
        )
        assert other.status_code == 200, (
            "a second visitor was refused because the first was hogging slots"
        )
    finally:
        app.reset_run_slots()


def test_a_completed_run_removes_its_per_client_entry():
    """The per-client map must not grow one entry per visitor ever seen."""
    from fastapi.testclient import TestClient

    app.reset_run_slots()
    client = TestClient(app.app)
    client.get("/api/run", params={"scenario": "S1", "arm": "undefended",
                                   "stage": 1, "mode": "mock"})
    assert app._RUNS_PER_CLIENT == {}, f"leaked per-client entries: {app._RUNS_PER_CLIENT}"
    assert app._RUNS_IN_FLIGHT["n"] == 0


def test_a_database_deleted_underneath_a_running_process_is_rebuilt(tmp_path, monkeypatch):
    """Observed for real: a test that unset DB_PATH called reset_db() and
    unlinked a running dev server's database. The server's "already built"
    flag stayed true, so every later connection opened an empty file and every
    run died with `no such table: memory` — which reads as the app being
    broken rather than the database being gone.

    A cleared /tmp does the same thing to the deployed service.
    """
    monkeypatch.setenv("DB_PATH", str(tmp_path / "corpus.db"))
    app.reset_db()

    conn = app.get_db()
    assert conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0] > 0
    conn.close()

    # Something external removes the file while the process still thinks it
    # has one.
    (tmp_path / "corpus.db").unlink()
    assert app._DB_READY is True, "this test is only meaningful while the flag is stale"

    recovered = app.get_db()
    try:
        assert recovered.execute("SELECT COUNT(*) FROM chunks").fetchone()[0] > 0
        recovered.execute("SELECT COUNT(*) FROM memory").fetchone()
    finally:
        recovered.close()
        app.reset_db()


def test_a_replayed_run_does_not_draw_down_the_token_budget(monkeypatch):
    """The cap bounds spend, and a replay spends nothing.

    Charging replays made the guardrail lock visitors out of the one mode
    that cannot cost anything: a single hands-free pass of the four demo
    cases reports ~107k tokens, so against the deployed 150k cap a visitor
    got one pass and then met "Token budget reached". The usage numbers are
    still real and still reported (D-053); they are no longer billed.
    """
    monkeypatch.setenv("SESSION_TOKEN_CAP", "1")
    c = _client()
    for _ in range(3):
        frames = _parse_sse(c.get("/api/run", params=_BASE_RUN_PARAMS).text)
        assert frames[-1]["data"]["outcome"]["reason"] != "token_cap", (
            "a run that calls no model was charged against the spend cap"
        )


def test_bills_tokens_distinguishes_the_clients_that_reach_a_model():
    assert app.bills_tokens(clients.ReplayClient("S1", "undefended", 1)) is False
    assert app.bills_tokens(clients.MockClient(gullible=True)) is False

    class _Live:
        name = "gemini"

    assert app.bills_tokens(_Live()) is True
