"""M3 acceptance-criteria tests for T3 (client factory + /api/config,
/api/scenarios) and T4 (the /api/run SSE endpoint itself), folded into one
file per the test-engineer brief (CLAUDE.md §2 SSE, §6 UI "streamed step
trace", §10.3 "The SSE stream emits well-formed events and a terminal done
event").

None of `app.make_client`, `GET /api/config`, `GET /api/scenarios`, or
`GET /api/run` exist yet as of M3's red state. Every test below is expected
to fail with AttributeError (missing `app.make_client`) or 404 (missing
route) -- not an import error or a fixture bug.

Contract under test:

- `app.make_client(mode, scenario_id, arm, stage)`. The *effective* mode
  honours `replay`/`mock` from the query string always, but only honours
  `live` when `app.resolve_mode()` (the server's own MODE env var) is
  itself `"live"` -- a client cannot force a live model call the deployment
  isn't configured for.
- `GET /api/config` -> `{mode, live_available, replay_available,
  defenses}`.
- `GET /api/scenarios` -> the three canonical fixtures only (S1, S2, S3),
  each with `id, name, description, alert_id, injection.location,
  expected_undefended, primary_defense, stages` (S2's `stages == 2`).
- `GET /api/run` streams SSE frames shaped exactly
  `id: <seq>\\nevent: <event type>\\ndata: <single-line json>\\n\\n`. The
  `event:` name IS the trace event's own `type` (so the terminal frame is
  literally `event: done`). Headers: `text/event-stream`,
  `Cache-Control: no-cache`, `X-Accel-Buffering: no`. `arm=undefended`
  forces all defenses off server-side regardless of the d1/d2/d3 query
  params. An exception during the run emits `event: error` then a
  synthetic terminal `event: done` with `outcome.reason == "error"`,
  leaking no traceback into the response body.
"""
import json
import re
import socket
import time

from fastapi.testclient import TestClient

import app
import clients


def _client() -> TestClient:
    return TestClient(app.app)


def _parse_sse(text: str) -> list[dict]:
    """Parse raw SSE body text into a list of {"id", "event", "data"} dicts,
    one per frame. Asserts each frame's `data:` line is a single physical
    line of JSON, per the documented frame shape."""
    frames = []
    for block in text.strip("\n").split("\n\n"):
        if not block.strip():
            continue
        # SSE comment lines (": text") are a legitimate part of the protocol.
        # The endpoint sends one up front so the browser's onopen fires and
        # the headers flush before retrieval starts, which is also what stops
        # an intermediary buffering the stream. They carry no data.
        if all(line.startswith(":") for line in block.splitlines() if line.strip()):
            continue
        frame_id = None
        event = None
        data_lines = []
        for line in block.splitlines():
            if line.startswith("id:"):
                frame_id = line[len("id:") :].strip()
            elif line.startswith("event:"):
                event = line[len("event:") :].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:") :].strip())
        assert len(data_lines) == 1, (
            f"expected exactly one data: line per frame, got {len(data_lines)} "
            f"in block {block!r}"
        )
        payload = json.loads(data_lines[0])
        frames.append({"id": frame_id, "event": event, "data": payload})
    return frames


def _run(client: TestClient, **params):
    return client.get("/api/run", params=params)


_BASE_PARAMS = {"scenario": "S1", "arm": "undefended", "stage": 1, "mode": "mock"}


# =============================================================================
# T3 -- make_client
# =============================================================================


def test_t3_1_make_client_mock_never_touches_the_network(monkeypatch):
    """T3 AC1 (mock half): `app.make_client("mock", ...)` has `.name ==
    "mock"` and opens no socket."""

    def _blocked_connect(self, *a, **kw):
        raise AssertionError("make_client('mock', ...) opened a network connection")

    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)

    mock_client = app.make_client("mock", "S1", "undefended", 1)
    assert mock_client.name == "mock"


def test_t3_1b_replayclient_constructed_directly_never_touches_the_network(
    monkeypatch, tmp_path
):
    """T3 AC1 (replay half): `clients.ReplayClient(...).name == "replay"`
    and it opens no socket. Constructed directly with `dir=` (the one part
    of the replay lookup path the T7 contract pins explicitly) against a
    scratch fixture, rather than through `app.make_client`'s default
    lookup location -- repo-root `replays/` is intentionally empty until
    the M3 eval populates it (see tests/test_replay.py), so a test that
    depends on a file existing there would be fixture-dependent rather than
    behaviour-dependent."""

    def _blocked_connect(self, *a, **kw):
        raise AssertionError("ReplayClient construction opened a network connection")

    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)

    fixture = tmp_path / "s1_undefended_stage1.json"
    fixture.write_text(
        json.dumps(
            {
                "scenario": "s1",
                "arm": "undefended",
                "stage": 1,
                "defenses": {"D1": False, "D2": False, "D3": False},
                "model": "test-fixture",
                "recorded_at": "2026-01-01T00:00:00+00:00",
                "outcome": {},
                "completions": [
                    {
                        "text": "done",
                        "stop_reason": "end_turn",
                        "tool_calls": [],
                        "usage": {"input_tokens": 1, "output_tokens": 1},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    replay_client = clients.ReplayClient("S1", "undefended", 1, dir=tmp_path)
    assert replay_client.name == "replay"


def test_t3_2_query_mode_live_is_ignored_unless_the_server_env_mode_is_live(monkeypatch):
    """T3 AC2: with `MODE` unset (so `app.resolve_mode() == "mock"`),
    `GET /api/run?...&mode=live` must NOT construct a `VertexClient` --
    the server's own configured mode gates `live`, not the query string."""

    def _boom(*a, **kw):
        raise AssertionError(
            "VertexClient was constructed even though resolve_mode() != 'live'"
        )

    monkeypatch.setattr(clients, "VertexClient", _boom)
    monkeypatch.delenv("MODE", raising=False)
    assert app.resolve_mode() == "mock"

    client = _client()
    r = _run(client, scenario="S1", arm="undefended", stage=1, mode="live")
    assert r.status_code == 200
    frames = _parse_sse(r.text)
    assert frames, "expected at least one SSE frame"
    assert frames[-1]["data"]["type"] == "done"


# =============================================================================
# T3 -- /api/scenarios and /api/config
# =============================================================================

_LOCATION_RE = re.compile(r"^(log|ticket|alert):[^:]+:[a-z_]+$")


def test_t3_3_scenarios_route_returns_exactly_the_three_canonical_fixtures():
    """`GET /api/scenarios` returns the picker's scenarios — not the
    red-teamer's variants — each with the documented fields and S2's
    `stages == 2`.

    The picker carries the two attacks. S3, S4 and S5 are deliberately not in
    it (D-067, D-077): S3 is the same shape as S1 and the live model declines
    it outright; S4 shows what D3 costs on a legitimate action and S5 shows
    all three defenses staying blind, and both were judged to raise more
    questions on screen than they answered. All three remain CI fixtures,
    matrix rows and red-team targets, and S4/S5 keep their recordings.
    """
    client = _client()
    r = client.get("/api/scenarios")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)

    ids = sorted(s["id"] for s in body)
    assert ids == ["S1", "S2"], f"got {ids!r}"

    by_id = {s["id"]: s for s in body}
    required_keys = {
        "id",
        "name",
        "description",
        "alert_id",
        "injection",
        "expected_undefended",
        "primary_defense",
        "stages",
    }
    for sid, scenario in by_id.items():
        missing = required_keys - set(scenario.keys())
        assert not missing, f"{sid} missing keys {missing}"
        location = scenario["injection"]["location"]
        if scenario.get("kind") == "legitimate":
            # A legitimate scenario has no attacker and therefore no injection
            # site. Demanding one would force a fixture to invent a location
            # for content that does not exist.
            assert location == "", f"{sid} is legitimate but names an injection site"
            continue
        assert _LOCATION_RE.match(location), (
            f"{sid} injection.location {location!r} doesn't match doc_type:doc_id:field"
        )

    assert by_id["S2"]["stages"] == 2


def test_t3_4_config_mode_matches_resolve_mode():
    """T3 AC4: `GET /api/config`'s `mode` equals `app.resolve_mode()`, and
    the body has exactly the documented four keys."""
    client = _client()
    r = client.get("/api/config")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"mode", "live_available", "replay_available", "defenses", "rate_limit_per_min"}
    assert body["mode"] == app.resolve_mode()


def test_t3_5_health_still_has_exactly_status_mode_version_keys(client):
    """T3 AC5: M3's new routes must not touch `/health`'s M0 contract --
    still exactly {status, mode, version} (guards against, e.g., a shared
    response-model change bleeding into every route)."""
    r = client.get("/health")
    body = r.json()
    assert set(body.keys()) == {"status", "mode", "version"}


# =============================================================================
# T4 -- the SSE endpoint itself
# =============================================================================


def test_t4_1_run_returns_200_event_stream_with_the_documented_headers():
    """T4 AC1."""
    client = _client()
    r = _run(client, **_BASE_PARAMS)
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("text/event-stream")
    assert r.headers.get("cache-control") == "no-cache"
    assert r.headers.get("x-accel-buffering") == "no"


def test_t4_2_every_frame_is_well_formed_and_event_name_matches_payload_type():
    """T4 AC2: every frame's `data:` is valid single-line JSON, its
    `event:` name equals `data.type`, and every type is one of
    `app.EVENT_KINDS | {"error"}`."""
    client = _client()
    r = _run(client, **_BASE_PARAMS)
    frames = _parse_sse(r.text)
    assert frames

    allowed = app.EVENT_KINDS | {"error"}
    for frame in frames:
        assert frame["event"] in allowed, f"unexpected event type {frame['event']!r}"
        assert frame["data"]["type"] == frame["event"], (
            f"event: {frame['event']!r} does not match data.type "
            f"{frame['data'].get('type')!r}"
        )


def test_t4_3_s1_undefended_starts_run_started_retrieval_and_ends_on_exactly_one_done():
    """T4 AC3."""
    client = _client()
    r = _run(client, **_BASE_PARAMS)
    frames = _parse_sse(r.text)
    types = [f["event"] for f in frames]

    assert types[0] == "run_started"
    assert "retrieval" in types[:3], f"no retrieval near the start: {types[:5]}"

    done_indices = [i for i, t in enumerate(types) if t == "done"]
    assert len(done_indices) == 1, f"expected exactly one done event, got {done_indices}"
    assert done_indices[0] == len(types) - 1, "done must be the last frame, nothing after it"


def test_t4_4_frame_ids_are_sequential_and_match_payload_seq():
    """T4 AC4."""
    client = _client()
    r = _run(client, **_BASE_PARAMS)
    frames = _parse_sse(r.text)
    for i, frame in enumerate(frames):
        assert frame["id"] == str(i), f"frame {i} has id: {frame['id']!r}"
        assert frame["data"]["seq"] == i, f"frame {i}'s payload seq is {frame['data']['seq']!r}"


def test_t4_5_undefended_arm_forces_all_defenses_off_regardless_of_query_flags():
    """T4 AC5: `arm=undefended&d1=1&d2=1&d3=1` on S1 still achieves the
    attacker's goal, and no event carries a non-null `defense`."""
    client = _client()
    r = _run(client, scenario="S1", arm="undefended", stage=1, mode="mock", d1="1", d2="1", d3="1")
    frames = _parse_sse(r.text)

    done = frames[-1]["data"]
    assert done["type"] == "done"
    assert done["outcome"]["attacker_goal_achieved"] is True

    fired = [f for f in frames if f["data"].get("defense") is not None]
    assert not fired, f"a defense fired under arm=undefended: {fired}"


def test_t4_6_defended_arm_with_only_d3_blocks_s1_and_the_goal_is_false():
    """T4 AC6: `arm=defended&d3=1` on S1 (backstop defense per §4's
    matrix) produces a blocked event with `defense.id == "D3"`, and the
    goal is not achieved."""
    client = _client()
    r = _run(client, scenario="S1", arm="defended", stage=1, mode="mock", d3="1")
    frames = _parse_sse(r.text)

    blocked = [f["data"] for f in frames if f["event"] == "blocked"]
    assert blocked, "expected a blocked event"
    assert blocked[0]["defense"]["id"] == "D3"

    done = frames[-1]["data"]
    assert done["type"] == "done"
    assert done["outcome"]["attacker_goal_achieved"] is False


def test_t4_7_an_exception_mid_run_yields_error_then_done_with_no_traceback_leak(monkeypatch):
    """T4 AC7: a client whose `complete()` raises still produces a
    terminal `done`, preceded by an `error` frame, and the raw exception
    message / a traceback never reach the response body."""

    class _RaisingClient:
        # Deliberately not named after the exception text: run_started echoes
        # the client's name, so a name containing "boom" would trip the leak
        # assertion below on the client's own identity rather than on
        # anything the exception leaked.
        name = "raising-client"

        def complete(self, **kwargs):
            raise RuntimeError("boom")

    monkeypatch.setattr(app, "make_client", lambda *a, **kw: _RaisingClient())

    client = _client()
    r = _run(client, **_BASE_PARAMS)
    assert r.status_code == 200

    frames = _parse_sse(r.text)
    types = [f["event"] for f in frames]
    assert "error" in types, f"no error frame: {types}"
    assert types[-1] == "done", f"run did not end on done: {types}"
    assert types.index("error") < len(types) - 1, "error frame must precede the terminal done"

    done = frames[-1]["data"]
    assert done["outcome"]["reason"] == "error"

    assert "boom" not in r.text, "the raw exception message leaked into the SSE body"
    assert "Traceback" not in r.text, "a traceback leaked into the SSE body"


def test_t4_8_unknown_scenario_id_is_404_before_the_stream_opens():
    """T4 AC8."""
    client = _client()
    r = _run(client, scenario="NOPE", arm="undefended", stage=1, mode="mock")
    assert r.status_code == 404
    assert not r.headers.get("content-type", "").startswith("text/event-stream")


def test_t4_9_frames_stream_before_a_slow_model_call_finishes(tmp_path):
    """T4 AC9: the endpoint must stream events as they happen, not buffer the
    run and send it at the end.

    This runs a real uvicorn server rather than TestClient. Starlette's
    TestClient routes through httpx's ASGI transport, which collects the whole
    response body before handing it back -- so under TestClient a perfectly
    streaming endpoint and a fully buffered one are indistinguishable, and
    this assertion would fail for a reason that has nothing to do with the
    code under test. Measured against a real server: run_started and
    retrieval arrive at 0.00s while the model's frames wait on the model.

    If this breaks, the side-by-side UI shows two empty columns until each run
    finishes -- which is the whole point of the SSE work.
    """
    import socket
    import subprocess
    import sys
    import textwrap
    import time
    import urllib.request

    import pathlib

    repo_root = str(pathlib.Path(__file__).resolve().parent.parent)
    model_delay = 1.5

    stub = tmp_path / "slow_server.py"
    stub.write_text(
        textwrap.dedent(
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
            application = app.app
            """
        )
    )

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "--app-dir", str(tmp_path),
         "slow_server:application", "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1).read()
                break
            except Exception:
                if proc.poll() is not None:
                    raise AssertionError("the test server exited during startup")
                time.sleep(0.2)
        else:
            raise AssertionError("the test server never became healthy")

        url = (
            f"http://127.0.0.1:{port}/api/run"
            "?scenario=S1&arm=undefended&stage=1&mode=mock"
        )
        start = time.monotonic()
        seen, elapsed_at_retrieval = [], None
        with urllib.request.urlopen(url, timeout=30) as response:
            for raw in response:
                line = raw.decode("utf-8", "replace")
                if line.startswith("event:"):
                    seen.append(line[len("event:"):].strip())
                    if seen[-1] == "retrieval" and elapsed_at_retrieval is None:
                        elapsed_at_retrieval = time.monotonic() - start
                        break
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    assert seen[:2] == ["run_started", "retrieval"], f"unexpected opening frames: {seen!r}"
    assert elapsed_at_retrieval is not None
    assert elapsed_at_retrieval < model_delay * 0.5, (
        f"the first two frames took {elapsed_at_retrieval:.3f}s against a model that "
        f"sleeps {model_delay}s -- the endpoint is buffering the run instead of "
        "streaming events as they are produced"
    )
