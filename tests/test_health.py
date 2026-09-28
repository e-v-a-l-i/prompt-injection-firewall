"""M0 acceptance-criteria tests (CLAUDE.md §9 M0, §10 item 3/5).

Each test's docstring names the acceptance criterion (AC1-AC6) it encodes,
as given in the approved M0 task list:

  AC1 - `import app` succeeds with no env vars set: no GCP client
        construction, no network calls, no filesystem writes at import time.
  AC2 - GET /health -> 200, application/json, body is exactly
        {status, mode, version} with status == "ok", mode in
        {mock, replay, live}, version a non-empty string.
  AC3 - mode defaults to "mock" with no MODE env var; MODE=replay ->
        mode == "replay".
  AC4 - GET / -> 200, text/html, body contains "Prompt Injection Firewall".
  AC5 - GET /does-not-exist -> 404.
  AC6 - Procfile exists at repo root with the exact required content.

None of these tests touch the network or write to disk. AC1 and AC3 spawn a
subprocess (using the same venv interpreter running this test session) so
that env vars can be controlled *before* `import app` runs, regardless of
whether the app reads MODE at import time or at request time -- that keeps
the test deterministic and not dependent on test ordering or on this
session's own env leaking in.
"""
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _minimal_env(overrides=None):
    """A small, deterministic env: PATH plus a few keys some libs expect.

    Deliberately does NOT copy the full parent environment, so a stray
    MODE (or GCP_*) var set in the developer's shell can't leak into a test
    that's asserting default/no-env behavior.
    """
    env = {"PATH": os.environ.get("PATH", "")}
    for key in ("SYSTEMROOT", "HOME", "LANG", "LC_ALL"):
        if key in os.environ:
            env[key] = os.environ[key]
    if overrides:
        env.update(overrides)
    return env


# --- AC1 ---------------------------------------------------------------

# Guards `import app` against the three side effects AC1 forbids, so a
# violation fails loudly with a clear message instead of e.g. silently
# hanging on a real network call or leaving a stray file behind.
_IMPORT_GUARD_SCRIPT = textwrap.dedent(
    """
    import builtins
    import io
    import os
    import socket
    import sqlite3
    import sys

    _orig_open = builtins.open
    _WRITE_FLAGS = ("w", "a", "x", "+")

    def _guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in mode for flag in _WRITE_FLAGS):
            raise AssertionError(
                "app.py performed a filesystem write at import time: "
                "open(%r, %r)" % (file, mode)
            )
        return _orig_open(file, mode, *args, **kwargs)

    # Both names: pathlib.Path.write_text/open route through io.open, not
    # builtins.open, so patching builtins alone lets a whole family of
    # writes through.
    builtins.open = _guarded_open
    io.open = _guarded_open

    _orig_os_open = os.open
    _OS_WRITE_MASK = (
        os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
    )

    def _guarded_os_open(path, flags, *args, **kwargs):
        if flags & _OS_WRITE_MASK:
            raise AssertionError(
                "app.py performed a filesystem write at import time: "
                "os.open(%r)" % (path,)
            )
        return _orig_os_open(path, flags, *args, **kwargs)

    os.open = _guarded_os_open

    def _blocked_dir_write(*a, **kw):
        raise AssertionError(
            "app.py touched the filesystem (mkdir/makedirs) at import time"
        )

    os.mkdir = _blocked_dir_write
    os.makedirs = _blocked_dir_write

    # sqlite3 opens its file in C, so neither open() guard sees it. This is
    # the side effect M1 is most likely to introduce, since §2 says the DB
    # is "built at startup from data/".
    _orig_connect = sqlite3.connect

    def _guarded_connect(database, *a, **kw):
        if str(database) != ":memory:":
            raise AssertionError(
                "app.py opened a SQLite database at import time: %r" % (database,)
            )
        return _orig_connect(database, *a, **kw)

    sqlite3.connect = _guarded_connect

    class _BlockedSocket(socket.socket):
        def connect(self, *a, **kw):
            raise AssertionError(
                "app.py made a network connection at import time"
            )

        def connect_ex(self, *a, **kw):
            raise AssertionError(
                "app.py made a network connection at import time"
            )

    socket.socket = _BlockedSocket

    import app  # noqa: F401

    # A module-level `AnthropicVertex(...)` would construct without touching
    # the network, so the guards above cannot see it. Its import can.
    if "anthropic" in sys.modules:
        raise AssertionError(
            "app.py imported the anthropic SDK at import time; the model "
            "client must be constructed lazily, on first use"
        )

    print("IMPORT_OK")
    """
)


def _run_import_guard(cwd):
    """Run the import guard against whatever `app` module `cwd` exposes."""
    return subprocess.run(
        [sys.executable, "-c", _IMPORT_GUARD_SCRIPT],
        cwd=str(cwd),
        env=_minimal_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_import_app_with_no_env_has_no_import_time_side_effects():
    """AC1: `import app` succeeds with NO env vars set, and does so without
    constructing a GCP client, making a network call, or writing to disk.

    Runs in a subprocess with a scrubbed env and with socket.connect and
    filesystem writes patched to raise -- this would actually catch a
    violation (e.g. a module-level VertexClient() or DB-write call),
    unlike just checking the import doesn't raise on its own.
    """
    result = _run_import_guard(REPO_ROOT)
    assert result.returncode == 0, (
        "`import app` failed or triggered a forbidden side effect with a "
        f"scrubbed env.\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    assert "IMPORT_OK" in result.stdout


# --- AC2 -----------------------------------------------------------------


def test_health_returns_200_json(client):
    """AC2: GET /health -> 200 with an application/json content type."""
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("application/json")


def test_health_body_has_exactly_status_mode_version(client):
    """AC2: body is a JSON object with exactly {status, mode, version}."""
    r = client.get("/health")
    body = r.json()
    assert isinstance(body, dict)
    assert set(body.keys()) == {"status", "mode", "version"}
    assert body["status"] == "ok"
    assert body["mode"] in {"mock", "replay", "live"}
    assert isinstance(body["version"], str) and body["version"] != ""


# --- AC3 -----------------------------------------------------------------

_HEALTH_MODE_SCRIPT = textwrap.dedent(
    """
    import json
    import sys
    sys.path.insert(0, {repo_root!r})
    from fastapi.testclient import TestClient
    import app
    client = TestClient(app.app)
    r = client.get("/health")
    print(json.dumps(r.json()))
    """
)


def _health_body_with_env(overrides):
    script = _HEALTH_MODE_SCRIPT.format(repo_root=str(REPO_ROOT))
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(REPO_ROOT),
        env=_minimal_env(overrides),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        "subprocess fetching /health failed.\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    # Last line in case something else printed to stdout during import.
    last_line = result.stdout.strip().splitlines()[-1]
    return json.loads(last_line)


def test_health_mode_defaults_to_mock_with_no_mode_env():
    """AC3: with no MODE env var set at all, mode == "mock"."""
    body = _health_body_with_env({})
    assert body["mode"] == "mock"


def test_health_mode_is_replay_when_mode_env_is_replay():
    """AC3: with MODE=replay, mode == "replay"."""
    body = _health_body_with_env({"MODE": "replay"})
    assert body["mode"] == "replay"


# --- AC4 -----------------------------------------------------------------


def test_index_serves_html_containing_title(client):
    """AC4: GET / -> 200, text/html, body contains "Prompt Injection Firewall"."""
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("text/html")
    assert "Prompt Injection Firewall" in r.text


# --- AC5 -----------------------------------------------------------------


def test_unknown_route_is_404(client):
    """AC5: GET /does-not-exist -> 404."""
    r = client.get("/does-not-exist")
    assert r.status_code == 404


# --- AC6 -----------------------------------------------------------------


def test_procfile_has_exact_required_content():
    """AC6: Procfile exists at repo root with exactly the required content
    (a single trailing newline is acceptable)."""
    procfile = REPO_ROOT / "Procfile"
    assert procfile.exists(), "Procfile is missing at repo root"
    content = procfile.read_text()
    expected = "web: uvicorn app:app --host 0.0.0.0 --port $PORT"
    assert content in (expected, expected + "\n"), (
        f"Procfile content does not match exactly.\ngot={content!r}\n"
        f"expected={expected!r} (optionally with one trailing newline)"
    )


# --- Guard self-test: does AC1's guard actually catch a violation? ---------

# Each entry is a module-level statement that AC1 forbids. The guard is the
# load-bearing test of the whole suite (D-005), so it is itself tested:
# a guard that silently passes everything would look identical to a clean
# app.py in the report.
_VIOLATIONS = {
    "builtins_write": "open('evidence.txt', 'w').close()",
    "pathlib_write": (
        "from pathlib import Path\nPath('evidence.txt').write_text('x')"
    ),
    "os_open_write": (
        "import os\n"
        "os.close(os.open('evidence.txt', os.O_CREAT | os.O_WRONLY))"
    ),
    "sqlite_db": (
        "import sqlite3\n"
        "sqlite3.connect('evidence.db').execute('create table t (a)')"
    ),
    "network": (
        "import socket\n"
        "socket.create_connection(('127.0.0.1', 9), timeout=0.2)"
    ),
    "anthropic_import": "import anthropic",
    "makedirs": "import os\nos.makedirs('evidence_dir')",
}


@pytest.mark.parametrize("violation", sorted(_VIOLATIONS))
def test_import_guard_catches_forbidden_side_effects(tmp_path, violation):
    """The AC1 guard must fail on each side effect it claims to catch.

    Without this, a guard that patches the wrong name (builtins.open while
    the code writes through pathlib, say) reports IMPORT_OK forever and the
    invariant quietly stops being enforced.
    """
    (tmp_path / "app.py").write_text(_VIOLATIONS[violation] + "\n")

    result = _run_import_guard(tmp_path)

    assert result.returncode != 0, (
        f"the import guard did NOT catch the {violation!r} side effect; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "IMPORT_OK" not in result.stdout
    # Nothing the fake app tried to create should exist.
    assert not (tmp_path / "evidence.txt").exists()
    assert not (tmp_path / "evidence.db").exists()
    assert not (tmp_path / "evidence_dir").exists()


def test_import_guard_passes_a_clean_module(tmp_path):
    """...and must still pass a module with no side effects, so the guard
    self-test above cannot be satisfied by a guard that fails everything."""
    (tmp_path / "app.py").write_text("VALUE = 1\n")

    result = _run_import_guard(tmp_path)

    assert result.returncode == 0, (
        f"the guard rejected a clean module: stderr={result.stderr!r}"
    )
    assert "IMPORT_OK" in result.stdout


# --- resolve_mode: the fallback D-004 rests on ----------------------------


def test_modes_constant_is_exactly_the_three_documented_values():
    """Locks the mode set itself. `mode in MODES` is a tautology in the
    /health test, so drift in MODES has to be caught here."""
    import app as app_module

    assert app_module.MODES == {"mock", "replay", "live"}
    assert app_module.DEFAULT_MODE == "mock"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("mock", "mock"),
        ("replay", "replay"),
        ("live", "live"),
        ("LIVE", "live"),
        ("  live  ", "live"),
        ("Replay", "replay"),
        ("", "mock"),
        ("   ", "mock"),
        ("bogus", "mock"),
        ("liv", "mock"),
        ("live; rm -rf /", "mock"),
        (None, "mock"),
    ],
)
def test_resolve_mode_normalises_and_falls_back_to_mock(monkeypatch, raw, expected):
    """An unrecognised MODE must resolve to `mock` -- never to `live`.

    `mock` is the only mode that cannot reach the network, so a typo in a
    deploy flag has to degrade towards the safe mode, not away from it.
    """
    import app as app_module

    if raw is None:
        monkeypatch.delenv("MODE", raising=False)
        assert app_module.resolve_mode() == expected
    else:
        assert app_module.resolve_mode(raw) == expected


def test_resolve_mode_never_returns_live_for_an_unknown_value():
    """The fallback direction stated in D-004, asserted directly."""
    import app as app_module

    for junk in ("live-ish", "production", "1", "true", "LIVEE", "l i v e"):
        assert app_module.resolve_mode(junk) == "mock"


# --- static assets are not served as a directory --------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/static/index.html",
        "/static/",
        "/static/../app.py",
        "/static/..%2fapp.py",
        "/static/%2e%2e/app.py",
    ],
)
def test_static_directory_is_not_served(client, path):
    """`static/` is served through one explicit route, not a directory mount,
    so a replay dump or scratch fixture dropped in there later is not
    publicly fetchable and there is no traversal surface to get wrong."""
    r = client.get(path)
    assert r.status_code == 404, f"{path} unexpectedly served {r.status_code}"
    assert "uvicorn app:app" not in r.text
