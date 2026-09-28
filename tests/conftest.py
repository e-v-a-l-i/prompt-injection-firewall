"""Pytest configuration for the Prompt Injection Firewall test suite.

Ensures the repo root is on ``sys.path`` so ``import app`` works no matter
which directory pytest is invoked from, and provides a shared TestClient
fixture for tests that only care about the default (in-process) env.

Tests that need to control MODE (or other env vars) *before* app import runs
a subprocess instead of relying on this fixture, since import-time env
reads can't be un-done by monkeypatching an already-imported module. See
test_health.py for that pattern.
"""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(scope="session")
def client():
    """A TestClient bound to the app, imported once for the whole session.

    Uses whatever MODE (if any) is present in this pytest process's own
    environment -- fine for assertions that don't pin a specific mode value.
    """
    from fastapi.testclient import TestClient

    import app as app_module

    return TestClient(app_module.app)


# --- M1 fixtures -----------------------------------------------------------
#
# Added for the M1 test suite (store/skills/clients/agent-loop). These read
# real repo fixtures (`data/`, `skills/`, `scenarios/`) rather than synthetic
# ones, per CLAUDE.md §10: M1's tests are meant to bind to the actual bundled
# data so a genuine data/implementation mismatch fails loudly instead of
# being hidden behind a mock. They deliberately do NOT exist yet during M0's
# red state and will raise (not skip) until the main session adds those
# files -- that's the expected failure mode, not a fixture bug.

DATA_DIR = REPO_ROOT / "data"
SKILLS_DIR = REPO_ROOT / "skills"
SCENARIOS_DIR = REPO_ROOT / "scenarios"


@pytest.fixture(scope="session")
def data_dir():
    """Path to the bundled synthetic data directory (`data/`)."""
    return DATA_DIR


@pytest.fixture(scope="session")
def skills_dir():
    """Path to the bundled skills directory (`skills/`)."""
    return SKILLS_DIR


@pytest.fixture
def s1_scenario():
    """The parsed S1 scenario fixture (`scenarios/s1_retrieval_hijack.yaml`).

    Tests use this instead of hardcoding the injection payload text, so they
    stay correct however the main session phrases the actual injected
    sentence -- the assertion is "the payload's own distinctive words are
    retrievable", not "this exact string appears".
    """
    import yaml

    path = SCENARIOS_DIR / "s1_retrieval_hijack.yaml"
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(autouse=True, scope="session")
def _tmp_db_path(tmp_path_factory):
    """Point the app's database at a throwaway path for the whole run.

    Without this the suite uses `$TMPDIR/memory-firewall.db` — the same file a
    local dev server is holding open — and the autouse reset below unlinks it
    underneath that server. The server keeps writing to the deleted inode and
    nothing it writes is visible to any new connection: a split brain with no
    error anywhere.
    """
    import os

    import app as app_module

    previous = os.environ.get("DB_PATH")
    os.environ["DB_PATH"] = str(tmp_path_factory.mktemp("db") / "memory-firewall.db")
    app_module.reset_db()
    yield
    if previous is None:
        os.environ.pop("DB_PATH", None)
    else:
        os.environ["DB_PATH"] = previous


@pytest.fixture(autouse=True)
def _isolate_app_db():
    """Drop `app`'s cached DB around every test.

    `run_scenario` defaults to `session_id="default"` and a process-global
    in-memory DB, so a test that saves memory would otherwise be visible to
    every test that ran after it. No M1 test triggers that today, which is
    exactly why it is worth pinning now rather than debugging an
    order-dependent failure in M2.
    """
    import app as app_module

    app_module.reset_db()
    yield
    app_module.reset_db()


@pytest.fixture(autouse=True)
def _reset_guardrail_state():
    """Drop the M4 guardrails' process-wide state around every test.

    Same reasoning as `_isolate_app_db` above: the rate limiter's per-key
    counters, the run-concurrency slot count, and the per-session token
    spend ledger all live outside the per-test DB, so a test that trips one
    of them would otherwise poison every test that runs after it. Looked up
    by name and called only if present -- this fixture is added ahead of the
    M4 implementation (tests/test_guardrails.py), so `app` won't expose any
    of these yet; once it does, all three exist and all three get reset.
    """
    import app as app_module

    def _reset():
        for name in ("reset_rate_limits", "reset_run_slots", "reset_token_budgets"):
            fn = getattr(app_module, name, None)
            if callable(fn):
                fn()

    _reset()
    yield
    _reset()
