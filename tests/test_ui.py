"""Static assertions over `static/index.html` (CLAUDE.md §2, §6).

The UI is one vanilla-JS file with no build step, so there is no unit-test
seam. These assert the properties that fail *silently* in a browser — a
missing SSE listener drops events with no error, a stray external script
breaks a cold start offline, a session id in a fetch body reopens a
vulnerability the server closed. Appearance is checked by eye (§10.6).
"""
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app

HTML = (Path(__file__).resolve().parent.parent / "static" / "index.html").read_text()


def test_single_inline_script_no_external_origins():
    """§2: vanilla JS, no build step. Also a cold-start property: a CDN
    reference makes the demo depend on the network at exactly the moment
    someone is watching."""
    assert len(re.findall(r"<script", HTML)) == 1
    assert not re.search(r"<script[^>]+src=", HTML)
    assert "import " not in HTML.split("<script")[1].split("</script>")[0]


def test_stylesheets_are_inline_too():
    assert not re.search(r"<link[^>]+stylesheet", HTML)


def test_phone_layout_has_a_breakpoint_that_collapses_the_columns():
    """§6: it must be usable on a phone. Verified in a real 375px viewport;
    this pins the mechanism so a later edit cannot quietly drop it."""
    assert "grid-template-columns: 1fr 1fr" in HTML
    media = re.search(r"@media \(max-width: (\d+)px\)(.*?)\n  \}", HTML, re.S)
    assert media, "no max-width media query"
    assert int(media.group(1)) <= 900
    assert "grid-template-columns: 1fr" in media.group(2)


def test_every_trace_event_type_has_an_sse_listener():
    """Named SSE events do not fire `onmessage`. A type with no listener is
    dropped in silence — no error, no console warning, just a missing card.
    """
    script = HTML.split("<script")[1]
    declared = set(re.findall(r'"(\w+)"', script.split("EVENT_TYPES = [")[1].split("]")[0]))
    required = set(app.EVENT_KINDS) | {"error"}
    assert required <= declared, f"no SSE listener for: {sorted(required - declared)}"
    assert "addEventListener(type," in script


def test_the_page_never_sends_a_session_id():
    """The server derives the session from the cookie. A UI that sent one
    would hand back the attack the server's design closes: record ids are
    guessable, so an attacker-supplied session could reach another visitor's
    quarantined memory."""
    assert "session_id" not in HTML
    assert "mf_sid" not in HTML
    for fetch in re.findall(r"fetch\((.*?)\)\s*[.;]", HTML, re.S):
        if "/api/memory/" in fetch or "/api/reset" in fetch:
            assert 'credentials: "same-origin"' in fetch, f"fetch without cookies: {fetch[:80]}"


def test_reset_clears_the_session_not_the_process():
    """`app.reset_db()` is a process-wide wipe that would destroy every other
    visitor's memory. The button must hit the per-session route."""
    assert '"/api/reset"' in HTML
    assert "reset_db" not in HTML


def test_only_the_defended_arm_carries_defense_toggles():
    """Belt and braces alongside the server forcing the baseline off."""
    script = HTML.split("<script")[1]
    block = script.split('if (arm === "defended")')[1].split("}")[0]
    for flag in ("d1=", "d2=", "d3="):
        assert flag in block, f"{flag} is not inside the defended-only branch"


def test_injection_source_is_visibly_marked():
    """§6: the UI highlights where the injection entered."""
    assert "attacker-controllable" in HTML
    assert "injection source" in HTML
    assert ".chunk.untrusted" in HTML


def test_static_directory_is_still_not_served():
    """The page is served only through `GET /`."""
    client = TestClient(app.app)
    assert client.get("/static/index.html").status_code == 404
    assert client.get("/").status_code == 200


def test_index_is_valid_enough_to_parse():
    assert HTML.count("<html") == 1 and HTML.count("</html>") == 1


def test_the_page_does_not_claim_d1_blocks_anything():
    """D1 tags; it never refuses a call and never holds anything for review.

    A viewer reading the toggles has no way to know that the three defenses
    are different *kinds* of control, and the obvious assumption — three
    checkboxes, three things that stop attacks — is wrong about D1. This
    replaces an older test that required the page to mention the eval; the
    eval is no longer referenced in the UI, but the property that test was
    really protecting, that the page does not overstate D1, still holds.
    """
    markup = HTML.split("<script")[0].lower()
    d1 = markup[markup.index("<strong>d1</strong>"):]
    d1 = d1[:d1.index("</li>")]
    disclaimers = ("blocks nothing", "never blocks", "cannot stop anything",
                   "can only ask", "does not block")
    assert any(d in d1 for d in disclaimers), (
        f"the D1 description never says D1 cannot stop anything: {d1!r}"
    )
    for overclaim in ("d1 blocks", "d1 stops", "d1 refuses", "d1 prevents"):
        assert overclaim not in markup, f"the page claims {overclaim!r}"

    # The comparison table has to agree with the prose. D1 is the only one
    # whose outcome is decided by the model rather than by code or a person,
    # and that row is what stops three checkboxes reading as three of the
    # same kind of control.
    assert "determined by" in markup, "the comparison table lost its 'determined by' row"
    assert "the model" in markup, (
        "the table no longer says D1's outcome is decided by the model"
    )


@pytest.mark.parametrize(
    "sink",
    ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function("],
)
def test_no_html_injection_sinks(sink):
    """Every value the page renders comes from the trace, and the trace
    quotes the corpus — which in this project deliberately contains
    `</user><system>Ignore all prior instructions…` and other markup-shaped
    payloads. One innerHTML would turn the demo's own injection corpus into
    script running in the viewer's browser: a page about prompt injection
    shipping an XSS.
    """
    script = HTML.split("<script")[1]
    assert sink not in script, f"{sink} is an HTML/JS injection sink; use textContent"


def test_rendered_values_go_through_textcontent():
    assert "textContent" in HTML
    assert HTML.count("createElement") >= 1


# =============================================================================
# T5 -- the UI surfaces both M4 guardrails (CLAUDE.md §7, §10.3)
# =============================================================================


def test_onerror_copy_names_a_rate_limit_cause_as_well_as_the_mode():
    """T5: today `source.onerror` says only "check the mode" -- a 429 from
    the new per-IP rate limit (or the concurrent-run cap) reads identically
    to a misconfigured MODE, with nothing telling the visitor which one
    happened. The copy must name a rate/limit cause too."""
    script = HTML.split("<script")[1]
    assert "source.onerror" in script, "no source.onerror handler found"
    onerror_block = script.split("source.onerror", 1)[1].split("};", 1)[0]
    assert re.search(r"rate|limit", onerror_block, re.I), (
        "onerror copy does not mention a rate/limit cause"
    )
    assert re.search(r"mode", onerror_block, re.I), (
        "onerror copy dropped the existing mode-check wording"
    )


def test_script_has_a_token_cap_branch():
    """T5: a run stopped by the per-session token cap (§7) must be a
    distinct, visible state in the trace, not indistinguishable from an
    ordinary max_steps/end_turn stop."""
    script = HTML.split("<script")[1]
    assert "token_cap" in script, "no token_cap handling found in the inline script"


# --- the verdict must say *why*, not only *what* ---------------------------


def test_the_outcome_distinguishes_a_block_from_the_model_declining():
    """"Attacker goal not achieved" means two completely different things.

    With a defense enabled and firing, it is this demo's result. With nothing
    enabled — which happens routinely in live mode, where the model declines
    S3 outright — it is a fact about the model, and showing it in the same
    green as a block would claim a win the enforcement layer did not earn.
    """
    script = HTML.split("<script")[1]
    assert "stopped by" in script, "a block must name the defense that stopped it"
    assert "declined the" in script, "a model-level refusal must be labelled as one"
    assert "nothing stopped it" in script
    # Three tones, not two.
    assert '"neutral"' in script
    assert ".outcome.neutral" in HTML and ".verdict.neutral" in HTML


def test_an_unusable_response_is_not_presented_as_a_refusal():
    """`no_response` covers a safety filter or a malformed tool call. Letting
    that read as the model declining is the same conflation the eval fixes in
    its own table (§10.4)."""
    script = HTML.split("<script")[1]
    assert "no_response" in script
    assert "not evidence that it declined" in script


def test_the_undefended_column_states_that_nothing_was_enabled():
    """A viewer must be able to tell the baseline apart from a defended run
    at a glance, including when the attack happens to fail."""
    script = HTML.split("<script")[1]
    assert "No defenses were enabled" in script


def test_the_outcome_separates_consequential_actions_from_lookups():
    """A live run searches repeatedly; listing every read-only call buries
    the one line that says what the agent did to the world."""
    script = HTML.split("<script")[1]
    assert "a.privileged" in script
    assert "read-only call" in script
    assert "No privileged action was taken" in script


def test_the_page_is_revalidated_rather_than_served_from_cache():
    """A cached copy of `/` is a cached build of the whole demo.

    It fails silently: the page renders and runs while showing a defense
    name, a scenario list or a default mode from a previous deploy. It
    happened three times during this project, twice while writing the
    recording run sheet and once while verifying a deploy.
    """
    client = TestClient(app.app)
    response = client.get("/")
    assert response.status_code == 200
    cache_control = response.headers.get("cache-control", "")
    assert "no-cache" in cache_control, (
        f"/ is cacheable without revalidation: {cache_control!r}"
    )


def test_a_declined_run_with_d1_on_is_distinguished_from_no_defense_at_all():
    """Three not-achieved outcomes, not two.

    D1 never blocks, so it can never appear in a "stopped by" headline. The
    verdict used to collapse two different situations into "no defense fired":
    D1 tagged the untrusted text and the model then declined, versus nothing
    was applied at all. The first states as fact that D1 was idle when D1 is
    the only defense that could have acted.

    Asserted structurally, not on copy: the branch must key on D1 having
    annotated the run, and the three not-achieved cases must produce three
    different headlines. There is no JS seam to call these through, so this
    checks that the distinction exists rather than how it is worded.
    """
    script = HTML.split("<script")[1].split("</script>")[0]
    start = script.index("function renderOutcome")
    body = script[start:script.index("\n  function ", start + 1)]

    assert "annotated" in body, (
        "renderOutcome does not consult which defenses annotated the run, so a "
        "run D1 acted on cannot be told from one it did not"
    )

    headlines = re.findall(r'headline = "([^"]+)"', body)
    not_achieved = [h for h in headlines if "not achieved" in h]
    assert len(not_achieved) >= 3, (
        f"expected three distinct not-achieved verdicts, found {not_achieved!r}"
    )
    assert len(set(not_achieved)) == len(not_achieved), (
        f"two not-achieved branches share a headline: {not_achieved!r}"
    )


def test_the_page_offers_only_real_model_runs():
    """`mock` is a test double, not a mode a viewer should pick.

    Everything the page can run is now either a recorded real run or a live
    one. The scripted mock still backs the whole test suite and still answers
    `?mode=mock` on the API — it is just not something the demo offers, because
    a viewer choosing it would be shown a model with no judgement and no way
    to know that from the screen.
    """
    head = HTML.split("<script")[0]
    options = re.findall(r'<option value="([^"]+)"', head)
    assert "mock" not in options, f"the mode picker still offers mock: {options}"
    assert set(options) == {"replay", "live"}, options


def test_boot_never_selects_a_mode_the_page_does_not_offer():
    """Setting `select.value` to an absent option blanks the control.

    The service default may be `mock`, which the picker no longer lists, so
    boot must not assign it straight through.
    """
    script = HTML.split("<script")[1].split("</script>")[0]
    assert "config.replay_available ? \"replay\" : config.mode" not in script, (
        "boot assigns the service default to the picker without checking the "
        "option exists"
    )


def test_a_defense_that_touched_nothing_is_not_counted_as_having_acted():
    """D1 annotates every retrieval it is enabled for, wrapping nothing when
    no chunk is attacker-controllable — Case 4 is exactly that, because the
    trust map calls the injected field internal.

    Recording that as "D1 acted" would let the third verdict tell a viewer
    that D1 tagged the untrusted text when it touched none, which is the
    overstatement that verdict exists to prevent.
    """
    script = HTML.split("<script")[1].split("</script>")[0]
    start = script.index("annotated.push")
    guard = script[max(0, start - 600):start]
    assert "trigger_chunks" in guard, (
        "a defense is recorded as having acted without checking it touched anything"
    )


def test_every_case_says_what_is_worth_watching():
    """Cases 3 and 4 both end in a red verdict.

    Red reads as "broken". Case 3's refusal is the cost of the rule and Case
    4's silence is the blind spot — both are findings, and a viewer who is not
    told that reads them as the demo failing. Every case carries the line, not
    just those two, so the framing is not special pleading for the awkward
    ones.
    """
    import app as app_module

    for scenario_id in app_module.UI_SCENARIOS:
        watch = app_module.load_scenario(scenario_id).get("watch_for", "").strip()
        assert watch, f"{scenario_id} has no watch_for line"
        assert len(watch.split()) >= 8, f"{scenario_id}'s watch_for is too thin: {watch!r}"

    assert 'id="scenario-watch"' in HTML, "the page has nowhere to render it"
    script = HTML.split("<script")[1].split("</script>")[0]
    assert "watch_for" in script, "the page never reads watch_for"


def test_the_memory_panel_does_not_claim_everything_in_it_is_quarantined():
    """The panel lists both arms' memory, not only the quarantined rows.

    It used to be headed "Quarantine" and subtitled "nothing here is recalled
    by a later run", which was false of the row that matters most: the
    undefended arm's long-term write is exactly what Case 2's second alert
    goes on to believe. A row with no Approve button sat under a promise that
    described the row below it.
    """
    head = HTML.split("<script")[0]
    assert "nothing here is recalled by a later run" not in head, (
        "the panel still promises that every row in it is quarantined"
    )
    script = HTML.split("<script")[1].split("</script>")[0]
    render = script[script.index("function renderRecords"):]
    render = render[:render.index("\n  }")]
    assert "long-term" in render and "held for review" in render, (
        "a memory row does not say whether a later run will see it"
    )
