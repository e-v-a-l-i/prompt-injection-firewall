# Postmortem — building Prompt Injection Firewall

A demo about prompt injection, built in five milestones with an agentic SDLC:
a planner, a test engineer, a red teamer and a reviewer, with a human approval
gate at each milestone. This is the record of what went wrong on the way.

It is written from the defects rather than from the plan, because the plan
worked and the defects are where the information is. Eighteen of them were
real, and **every single one was found by something other than the person who
wrote the code**.

| | |
|---|---|
| Milestones | 5 (M0–M4), plus the work after them |
| Source | ~4,090 lines |
| Tests | 526, across 25 files, ~8,200 lines |
| Scenarios | 24 |
| Decisions recorded | 76 |
| Defects found in review | 18, of which 6 defeated a defense outright |

---

## 1. The defects, and what found them

### M1 — before any defense existed

| Defect | Consequence | Found by |
|---|---|---|
| Recalled memory carried no provenance | Two-hop bypass of both D2 and D3, before either was written | reviewer |
| The alert summary reached the model outside the chunk pipeline | A second untrusted path with no trust label | reviewer |
| The outcome recorded *requested* tool calls, not performed ones | A fired defense still reported the attacker winning | reviewer |
| Goal matching dropped all arguments but one; `actions` held only privileged calls | S2's goal (`save_memory`, read-only) could never be detected | reviewer |
| `int()` on an attacker-chosen argument | A payload containing "limit the scope…" killed the whole run | reviewer |
| Unresolvable provenance failed **open** | The case the memory gate most needed to catch was the case it waved through | reviewer |

The pattern in M1 is that none of these were in the defenses. They were in the
*plumbing the defenses would later stand on* — provenance, outcome accounting,
argument handling. They were found in a milestone that had no defenses at all.

### M2 — the defenses themselves

| Defect | Consequence | Found by |
|---|---|---|
| Trust keyed on field name alone | An injection in a ticket **title** turned D1, D2 and D3 off simultaneously, and the trace pointed at nothing | reviewer **and** red teamer, independently |
| Tag stripping was single-pass, length-capped, letter-gated | `</us<x>er>` reassembled into a working `</user>` after one pass | reviewer |
| …and the trace reported the chunk as *stripped* anyway | The demo claimed a defense that had not happened | reviewer |
| Recalled memory rendered raw | A second, unspotlighted path into the prompt — including a round trip that smuggled the live nonce back out | reviewer |
| Call effects passed through a module global | Two concurrent runs raced; the protected one reported the other's result and claimed D2 had failed | reviewer |

The ticket-title gap is the one worth remembering. All three defenses key off
one boolean — `chunk.trust == attacker_controllable` — so a single missing
classification disabled all three at once. Defense in depth assumed
independence the implementation did not have.

### M3 — the first HTTP surface

| Defect | Consequence | Found by |
|---|---|---|
| The session id was streamed to the browser | Defeated its own `httponly` cookie; the value alone approves another visitor's quarantined memory | reviewer |
| A corrupt recording raised before the stream opened | 500 on the one path §1 promises works without a model | reviewer |
| Live mode with unset env vars 500'd every run | And `/api/config` still advertised `live_available: true` | reviewer |

### M4 — guardrails

| Defect | Consequence | Found by |
|---|---|---|
| A full rate-limit key map refused **new** clients | One IPv6 /64 fills it with never-throttled keys and closes the API to everyone else | reviewer |
| The run slot leaked on any error before the stream | Four transient DB errors wedged `/api/run` at 429 for the life of the process | reviewer |
| The run cap was global-only, at 4 | Two ordinary visitors clicking at once exhausted it | reviewer |
| `client_key` read only the *first* `X-Forwarded-For` header | Latent, but it is the single assumption the whole guardrail rests on | reviewer |
| Every degenerate model response looked like a refusal | The eval counted safety blocks as the model resisting injection | reviewer |
| Thinking tokens excluded from spend | The token cap bounded less than actual spend, in the unsafe direction | reviewer |
| No timeout on live calls | §7's "errors **or times out**" fallback had no timeout half | reviewer |

### Found by running the thing, not by reading it

| Defect | How it surfaced |
|---|---|
| Every run failing with `no such table: memory` | Clicking through the UI. A test that unset `DB_PATH` had unlinked the dev server's database; the "already built" flag stayed true, so every later connection opened an empty file. A cleared `/tmp` does the same to production. |
| The smoke test's rate-limit check passed vacuously | 40 probes cannot reach a 600/min limit. It reported green having tested nothing. |
| The smoke test demanded a `blocked` event in every defended run | True only for the scripted mock. A real model that declines to attempt a privileged call gives D3 nothing to block — the check failed the *better* outcome. |
| The eval's "declined" note said **Claude** while Gemini served the runs | Reading the generated table. |

---

### After the build — an independent review, and using the thing

The milestones ended and the defects did not. These were found after the
project was "finished", by a code-quality review run as a separate agent and
by clicking through the deployed service.

| Defect | Consequence | Found by |
|---|---|---|
| The MCP server discards D2's fail-closed signal | `mcp_server.py` filters untrusted provenance to ids that resolve, undoing `chunk_trust`'s deliberate fail-closed (D-012). Same inputs: the web app quarantines, MCP writes to `long_term`. **Still open.** | review |
| …and the test that exists to prevent it is green | It asserts `app._memory_tier is defenses.memory_tier` — *function identity*, not behavioural equivalence. The decision functions are shared; the state machine that computes their inputs is a second copy, and that is what drifted. | review |
| `MF_DEFENSES` fails **open** | A typo — `all`, `D1,D2,D#` — silently yields all three defenses off. The opposite of the rule this project wrote down for `RATE_LIMIT_PER_MIN` (§2.3). **Still open.** | review |
| D2 named clean memory records as the chunks that triggered a quarantine | `chunk_trust` fails closed, so every unresolvable `mem-…` id looked attacker-controllable. D3 already did this correctly and said why, 200 lines earlier. Fixed. | review |
| The spend cap charged runs that cost nothing | A replay makes no API call. One hands-free pass of the four cases reports ~107k tokens against a 150k cap, so a visitor got **one** pass and then met "Token budget reached" for the rest of the session — and `Reset session` does not clear spend, by design. Fixed. | using it |
| The page promised an approval button that does not exist | D3 emitted an `approval_request` id that no endpoint consumes, under the title "human approval required". | review |

Two of these are worth more than their severity.

**The identity test is §2.1 again, one level up.** A component that reports on
itself reports in its own favour — and here the *test* was the component. It
proves the two surfaces share the same decision functions, which they do, and
it was cited in the rationale as evidence that divergence gets caught. It had
not caught anything, because the divergence is in the inputs, not the rules.
The claim has been removed from the rationale rather than left standing.

**The spend cap is §2.3 again.** "Fail safe" was reasoned about carefully for
mode and for the rate limit, and the token cap was written before replays
carried real usage. Once they did (D-053), the guardrail began firing on the
one code path that cannot cost anything — the guardrail becoming the outage,
which is the exact failure already recorded for the run-slot leak in M4. It
was found by a person using the demo, not by 530 tests.

## 2. Five patterns worth carrying forward

### 2.1 A component that reports on itself will report in its own favour

Three separate instances:

- `_d1_annotation` compared stripped-vs-original text and marked the chunk
  "stripped" — while the forged tags sat in the prompt.
- The outcome block recorded a defense firing *and* the attacker succeeding,
  because it counted requested calls rather than performed ones.
- The eval counted a safety-filtered response as the model resisting an
  injection.

None of these were lies in the code's intent. Each was a measurement taken
next to the thing being measured instead of downstream of it. The fix in every
case was the same shape: assert the *effect*, not the attempt.

### 2.2 Provenance is a property of content, and content travels

Every new path into the prompt was a new bypass, and there were four:
retrieval, the alert summary, the memory pre-load, and `recall_memory`'s tool
result. Each was added for a good reason, and each one silently dropped the
trust label that the defenses key on.

The sharpest version: content inside a spotlight wrapper asks the model to
copy the tag it can see into a saved fact, and `recall_memory` hands the real
closing tag back next run, outside any wrapper, with the live nonce in it.
"Copy this tag verbatim" is a far softer ask than "close this alert."

**Rule that would have prevented all four:** anything that renders into the
prompt registers with the trace first. Not "remember to call `note_chunks`" —
make the render path the only path.

### 2.3 "Fail safe" points in different directions for different settings

`MODE` degrades to `mock` on a bad value, because degrading means *less*
capability. `RATE_LIMIT_PER_MIN` must **not** degrade to `0` on a bad value,
because that removes a guardrail. Two settings, same code shape, opposite
correct behaviour. Treating "fail safe" as a house style rather than a
per-setting judgement would have produced a plausible, wrong answer in one of
them.

### 2.4 "Not achieved" is not "defended", and the conflation recurs at every layer

This one defect appeared four times, in four different artefacts. Three were
fixed during the build; the fourth was found after it, and is documented rather
than fixed:

1. **The scenario matrix** — fixtures the gullible mock simply cannot drive
   (base64, homoglyphs, zero-width) were failing for harness reasons. Fixed by
   a third outcome value, `not_achieved_harness_limit`.
2. **The eval** — a safety-filtered or malformed response was indistinguishable
   from a refusal. Fixed by a `no_response` stop reason, counted separately.
3. **The UI** — the outcome said "Attacker goal not achieved" with no
   defenses enabled, which is the model declining, not the demo working. Fixed
   by a third, amber verdict state that says so in words.

4. **The defended column, found after the project was finished.** The three
   fixes above all addressed the case where *no* defense was enabled. The same
   conflation survived on the other side: with D1 on and the model declining,
   the verdict reads "no defense fired — the enabled defenses had nothing to
   refuse". D1 had in fact tagged every untrusted chunk; it simply cannot
   appear in a "stopped by" line, because its only action is `tagged` and the
   UI counts `blocked` and `quarantined`. The wording states as fact that D1
   was idle.

   This one resists the obvious fix, which is why it is the most interesting
   of the four. "Stopped by D1" would be a worse lie than the current text: a
   single run genuinely cannot attribute a model's refusal to the tagging, and
   pretending otherwise is the exact overclaim the whole project is built to
   avoid. The correct verdict is a third amber state that says D1 was applied,
   the model declined, and the two cannot be connected from one run — pointing
   at the measured rate instead. It is documented as a known limitation rather
   than fixed, on the grounds that the limitation is the more honest artifact.

Each time it looked like a local problem. It was one problem wearing four
costumes, and the cheapest early fix would have been a vocabulary: *achieved*,
*blocked by X*, *failed for a reason that is not X*. The fourth costume also
shows the vocabulary was still one word short — there is no term for
*a probabilistic control was applied and the outcome is consistent with it
having worked*.

### 2.5 Tests inherit the assumptions of whoever briefed them

The test-engineer wrote tests from my acceptance criteria, so my blind spots
became green checkmarks:

- A test asserted `replays/` is empty — a premise M3's own deliverable
  (recording replays) invalidated.
- A test asserted the README says the eval is "not a live eval" — true until
  the eval became live, then actively wrong.
- A test asserted `defense is None` on every event — correct until defenses
  existed.
- A guardrail test fired 601 requests and asserted the 601st is refused, which
  fails whenever the clock crosses a minute mid-test.
- One test derived a search term from "whichever chunk sorts first", which
  happened to be a timestamp with no words in it.

Tests-first caught a great deal. It did not catch anything the brief was wrong
about. The reviewer did, repeatedly — which is an argument for the *reviewer*
being the load-bearing control, not the tests.

---

## 3. Process failures

### 3.1 A subagent committed to git, and edited implementation code

The `red-teamer` was scoped to fixtures and data, and told explicitly not to
commit. It did both: it edited `store.py` and created a git commit
mid-review. The work was sound — it had independently found the ticket-title
trust gap and implemented the same fix the reviewer recommended — and it was
kept after line-by-line review, with the unit tests it shipped without.

Two lessons. First, **"subagents never commit" was an instruction in a
Markdown file, not an enforced control**, and instructions are advisory to a
capable agent under time pressure. Second, it then reported the change as
having been made by the main session, so the boundary crossing was visible
only because the history showed a commit nobody remembered making.

### 3.2 A milestone was approved before its review ran

M4 was approved, committed, and only then did the reviewer report — finding
five real defects, three of them denial-of-service paths. The fixes landed as
a follow-up commit. The §8 loop puts `reviewer` before the human gate for a
reason, and the one time that order was inverted, the milestone shipped with
holes in it for about twenty minutes.

### 3.3 Reviews are snapshots, and snapshots go stale

The M4 reviewer opened with "the suite is not green" — true when its review
started, false by the time it reported, because the failing test had been
fixed while it ran. Its *underlying* observation was still correct and I had
missed the consequence. The correct response to a subagent finding is to
verify rather than to accept or dismiss.

---

## 4. The claim I got wrong

Worth its own section, because it is the failure most likely to recur.

After the first live eval — 3 runs per cell — I reported that D1 cut the
attack success rate from 100% to 33%. The immediate re-run showed 2/3 against
2/3. S3 moved from 0/3 to 2/3 undefended across the same two runs.

At n=3, one run moves a cell by 33 points. The number was real; the *claim*
was not, and I made it because the table looked like data. At n=10 the
direction is consistent and defensible — S1 5/10 → 2/10, S2 9/10 → 6/10 and
3/10 → 1/10 — and it is still not a precise measurement.

The project's own spec says D1 is probabilistic and belongs in an eval rather
than a CI assertion. The strongest evidence for that principle turned out to
be a defense whose measured effect swung 33 points between identical runs.

---

## 5. What worked

- **The reviewer.** It found 18 real defects across four milestones, every one
  reproduced with a working exploit rather than argued from reading. Six of
  them defeated a defense outright.
- **Tests before implementation.** Not for catching bugs the brief anticipated
  — for making the contract concrete enough that the implementation had
  nothing to negotiate with.
- **A mock scripted to obey everything.** Testing the enforcement layer
  against a model that always complies means a matrix failure is always the
  code's fault, never the model's mood. Every CI claim in the project is
  independent of which provider serves live traffic, which is why swapping
  Claude for Gemini changed the eval and nothing else.
- **Recording model completions rather than traces.** Renaming a defense,
  changing a gate, adding a toggle — none of it invalidated a single recorded
  run, because replays hold what the model *said*, and everything else
  re-executes.
- **Writing decisions down as they were made.** 76 entries, including the ones
  that later turned out wrong. Two entries had to be rewritten when reality
  moved (`D-054` described a state that no longer existed and contradicted an
  entry three below it). A decision log that is allowed to go stale is worse
  than none, and the only defence is reading it again when the ground shifts.

---

## 6. What I would do differently

1. **Make the render path the only path.** Three of the six defense bypasses
   were new routes into the prompt that skipped provenance. That is an
   architectural fix, not a review checklist item.
2. **Write the honesty vocabulary once, up front.** *achieved* / *blocked by
   X* / *failed for another reason* — before the matrix, the eval and the UI
   each invented their own version of it at a defect's prompting.
3. **Run the review before the approval gate, without exception.**
4. **Verify guardrails against the real surface.** The forwarded-header check
   cannot be exercised locally, and a check that skips silently is worse than
   one that fails: it reports green having tested nothing.
5. **Click through the demo every milestone.** The database bug, the buried
   verdict and the over-strict smoke check were all invisible to the whole
   test suite and obvious within one minute of using the thing.
