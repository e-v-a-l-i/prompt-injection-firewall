# Prompt Injection Firewall — decision log

Key tradeoffs, recorded as they are made (§12). Format:

`D-nnn | decision | options considered | reason`

## M0 — repo, skeleton, /health

### D-001 Python 3.12 in a dedicated venv
- **Decision:** `.venv` built from `/opt/homebrew/bin/python3.12`; `.python-version`
  pins `3.12` so the Cloud Run buildpack picks the same runtime.
- **Options:** use the system interpreter; pin 3.12 explicitly.
- **Reason:** system `python3` on this machine is 3.9.6. §2 specifies 3.12, and
  `str | None` syntax in `app.py` already requires it. Pinning avoids a class of
  "works locally, fails on deploy" surprises.
- **Amended at the M1 deploy:** Cloud Run's buildpack no longer offers 3.12. The
  builder's Artifact Registry lists only 3.13.x and 3.14.x, and `.python-version:
  3.12` failed the build outright. `.python-version` is now `3.13`; the local
  venv stays on 3.12 because that is the newest interpreter installed on this
  machine. The runtime split is a real (small) risk — the code targets 3.10+
  syntax and the four pinned deps ship wheels for both — and it is the exact
  thing D-001 set out to avoid. Closing it means installing 3.13 locally and
  rebuilding the venv. Flagged for the human; deliberately not done mid-milestone.

### D-002b First deploy landed at the top of M1
- **Decision:** deployed `memory-firewall` to Cloud Run, `us-central1`,
  `--max-instances 1`, `--allow-unauthenticated`, `MODE=mock`, default compute
  service account.
- **Result:** https://memory-firewall-366819802884.us-central1.run.app —
  `/health` 200 `{"status":"ok","mode":"mock","version":"0.1.0"}`, `/` 200 HTML,
  unknown route 404, and `/openapi.json` and `/static/*` both 404 in production,
  confirming the M0 hardening survived the deploy.
- **Cost:** two builds — the first failed on the 3.12 runtime (see D-001).

### D-002 First Cloud Run deploy moved to the top of M1
- **Decision:** M0 closes on a green local `/health`; the first deploy is M1's
  first task.
- **Options:** deploy inside M0 as §9 specifies and accept a ~10m overrun; defer.
- **Reason:** the planner estimated M0 at exactly its 20m box with the deploy as
  the riskiest item — a fresh project needs `run`, `cloudbuild` and
  `artifactregistry` APIs enabled plus a cold buildpack build (3-6m). Deferring
  protects the box while keeping "deploy early" intact: the live URL still
  arrives early, just inside M1.
- **Cost:** M0's demoable result is a local `/health`, not a live URL. M1 is the
  milestone most likely to overrun as a result.

### D-003 Four modules instead of §2's two
- **Decision:** `app.py` (API, agent loop, defenses, SSE), `clients.py` (model
  clients), `store.py` (SQLite: FTS5 retrieval + memory tiers), `skills.py`
  (skill loader).
- **Options:** keep everything in `app.py` per §2's layout.
- **Reason:** a deliberate deviation from the spec's layout, taken so M1's units
  are testable without importing the API layer. Retrieval and the skill loader
  are where the security-relevant invariants live (`trust` on every chunk,
  `trust_level` on every skill); they deserve direct unit tests.

### D-004 `MODE=mock` added as a third value
- **Decision:** `MODE` accepts `mock | replay | live`; unset or unrecognised
  resolves to `mock`.
- **Options:** §2's `live|replay` only, selecting `MockClient` implicitly by the
  absence of `GCP_PROJECT`.
- **Reason:** makes §11's "all tests pass with no network access" an explicit,
  inspectable mode rather than an implicit fallback. An unrecognised value falls
  back to `mock` rather than raising, because `mock` is the mode that cannot
  reach the network — a bad env var should degrade, not take the service down.

### D-005 Import-time side-effect freedom is a tested invariant
- **Decision:** importing `app` constructs no model client, opens no socket and
  writes no file. The DB is built on first use, not at import.
- **Options:** build the SQLite DB at import, as "DB built at startup from
  `data/`" (§2) suggests.
- **Reason:** every test in the suite imports the module; if import reached the
  network, the suite would need mocks everywhere and CI would be flaky. The M0
  test enforces this with a scrubbed-env subprocess that patches `socket.connect`
  and write-mode `open` to raise, so a future module-level `VertexClient()` fails
  loudly instead of silently hanging.

### D-006 Runtime and dev dependencies split
- **Decision:** `requirements.txt` holds only what Cloud Run needs
  (`fastapi`, `uvicorn[standard]`, `pyyaml`, `anthropic[vertex]`);
  `requirements-dev.txt` adds `pytest` and `httpx`.
- **Options:** one manifest.
- **Reason:** §12 requires asking before adding dependencies beyond §2. `httpx`
  is a transitive requirement of FastAPI's `TestClient`, not of the service;
  keeping it dev-only means the deployed image's dependency set is exactly what
  §2 specifies. `.gcloudignore` excludes `tests/` and the dev manifest.
- **Also noted:** `pyyaml` is not named in §2 either, but is implied by §4's
  `scenarios/*.yaml` and §3's SKILL.md frontmatter. It ships as a runtime dep.
- **Pins:** all four runtime deps are pinned with `==`. D-001 pins the
  interpreter; leaving the libraries floating would leave the more volatile half
  to resolve fresh at deploy time, and M3's `VertexClient` is written against
  whatever `anthropic[vertex]` the local venv has.

### D-006b `.gcloudignore` re-includes `.gitignore`
- **Decision:** `.gcloudignore` starts with `#!include:.gitignore` and restates
  the credential patterns (`.env*`, `*.pem`, `*key*.json`) below.
- **Reason:** found in review. When a `.gcloudignore` exists, gcloud uses it
  verbatim instead of the generated one that inherits `.gitignore`. Without the
  include, a local `.env` or downloaded service-account key would be git-ignored
  but still uploaded to Cloud Build and baked into the image — §7's "no secrets
  in the repo" violated without anything showing up in `git status`.

### D-006c The import-time guard is itself tested
- **Decision:** seven parametrized cases assert that AC1's guard actually fails
  on each side effect it claims to catch, plus one asserting it still passes a
  clean module.
- **Reason:** also found in review. The first guard patched `builtins.open`
  only, so `pathlib.Path.write_text`, `os.open`, and `sqlite3.connect` all sailed
  through — the exact shape of the DB-at-startup code M1 will write. A guard that
  catches nothing is indistinguishable from a clean app in the test report, so
  the guard needs its own failing case.

## M1 — planned decisions (not yet implemented)

### D-007 Trust is per-field, not per-document
- **Decision:** each data record yields several retrieval chunks;
  `data/trust_map.yaml` marks `user_agent`, `url`, `referer`, `dns_query`,
  `comment` and `filename` as `attacker_controllable`, everything else
  `internal`.
- **Reason:** this is what makes S1 legible in the trace — one chunk of an
  otherwise internal log line carries the injection, and the UI can point at it.

### D-008 `MockClient` has two modes
- **Decision:** scripted (deterministic unit tests) and "gullible" — follows any
  instruction it finds in context that names an available tool.
- **Options:** have each scenario YAML declare the tool call the mock emits.
- **Reason:** §10.2 wants the scenario matrix to test the enforcement layer, not
  model behavior. A gullible model makes a matrix failure mean the enforcement
  layer failed. The YAML-declared alternative is simpler but makes the test
  partly assert its own fixture.

### D-009 Memory tiers exist in M1; the D2 gate lands in M2
- **Decision:** the `tier`, `status` and `provenance` columns exist from the
  first schema; M1 always writes `long_term`.
- **Reason:** D2 then arrives as a policy change, not a schema migration.

### D-010 One trace event schema, two transports
- **Decision:** M1 returns the trace as a list of event dicts; M3 re-emits
  byte-identical objects over SSE. Every event carries `defense` and
  `untrusted_in_context` keys from M1, unfilled until M2.
- **Reason:** the UI and the tests read one shape, and M2 adds defenses without
  reshaping the trace.

## M1 — data, retrieval, skills, memory, agent loop

### D-011 Retrieval interleaves documents instead of concatenating them
- **Decision:** `_retrieve_for_alert` orders each document's fields by
  informativeness (summary, message, user_agent, url … then identifiers, then
  bookkeeping) and round-robins across documents.
- **Found by:** implementing S1. Per-field chunking means ALR-1001 alone emits
  nine chunks, so a flat limit filled the context with timestamps and ports and
  never reached `evt-00042` — the injection was not retrieved at all and the
  scenario silently did nothing.
- **Reason:** which record gets read should not be an accident of file order.

### D-012 Unresolvable provenance fails closed
- **Decision:** `store.chunk_trust` returns `attacker_controllable` for any
  chunk id the corpus cannot resolve, rather than guessing from the field name.
- **Found by:** review. The field-name fallback failed open on a trailing
  space, a different case, an extra id segment, or any field with no trust_map
  entry — and the fallback exists precisely for ids the DB does not know
  (stale provenance surviving a rebuild, a hand-written fixture).
- **Reason:** "provenance I cannot check" is the case the memory gate most
  needs to catch. Fail closed on the path built for the unknown.

### D-013 Provenance is tracked on the trace, not re-derived from it
- **Decision:** `_Trace` accumulates every source id that reaches the model's
  context — from retrieval and from recalled memory — and a memory write is
  attributed to that set.
- **Found by:** review, as a two-hop bypass of both D2 and D3. Recalled memory
  reaches the prompt as plain text with no chunk and no trust label: an
  attacker's claim entered memory from a poisoned chunk on run one, came back
  out on run two with `untrusted_in_context` still False, and could be re-saved
  attributed to nothing but that run's own clean retrievals. Untrusted content
  in the prompt, both gates blind to it.
- **Reason:** the flag has to describe what the model actually read, by
  whatever route. Anything that renders into the prompt registers first.

### D-014 The outcome records performed calls, not requested ones
- **Decision:** `_execute_skill` reports whether it ran; the outcome's
  `actions` and `alert_status` are updated only when it did. Every executed
  call is recorded with a `privileged` flag rather than only privileged ones.
- **Found by:** review, with an M2-shaped D3 stubbed in: the defense fired, the
  trace said so, and the outcome still reported the attacker had won.
- **Reason:** §10.2 asserts "blocked" by reading the outcome. Recording all
  tool calls also makes S2's goal detectable at all — `save_memory` is
  `read_only`, so a privileged-only list could never see it.

### D-015 Attacker-chosen tool arguments degrade instead of raising
- **Decision:** `search_logs`'s `limit` is parsed defensively and clamped.
- **Found by:** review. The gullible model extracts arguments from the same
  untrusted text that named the tool, so a payload containing "limit the scope
  to this host" produced `limit="the"` and `int()` killed the run — no done
  event, no defense evaluation, and in M3 a dead SSE stream.

### D-016 `trust_level` is not sent to the model
- **Decision:** `to_tool_schemas` omits it; the policy layer reads the level
  from the loaded Skill.
- **Reason:** the Messages API rejects unknown fields on a tool object (M3's
  `VertexClient` would 400), and a privilege label the model can see is a
  privilege label an injection can argue with.

### Known limitations carried into M2
- **IP search is a bag of digits.** FTS5's tokenizer splits `10.0.4.17` into
  `10 0 4 17`, so `10.0.17.4` matches the same records. The host top-up in
  `_retrieve_for_alert` uses this, so a larger corpus could pull
  attacker-controlled content from unrelated hosts into context.
- **Non-ASCII is dropped by the tokenizer**, so a homoglyph or IDN indicator is
  unsearchable rather than erroring. This matters for the red-teamer's
  confusable-character variants (S1d).
- **Split-payload variants are retrieval-limited, not policy-limited.** The
  red-teamer's S1g/S1h never get their second fragment into context: the host
  top-up's five slots are taken by the alert's own internal chunks, which
  contain the host IP literally and outrank a planted ticket comment. Both
  fragments must reach context before D1's cross-chunk behaviour means
  anything.
- **`reset_db()` is a process-wide wipe.** The UI's reset button must call
  `store.reset_session(conn, session_id)` instead, or one visitor's reset
  destroys another's memory.

## M2 — S2, S3, defenses D1–D3, scenario matrix

### D-017 Alerts link their tickets explicitly (`related_tickets`)
- **Decision:** retrieval follows an alert's `related_tickets` the same way it
  follows `related_logs`, rather than discovering tickets by keyword.
- **Options:** an FTS search on the alert id (verified to work — TKT-4488's
  body says "Auto-created from ALR-1001", so it is the top hit) vs. an
  explicit field.
- **Reason:** D-011 already established that which record reaches the model
  must not be an accident of bm25 ranking. Closes the split-payload retrieval
  gap recorded at the end of M1: S1g's second fragment now reaches context, so
  the family is policy-limited rather than retrieval-limited.

### D-018 Each scenario carries exactly one injection
- **Decision:** S2 got its own alert (ALR-1031) instead of hanging its
  poisoning comment off ALR-1001.
- **Found by:** printing the matrix. Linking TKT-4488 to ALR-1001 put S2's
  payload into S1's context, and S1's all-defenses row started showing D2
  firing alongside D3.
- **Reason:** the demo's claim is that a user can see *where* the injection
  entered. Two injections in one alert's context makes that unanswerable.

### D-019 `_render_chunks` is D1's choke point for retrieved chunks
> **Superseded in part by D-029.** This was written as "the single choke
> point", which was already untrue: the memory pre-load (D-027) rendered
> recalled facts into the prompt outside it. Corrected below.
- **Decision:** both the first prompt and every `search_logs` result render
  through it, so one change covers both paths. The alert summary is built from
  already-retrieved chunks (M1's D-013 fix), so no untrusted text reaches the
  prompt outside a wrapper.

### D-020 D1 strips tag-like text and the live nonce, only when D1 is on
- **Decision:** `_strip_taglike` removes anything tag-shaped — a forged
  `</untrusted-…>`, `</user>`, `<system>`, `<tool_result>` — and any literal
  occurrence of the run's nonce, so content cannot reassemble a closing tag.
  With D1 off, nothing is stripped.
- **Reason:** leaving the undefended path untouched is what makes S1f's
  before/after meaningful. A defense that quietly also cleans the undefended
  baseline would make the demo lie in its own favour.

### D-021 D1 does not normalise zero-width or homoglyph characters
- **Decision:** deliberate omission, confirmed with the human.
- **Reason:** the defenses key on a chunk's *trust label*, not on matching its
  content, so obfuscation evades nothing in this design and normalising buys
  no security. It would also invert the demo: the gullible mock matches tool
  names literally, so stripping U+200B under D1 would make S1e read
  "undefended: not achieved / D1 on: achieved" — the defense appearing to
  enable the attack.
- **Alternative if wanted later:** strip Unicode `Cf` code points at *ingest*
  (`store.iter_chunk_rows`), documented as modelling the fact that a model
  reads through zero-width characters — not as a defense. Homoglyphs stay out
  either way; they need a confusables table (§12 dependency question) and
  remain a live-eval case.

### D-022 Both gates are pure functions
- **Decision:** `_memory_tier(defenses, untrusted_in_context, untrusted_ids)`
  and `_d3_blocks(defenses, skill, untrusted_in_context)` are module-level and
  side-effect free; the loop calls them.
- **Reason:** §10.1's determinism tests then need no corpus — which matters,
  because no alert in `data/` retrieves a fully clean chunk set, so "a
  privileged call with clean context is allowed" is untestable end to end.

### D-023 D2 fails closed on two signals
- **Decision:** quarantine if `untrusted_in_context` **or** any provenance id
  resolves as untrusted.
- **Reason:** D-012 makes an unresolvable id read as attacker-controllable,
  and D-013's flag is the authoritative record of what the model read.
  Quarantine is recoverable by a human clicking approve; a poisoned long-term
  fact is not.

### D-024 D3 checks before dispatch, and the run continues
- **Decision:** the policy check runs before `_execute_skill`, so `executed`
  is never True for a blocked call and D-014's outcome contract holds
  unchanged. The model gets an `is_error` tool result saying a human must
  approve, and the loop carries on to `done`.
- **Reason:** a blocked call is a decision handed to a human, not a crash.

### D-025 The attacker's goal can name an *effect*, not just a call
- **Decision:** `attacker_goal` may declare `effect: {tier: long_term}`;
  executed calls record their effect alongside their arguments.
- **Found by:** S2's D2 row scoring as a win. The `save_memory` call really
  did run — it landed in quarantine. §4 defines S2's goal as the false fact
  being *saved*, so a quarantined write achieves nothing, and the matrix has
  to be able to say that.

### D-026 The matrix has three outcomes, not two
- **Decision:** `achieved`, `blocked_by:Dn`, and
  `not_achieved_harness_limit`.
- **Reason:** S1b–S1e and S1h fail only because `MockClient(gullible=True)`
  matches tool names as literal ASCII and never decodes base64, hex,
  homoglyphs or zero-width splices. Scoring those as blocks would claim a
  defensive win the enforcement layer did not earn. This is the mechanical
  form of §10.4's "report results honestly".

### D-027 Long-term memory is pre-loaded into every run's first message
- **Decision:** after retrieval, before the first model turn, via
  `store.recall_memory` + `trace.note_recalled`.
- **Reason:** without it S2's stage 2 has nothing to be poisoned by. With it,
  the quarantine tier is what actually stops the attack — quarantined records
  are never recalled, so they never reach a later run's prompt.

### D-028 `MockClient` takes free-text arguments from the directive's sentence
- **Decision:** the last-resort fallback for a required prose parameter reads
  the span after the tool name, not the start of the context block.
- **Found by:** S2's poisoned memory containing the *alert summary* instead of
  the attacker's claim, which made stage 2 incoherent. Reinforces D-008: an
  attacker who writes the instruction writes the arguments.

### D-029 D1 wraps recalled memory, not just retrieved chunks
- **Found by:** review, as a full D1 bypass. The memory pre-load (D-027)
  rendered remembered facts into the prompt as plain text, outside any
  wrapper and unstripped — so D-019's "single choke point" claim was false the
  moment it was written.
- **Worse:** the reviewer demonstrated a same-run round trip. Content inside a
  wrapper asks the model to copy the tag it can see into a saved note; the
  next `recall_memory` hands back a real `</untrusted-{nonce}>` outside any
  wrapper. The attacker never guesses the nonce — the model is asked to copy
  it.
- **Decision:** both the pre-load and the `recall_memory` result render
  through the same wrapper-and-strip path as chunks. A human approving a
  quarantined record does not make its wording safe, so approved records are
  wrapped too.

### D-030 Tag stripping repeats to a fixed point
- **Found by:** review. One `re.sub` pass lets nested tags reassemble:
  `</us<x>er>` loses its inner `<x>` and becomes a working `</user>`. The
  trace then annotated the chunk as "stripped", so the demo claimed a defense
  that had not happened.

### D-031 What counts as "tag-like"
- **Decision:** three rules — an HTML comment; a tag opening with a letter,
  optionally prefixed by `!` or `?` (no length cap); and any bracketed run
  containing no whitespace.
- **Rejected:** a `{0,200}` body cap (`<system ` + 250 characters walked
  through it) and an `[A-Za-z]`-only first character (`<1system>` walked
  through that). `<!-- x -->` carries whitespace and has no tag name, so it
  fell through both remaining rules and needed a rule of its own.
- **Also rejected:** stripping every bracketed run whatever it contains. That
  removed the middle of an ordinary log line — `latency < 5ms and count > 3`
  — and stripping only ever applies to attacker-controllable chunks, which
  are precisely the evidence an analyst is reading. §5 asks for tag-like text
  to go; a prose comparison carries whitespace and no tag name, and is not
  what a model reads as a boundary. A defense that silently corrupts evidence
  has a cost of its own.

### D-032 Trust is keyed by document type and field, not field alone
- **Found by:** review. `comment` and `body` are attacker-controllable
  "because anyone with ticket access can write one" — and the same person
  writes the ticket's `title`, which was `internal`. Moving S3's payload into
  the title turned off D1, D2 and D3 at once: nothing was wrapped, nothing was
  flagged, and the privileged call executed.
- **Decision:** `trust_map.yaml` gains a `by_doc_type` block; `ticket` adds
  `title`, `status`, `assignee`. An alert's title, written by a detection
  rule, stays internal.
- **Regression fixtures:** S2e and S3e carry this payload shape permanently,
  and `tests/test_m2_regressions.py` pins the per-`(doc_type, field)` labels
  directly, which the fixtures alone did not.
- **Reachable only from M2:** D-017's `related_tickets` link is what first put
  ticket chunks into an alert's context at all.
- **Lesson worth keeping:** `trust_map.yaml` is now a security-critical file.
  A field added to the data without a map entry is a silent hole in all three
  defenses at once, and the trace points at no injection source.

### D-033 Skill effects are returned, not passed through a module global
- **Found by:** review, with a reproduction. Two concurrent `run_scenario`
  calls racing on a module-level `_LAST_EFFECT` made one run report the
  other's memory tier — enough to flip `attacker_goal_achieved` and claim D2
  had failed on a run where it worked. M3 serves this over HTTP with SSE, so
  two browser tabs would have been enough.

### Process note: the red-teamer edited implementation code
- The resumed red-teamer went beyond "fixtures and data only" and changed
  `app.py` and the tests. The work was sound and matched findings the reviewer
  had independently raised, so it was kept after verification rather than
  reverted — except its tag-stripping rule, which was over-broad (see D-031).
- It was stopped mid-iteration, leaving two of its own tests failing; those
  are resolved above. Every change it made was re-verified directly before
  being kept.


### D-034 `iter_scenario` is a generator; `run_scenario` collects it
- **Decision:** the agent loop yields trace events as they happen.
  `run_scenario` is a three-line wrapper returning `list(iter_scenario(...))`
  for tests, scoring and replay recording. Events emitted from inside a skill
  drain after dispatch, since a skill cannot yield for itself.
- **Reason:** done before M3 rather than during it. Retrofitting a streaming
  interface onto a 300-line function whose UI already depends on its shape is
  a different and worse job than splitting it while nothing depends on it yet.
- **Pinned by test:** the model must not be called before the first two
  events reach the consumer — otherwise a UI streams nothing until `done` and
  nobody notices until the demo.

### D-035 The live eval is scoped to S1/S2/S3, and "defended" means D1 only
- **Decision:** §10.4's eval runs the three canonical scenarios, not all 22
  fixtures, and its defended arm enables **D1 alone**.
- **Reason:** D2 and D3 are deterministic code. Running them against a real
  model measures an `if` statement at API prices and tells you nothing you
  cannot get from CI. D1 is the only defense whose efficacy is a question
  about model behaviour, so it is the only one worth spending live tokens on.
  With all three enabled, a blocked run tells you the enforcement layer
  worked — which the matrix already proves deterministically — while D1's
  actual effect stays invisible behind the block.
- **Consequence:** the eval table reports D1-only vs undefended, per scenario.
  If Claude resists a scenario even undefended, §10.4 says to report that
  plainly and keep the scenario: model-level resistance plus defense in depth
  is the honest result, not a failed experiment.
- **Variants stay in CI:** S1a-S1i, S2a-S2e and S3a-S3e remain deterministic
  regression fixtures. They are not eval material.

## M3 — SSE UI, VertexClient, replays, live eval

### D-036 One SQLite connection per caller, over a WAL file
- **Decision:** `app.get_db()` builds the corpus once into a file (guarded by
  a lock) and hands every caller a fresh connection; `store.build_db` sets
  `journal_mode=WAL` and `busy_timeout`.
- **Found by:** the planner, before the UI existed. The side-by-side view
  opens two SSE streams at once and Starlette runs sync generators on a
  threadpool, so two runs shared one connection. Measured: four threads ×
  200 inserts kept **339 of 800 rows**, with repeated
  `InterfaceError('bad parameter or other API misuse')`.
- **Why it mattered more than it looks:** the lost writes are memory writes.
  In a demo, that reads as D2 intermittently failing to record a quarantine —
  a defense that looks flaky rather than a database that is broken.
- **Rejected:** a shared-cache in-memory DB (`file:x?mode=memory&cache=shared`)
  — raises `database table is locked` and ignores `busy_timeout`.

### D-037 Sessions come from a cookie, and each arm remembers separately
- **Decision:** `mf_sid`, validated against `^[A-Za-z0-9_-]{16,64}$`, set by
  `GET /` before any stream opens (EventSource cannot send headers). Runs use
  `<sid>#undefended` / `<sid>#defended`.
- **Reason for the split:** without it the undefended column's poisoned
  `long_term` fact is recalled by the defended column's S2 stage 2, and D2
  appears to fail on a run where it worked.
- **No route accepts a session id from the client.** M2's reviewer found that
  record ids are guessable and an unscoped approve reaches another visitor's
  memory; deriving the session server-side makes that unreachable by
  construction rather than by remembering to pass an argument.

### D-038 Replays record model completions, not traces
- **Decision:** a replay holds what the model said. Retrieval, D1's per-run
  nonce and wrapping, D2's gate and D3's policy all re-execute on every
  replayed run.
- **Reason:** a frozen trace would make replay mode a video of the demo
  rather than the demo — the defense toggles would be dead exactly where §1
  promises the thing still works without an LLM.
- **Exhaustion returns a graceful `end_turn`** rather than raising, so a
  toggle combination the recording never saw still reaches `done`. A short
  run is a much better failure than a stream that dies mid-demo.

### D-039 The SSE event name is the trace event's type
- **Decision:** `event: <type>`, `data:` single-line JSON, `id: <seq>`. §10.3's
  terminal `done` becomes a literal assertion on the wire.
- **Errors terminate the stream:** an exception emits `event: error` carrying
  only the exception's class name, then a synthetic terminal `done` with
  `reason: "error"`. A UI that never receives `done` spins forever, and the
  exception text can quote corpus content straight back to the client.
- **One run per stream.** S2's stage 2 is a second `EventSource`, which is
  what keeps `done` genuinely terminal.

### D-040 The undefended arm ignores the toggles, server-side
- **Decision:** `arm=undefended` forces all three defenses off regardless of
  the query string.
- **Reason:** the same reasoning as D-020. A control arm that can be altered
  from the client is a control arm that can lie.

### D-041 Replays are mock-recorded, pending Vertex quota
> **Superseded by D-057 and D-072.** The recordings are no longer mock-made:
> live runs are served by Gemini (D-057) and every replay in `replays/` was
> recorded from one (D-072). The Claude quota situation below is still
> accurate, and it is why the provider changed. Kept because the reasoning
> about what a mock-recorded table would have implied is the reason the live
> recording mattered.
- **Situation:** `agent-eva` has **zero Claude quota** on Vertex. `global` is
  the only region serving `claude-sonnet-5` for this project and returns
  `Quota exceeded for global_online_prediction_requests_per_base_model`;
  every other region returns 404 for the model. Identity is not the problem —
  the API is enabled and the service account has access.
- **Decision:** `scripts/eval.py --dry-run --record` produced the replays so
  the demo works end to end in replay mode (§1), and `replays/eval.md` opens
  with a block saying plainly that the table is **not** a live eval and why.
- **What this costs:** §10.4's real numbers and §11's "eval table committed"
  are not yet satisfied. Re-running without `--dry-run` once quota is granted
  replaces both the table and the recordings; nothing else changes.
- **Why not hide it:** a table of numbers produced by a model scripted to
  obey every instruction would show 100% attack success and look like a
  finding. It is a property of the harness.

### D-042 Vertex identity: the existing service account, for now
- The Cloud Run service runs as the default compute SA, which holds
  `roles/editor` on `agent-eva` — broader than §7's `roles/aiplatform.user`.
  Left as is for M3 because it is not the blocker (quota is) and narrowing it
  is an M4 hardening item worth doing deliberately.

### D-043 The UI never uses innerHTML
- **Decision:** every value is rendered with `textContent`, pinned by test.
- **Reason:** the page renders chunk previews, memory contents and tool
  arguments — all of which quote a corpus that deliberately contains
  `</user><system>Ignore all prior instructions…`. A single `innerHTML` would
  make a demo about prompt injection ship an XSS.

### M3 review fixes

### D-044 The session id never reaches the trace
- **Bypass:** `run_started.detail` carried `session_id`, and M3 is what put
  the trace on the wire. The cookie is `httponly` precisely so page script
  cannot read it; the app then streamed the same value to page script on
  every run. The reviewer confirmed the value alone is enough: setting
  `mf_sid` to another visitor's id returns 200 on approving their record.
- **Not exploitable today** — one inline script, no external origins, no XSS
  — which is exactly why it was worth fixing before something makes it so.

### D-045 Replay mode degrades; it does not 500
- **Bypass:** a truncated, non-JSON, wrong-typed or `null` recording escaped
  as a parse error before the stream opened: 500, zero SSE frames, and
  `_error_events` — built for this — never ran. §1 makes replay the path that
  works without a model, so it is the one path that cannot fail hard.
- **Fix:** `ReplayClient` validates on load and raises `ReplayMissing`, the
  same error a missing file raises, which the route already turns into a 404.

### D-046 A live client that cannot be constructed falls back
- **Bypass:** `VertexClient.__init__` reads `os.environ["MODEL_AGENT"]`
  eagerly and was constructed outside any `try`, while `FallbackClient` only
  wraps `complete()`. With `MODE=live` and the variables unset, every run
  returned 500 while `/api/config` still advertised `live_available: true`.
- **Why it mattered here specifically:** with no Vertex quota (D-041), that
  is the expected path on this project, not a hypothetical.
- **Fix:** construction failures fall back to the recording, and
  `live_available` is probed rather than inferred from `MODE`.

### Notes carried to M4
- `$TMPDIR/memory-firewall.db` is world-readable on Linux and is shared by
  every process using that tempdir. Safe as deployed (one worker,
  `--max-instances 1`); worth an explicit path under a Cloud Run volume if
  that ever changes.
- A cookie-less `/api/run` mints its own session, so a visitor whose first
  request is a run — rather than `GET /`, which sets the cookie — would get
  two different sessions for the two arms. The UI always loads the page
  first, so this is insurance rather than a live defect.
- §7's guardrails (rate limit, token cap) are M4 and absent. `/api/run` has
  no per-IP cap on concurrent streams today, and each one runs a full
  scenario on the threadpool.

## M4 — guardrails, README, smoke test, final deploy

### D-047 The rate limit reads `X-Forwarded-For` from the right
- **Decision:** `client_key` takes `entries[-1 - TRUSTED_PROXY_HOPS]` and
  parses it with `ipaddress.ip_address`; `TRUSTED_PROXY_HOPS` defaults to 0
  (bare Cloud Run), 1 behind an external load balancer.
- **Options:** `request.client.host` — on Cloud Run that is the Google Front
  End, so every visitor is throttled as one client. Leftmost XFF entry — that
  is whatever the client sent, so an attacker rotates it for unlimited
  requests, or forges a victim's address to get the victim blocked. Rightmost
  minus hops — Google's front end *appends* what it observed, so trust flows
  from the right.
- **The `ipaddress` parse is not cosmetic:** it stops an attacker-chosen
  string becoming a dictionary key on a single-instance service.
- **This is the one guardrail behaviour that cannot be verified locally.**
  Directly against uvicorn nothing appends, so a client-supplied header *is*
  the rightmost entry and is trusted by design. `scripts/smoke.py` asserts it
  against the deployed URL and prints an explicit SKIP against localhost
  rather than asserting something that cannot fail there.
- **How it was actually verified, and the honest limit of the check:** the
  deployed `RATE_LIMIT_PER_MIN=600` is higher than the smoke probe will fire,
  so the check skips by default rather than passing vacuously — an earlier
  version reported a green "rate limit engages" from 40 requests that never
  came close to it. It was verified once by temporarily setting the deployed
  limit to 15, where the forged-header check passes against the real proxy.
  Re-verifying means lowering the limit for one run; the probe auto-sizes when
  the configured limit is 200 or less.

### D-048 A fixed window, replaced wholesale each minute
- **Options:** a per-key sliding-window deque; a fixed window discarded each
  minute.
- **Reason:** the deque needs eviction logic to stay bounded; the fixed window
  is bounded by construction, with a hard cap on distinct keys per window on
  top.
- **Accepted cost:** a burst straddling a minute boundary can briefly achieve
  twice the nominal rate. For a demo guardrail that is the right trade against
  eviction code that has to be correct under a threadpool.

### D-049 A bad limit value falls back to the default, not to "disabled"
- **Decision:** an unparseable or negative `RATE_LIMIT_PER_MIN` resolves to
  600; only an explicit `0` disables the limit.
- **Contrast with D-004**, where an unrecognised `MODE` degrades to `mock`.
  There, degrading means *less* capability. Here, degrading to `0` would mean
  removing a guardrail, so "fail safe" points the other way. The direction of
  safety is a property of the setting, not a house style.
- **Human-set value:** 600/min (≈150 runs), chosen so a room behind one NAT
  does not throttle itself.

### D-050 The token cap is checked before the model call, and ends the run normally
- **Decision:** the check runs at the top of each turn, before
  `client.complete()`, and on trip the loop breaks to the ordinary `done`
  emission with `reason: "token_cap"` and `detail: {"cap", "used"}`.
- **Options:** check after the call (lets a run overspend by a whole turn);
  raise and let the error path terminate the stream.
- **Reason:** §10.3 says a cap "stops a session cleanly". The error path was
  built for a run that *failed*; a capped run did not fail, and the outcome it
  reports — including `attacker_goal_achieved` — stays honest about what
  happened before the stop.

### D-051 Spend is per base session, survives reset, and is unlimited by default
- **Decision:** keyed on `sid.split("#")[0]`, so both arms share one budget;
  `SESSION_TOKEN_CAP` defaults to `0` (disabled); `POST /api/reset` clears
  memory but not spend.
- **Reasons:** keying on the arm-scoped id would silently make the cap twice
  what it says. A cap a visitor can clear with a button is not a cap. And a
  cap that truncates a demo unexpectedly is worse than no cap while there is
  no live spend to protect against.
- **Acknowledged hole:** clearing the cookie buys a fresh budget. That is why
  the IP rate limit exists alongside it — neither is the guardrail on its own.

### D-052 Guardrail state is in-process, which makes `--max-instances 1` load-bearing
- The counter and the budget map are module-level dicts under locks. §7's own
  justification for `--max-instances 1` ("so in-memory sessions stay
  consistent") is the licence, and §12 rules out Redis.
- **Consequence worth stating plainly:** raising `--max-instances` above 1
  silently divides both guardrails by the instance count. The flag is now a
  security control, not just a session-continuity one, and the README says so.

### D-053 Recorded replays now carry real token usage
- **Bug found in planning:** `scripts/eval.py` reads `usage` from `model`
  trace events, and `iter_scenario` never put it there, so all eight committed
  recordings reported zero tokens — a comment in that code claimed to be
  fixing exactly the problem it left in place. A token cap could therefore
  never trip in replay mode.
- **Fix:** `model` events carry the turn's usage, and the recordings were
  refreshed (4,708–6,411 tokens per run).

### D-054 Where the build leaves §11
*(Rewritten after D-057. The original text described the pre-Gemini state —
a mock-recorded table and no live mode — and contradicted D-057/D-058 three
entries later. A decision log that gives two accounts of the same milestone
is worse than one that gives none.)*

- **Met:** the suite passes on `MockClient` with no network and no
  credentials; live mode works (on Gemini); the eval table is committed with
  real 10-runs-per-cell numbers; the README explains the demo in under a
  minute; DECISIONS records the tradeoffs; the deployed URL works from a fresh
  browser on desktop and phone, light and dark.
- **Met with a caveat — "each scenario shows a hijack undefended and a block
  with its primary defense, in live mode and in replay":** true for S1 and S2.
  **Not true for S3 in replay or live**, because Gemini 2.5 Flash declines that
  injection outright (0/10 undefended), so there is no hijack to block. The
  scenario is kept and the result reported, per §10.4 — model-level resistance
  is a finding, not a broken fixture — and S3's D3 block is demonstrated
  deterministically in `mock` mode and asserted in the CI matrix. The README
  says this where a visitor will meet it.
- **Met differently than specified — "eval table committed":** the numbers
  describe Gemini, not Claude (D-057, D-058). §2's provider has no entitlement
  on this project. `LIVE_PROVIDER=claude` reproduces the table against Claude
  the day that changes; nothing else needs to move.

### D-055 The service account was not narrowed
- **Deferred deliberately.** The Cloud Run service still runs as the default
  compute SA with `roles/editor`, broader than §7's `roles/aiplatform.user`.
- **Reason:** with zero quota the service makes no Vertex calls at all, so the
  breadth is entirely unexercised, and re-deploying with a new identity risks
  the milestone's demoable result — a working deploy — for no present gain.
- **This becomes mandatory the moment `MODE=live` is deployed.** It is the
  first item to do when quota lands, before the eval re-run.

### D-056 `--min-instances 1` is an operator action, not a deploy flag
- §7 scopes it to the demo window. Putting it in the committed deploy command
  would bill a warm instance indefinitely, so both commands are in the README
  instead.

### D-057 The live model is Gemini, not Claude (a §2 deviation)
- **Situation:** this project has no Anthropic partner-model entitlement on
  Vertex. Every `anthropic-*` bucket in
  `global_online_prediction_requests_per_base_model` has no effective limit at
  all — Opus 4.1/4.5/4.6/4.7, Sonnet 4.5/4.6, Haiku 4.5, claude-3-7-sonnet,
  claude-3-5-sonnet-v2 — while Google's own buckets are provisioned at 600.
  That is a missing entitlement, not a rate limit, and not resolvable on this
  project's timescale.
- **Verified before porting**, per instruction: a real `generateContent` call
  returned 200 for `gemini-2.5-pro`, `gemini-2.5-flash` and
  `gemini-2.5-flash-lite`. Gemini 3.x is **not** available here, so the ids
  were probed rather than assumed. A control request to the Anthropic
  publisher through the identical URL shape returned the 429 quota error,
  which is what makes this a provider entitlement difference rather than a
  client bug.
- **Decision:** `clients.GeminiClient` implements the existing `ClaudeClient`
  protocol exactly — same `complete(system, messages, tools, max_tokens)`,
  same `Completion` and `ToolCall` shapes — and translates both ways:
  Anthropic block messages to Gemini `contents`/`parts`, our tool schemas to
  `FunctionDeclaration`s, and `functionCall` responses back to `ToolCall`.
  `VertexClient` is untouched and still tested, and the provider is chosen by
  `LIVE_PROVIDER`, never by editing code. The default stays `claude`, so the
  spec'd path is one env var away.
- **Two translation details that would have failed quietly:**
  Gemini returns `finish_reason: STOP` even when it asked for a function call,
  so the calls decide the stop reason — reading `finish_reason` literally
  would end every run after one turn. And Gemini returns no call id, while the
  agent loop pairs `tool_use` with `tool_result` by one, so ids are
  synthesised and asserted unique.
- **New dependency:** `google-genai==2.25.0`, human-approved under §12, pinned
  like the rest and in the runtime manifest because the deployed service needs
  it.

### D-058 What a Gemini eval does and does not claim
- **The eval measures whether the model under test follows an instruction
  hidden in retrieved content. Run against Gemini, it describes Gemini.**
  Claude may behave differently, better or worse; nothing in the committed
  table is evidence either way, and D1's measured efficacy is a claim about
  the model that was actually tested.
- This is stated in the **header** of `replays/eval.md` and in a top-level
  README section, not in a footnote — a reader who skims must not come away
  believing these are Claude numbers (§10.4).
- **Unaffected:** D2 and D3 are deterministic code, and all 24 scenarios in
  the CI matrix run on `MockClient`. No test claim depends on which provider
  serves live traffic, so the enforcement results stand unchanged.
- Replays are now recorded from real Gemini runs rather than synthesised from
  the mock, which is what §11 actually asks of the replay path.

### D-059 Eval results at n=3 did not replicate, and the table says so
- **What happened:** two consecutive 3-run evals of the same suite against the
  same model disagreed materially. S1 undefended moved 3/3 → 2/3, S1 with D1
  moved 1/3 → 2/3, and S3 undefended moved 0/3 → 2/3. On the first table I
  reported "D1 cut the attack rate from 100% to 33%"; the second run shows
  2/3 against 2/3, so that claim did not survive its own re-run.
- **Decision:** the eval runs 10 per cell, and `replays/eval.md` carries a
  sample-size caveat in its header stating how much one run moves a rate and
  that a one- or two-run gap between arms is inside the noise.
- **At n=10 the picture is stable and the direction is consistent:** S1 5/10
  undefended against 2/10 with D1; S2 9/10 → 6/10 at stage 1 and 3/10 → 1/10
  at stage 2. Spotlighting lowers the rate on every scenario where the model
  was susceptible at all — which is a directional claim the n=3 tables could
  not support, and is still not a precise one.
- **S3 across three evals:** 0/3, 2/3, 0/10 undefended. The middle result is
  why the caveat exists; on the larger sample the model consistently refuses
  to un-isolate a contained host on the strength of a pasted advisory.
- **Why this matters more here than in a normal benchmark:** the whole point
  of §10's principle is that D1 is *probabilistic*. A table that looks precise
  invites exactly the over-reading the principle warns about, and a defense
  whose measured effect swings by 33 points between identical runs cannot be
  summarised by a single number without saying so.
- **Unchanged:** D2 and D3 are deterministic and are proven in CI. None of
  this touches them.

### D-060 The M4 review, and what it caught
Run after the human approved the milestone rather than before it, so these
landed as a follow-up commit. Findings worth recording beyond the fixes:

- **A full rate-limit key map denied new clients while the keys already in it
  kept their allowance.** An attacker with one IPv6 /64 could fill it with
  addresses that are each under the per-key limit — never throttled — and
  close `/api/*` to every new visitor. Overflow keys now share a bucket:
  bounded by construction, degrading to sharing rather than exclusion.
  Failing open was not an option; that hands them unlimited requests.
- **The concurrent-run slot leaked on any error between acquiring it and
  starting the stream.** Four transient database errors wedged `/api/run` at
  429 for the life of the process, and `--max-instances 1` means nothing
  restarts it. A guardrail that becomes the outage is worse than no guardrail.
- **`client_key` read only the first `X-Forwarded-For` header.** Latent behind
  Cloud Run, which appends in place — but it is the single assumption
  D-047's design rests on, and the smoke test cannot detect it because it
  sends one header. Now joins every occurrence.
- **Every degenerate Gemini response looked like the model declining.** A
  safety filter, a malformed function call or an empty candidate all returned
  `end_turn` with no tool calls, which `scripts/eval.py` counts as the model
  resisting the injection. That would have quietly inflated the "declined"
  numbers the eval exists to report honestly. Those reasons now map to
  `no_response`, the loop records it as a distinct outcome, and the eval
  counts and footnotes them separately.
- **The session token cap undercounted Gemini spend**, because thinking tokens
  are billed and are not in `candidates_token_count` — an undercount in the
  unsafe direction for the only provider that spends anything.
- **No timeout was configured on live Gemini calls**, so §7's "errors or times
  out" fallback had no timeout half for the provider actually serving traffic.

### D-061 Renamed to Project Injection Firewall
- **Decision:** the project is *Project Injection Firewall*. The rename covers
  everything a reader meets — README, the page title and heading, the spec
  heading, the subagent briefs — and stops there.
- **Why the old name was wrong:** "Memory Firewall" named D2, one defense of
  three. S1 is a retrieval hijack and S3 is privileged-skill abuse; neither
  touches memory. "Firewall" also imported a perimeter metaphor that does not
  fit a context window, where there is no inside and outside — only text of
  different provenance sitting in the same prompt. The new name qualifies the
  *threat* rather than a single countermeasure, so all three scenarios sit
  under it and a fourth defense would not outdate it.
- **What deliberately did not change:** the Cloud Run service id
  (`memory-firewall`), the live URL, and the on-disk database filename.
  Renaming the service issues a new URL and kills every link already shared —
  a cost paid by other people, for a tidiness only we would notice.
- **DECISIONS entries keep the name they were written under.** A decision log
  is a record of what was decided when; rewriting its history to match a later
  name would make it a worse record for no gain.

### D-062 D1 is "untrusted tagging"; the technique is still spotlighting
- **Decision:** the defense is called *untrusted tagging* in the UI, the
  README and the trace (`defense.name == "untrusted_tagging"`,
  `action == "tagged"`). CLAUDE.md §5 and this log keep *spotlighting*
  attached to it as the name the technique has in the literature.
- **Why:** "spotlighting" collided with the demo's own screen. The UI puts a
  red border and an "injection source" pill on the injected chunk — that is
  the spotlight a viewer sees, and it is not this defense. Two different
  spotlights on one screen, and the visible one was the wrong one. The new
  label also reads in parallel with "memory gate" and "skill policy", where
  D1 was the only opaque one of the three.
- **The identifier moved too**, unlike the service id in D-061. The trace is
  read by the UI and the scenario matrix, both in this repo, and nothing
  outside it consumes the format — so the consistency was worth more than the
  stability. Nothing recorded in `replays/` carries defense names; those hold
  model completions only (D-038), so no artefact had to be regenerated.
- **Prior art is preserved deliberately.** A demo that renames a known
  technique into its own private vocabulary makes itself harder to place, so
  the literature name stays one line away in the spec.

### D-063 The verdict says why, not only what
- **Problem:** the outcome block reported "Attacker goal not achieved" with no
  explanation. In the undefended column — where nothing is enabled — that is
  routine in live mode, because the model sometimes declines on its own (S3,
  0/10). A viewer saw two columns that both looked fine and could not tell
  whether a defense worked, the model refused, or the demo was broken.
- **Decision:** three states, not two. Red: the attack landed. Green: a
  defense refused the action, named. **Amber: nothing stopped it** — no
  defense fired, and the text says the model declined by itself, that this is
  a fact about the model rather than a result from this demo, and that it may
  go the other way on the next run.
- **Why amber matters:** showing a model-level refusal in the same green as a
  block claims a win the enforcement layer did not earn. It is the same
  conflation the scenario matrix avoids with `not_achieved_harness_limit`
  (D-026) and the eval avoids by counting `no_response` separately (D-060),
  now applied where a viewer actually looks.
- **Also:** consequential actions are listed in full and read-only calls are
  counted. A live run searches repeatedly, and listing nine `search_logs`
  lines buried the one line saying what the agent did to the world.

### D-064 The corpus database is verified, not assumed
- **Found by running the demo**, not by review: every run started failing with
  `no such table: memory`. A test that unset `DB_PATH` had called
  `reset_db()`, which unlinked the running dev server's database; the "already
  built" flag stayed true, so every later connection opened a fresh empty file.
- **Decision:** `get_db()` checks that the expected tables exist and rebuilds
  if they do not, instead of trusting a process-local flag.
- **Why it matters beyond the dev loop:** the deployed service keeps its
  database in a temp directory. A cleared `/tmp` does exactly what that test
  did, and the symptom — every run dying — looks like the application is
  broken rather than the database being gone.

### D-065 A demo case with no attacker in it
- **Decision:** S4 shows the agent doing the right thing — closing an alert
  raised by the authorised scanner, on instructions from the alert's own
  runbook text — and D3 refusing it.
- **Why the demo needed it:** every other case was "the agent should have
  refused", so the demo only ever showed the defenses being right. The first
  question a security reviewer asks is what a control breaks, and the answer
  was sitting unmeasured in the corpus: **25 of 26 alerts retrieve at least
  one attacker-controllable chunk.** D3 as implemented is therefore not "block
  privileged actions when under attack" — it is "block privileged actions".
  (First measured as 24 of 24; adding S4's and S5's alerts moved it. The only
  alert with a clean context is S5's, because its injection sits in a
  mislabelled field — so the one case D3 ignores is the one that gets through.) An agent with D3 on can never close an
  alert or return a host to the network on its own.
- **The instruction to act comes from trusted content** (the alert summary,
  written by our collector) rather than from a ticket comment. That sharpens
  it: D3 does not care where the instruction came from, only that untrusted
  text is present somewhere in context.
- **Scoring:** a `legitimate` scenario reports `intended_action_taken` and
  never an attacker goal, and the UI colours a block **red** for it. Showing
  a refused legitimate action in the same green as a blocked attack would be
  the demo lying in its own favour, which is the failure D-063 fixed one
  layer up.

### D-066 A demo case the defenses cannot see, kept unfixed on purpose
- **Decision:** S5 puts the S1 payload inside a log's `message` field, which
  `trust_map.yaml` classifies as internal because our collector writes it —
  while the collector interpolates the client-controlled request line into
  that same sentence. The attack succeeds in every column, `all` included.
- **Not a bypass:** no defense was evaded, because none engaged. D1 does not
  wrap the chunk, `untrusted_in_context` never flips, D2 has no untrusted
  provenance, D3 never arms. One boolean gates all three.
- **Kept unfixed** because it is the only case in the suite that shows what
  the defenses cannot see, and because it is the shape review already found
  twice independently (D-029, the ticket title). The fixture states the fix —
  classify the field, or stop the collector signing content it copied — so a
  reader is not left thinking the demo is broken.

### D-067 S3 left the picker, not the suite
- **Decision:** the UI offers S1, S2, S4, S5. S3 remains a scenario fixture,
  a matrix row and a red-team target.
- **Reason:** S3 is the same shape as S1 — untrusted text naming a tool — and
  the live model declines it 0/10, so it occupied a demo slot with a run that
  shows an agent searching and stopping. Its D3 story is now told by S4, from
  the more useful direction.

### D-068 The corpus is checked for integrity
- **Found by colliding with it:** two alerts shared the id `ALR-1041`,
  because a new scenario reused an id the red-teamer had taken. Retrieval
  silently merged both records, and a scenario pulled in a ticket belonging
  to someone else's fixture. Nothing failed — the demo just showed the wrong
  evidence, which is the worst possible defect in a project about knowing
  where content came from.
- **Decision:** `tests/test_data_integrity.py` asserts ids are unique within
  and across the data files, that every `related_logs` / `related_tickets`
  reference resolves, and that every scenario points at an alert that exists.

### D-069 The defenses moved into their own module
- **Decision:** `defenses.py` holds D1's tagging and stripping, D2's tier
  decision and D3's policy as pure functions. `app.py` imports them under its
  old private names so nothing else moved; `mcp_server.py` imports them
  directly.
- **Reason:** the MCP server has to enforce the same rules, and a second copy
  of a defense is a second thing to get wrong. A test asserts the two surfaces
  hold the *same function objects*, not merely equivalent code — and it earned
  its keep immediately, catching a `git checkout` that silently restored
  `app.py`'s local copies while `defenses.py` still existed.
- **Alert-centric retrieval moved to `store.py` for the same reason.** It is
  the step that puts an injection in front of a model: the alert names related
  records, those get read, and one of their fields was written by whoever
  generated the traffic. A keyword search does not reproduce it, so without
  sharing this the MCP server could not run the scenarios at all.

### D-070 The trust policy as an MCP server
- **Decision:** `mcp_server.py` exposes the corpus, the five skills and the
  three defenses over MCP stdio, with `MF_DEFENSES` selecting which are on.
- **Why this shape is the point:** in the web demo we own the agent, so a
  sceptic can say the defenses only work because we wrote both sides. Over
  MCP the client is someone else's model and the enforcement is still on this
  side of the boundary. A model can be talked out of an instruction; it cannot
  be talked out of a tool that refuses to execute. D2 and D3 are server-side
  decisions, and that is exactly what makes them worth more than prompt text.
- **`firewall_status` is readable by the model on purpose.** Knowing that
  untrusted content is in context gains an attacker nothing — the refusal
  already said so — and a model that can see the boundary can report the
  injection instead of trying to route around it.
- **Tested over the wire, not just in-process:** a test starts the server as a
  subprocess, performs the MCP handshake, lists tools and asserts that a
  `close_alert` call comes back refused. A server that imports cleanly and
  dies on connect is the failure a client meets first.
- **New dependency:** `mcp==2.2.0`, human-approved, pinned. Note FastMCP is
  `MCPServer` in 2.x; v1 examples do not run against it.

### D-071 Reverted to Memory Firewall
- **Decision:** the project is *Memory Firewall* again. Reverts D-061 across
  everything a reader meets — README, page title and heading, spec heading,
  postmortem title, subagent briefs.
- **Unchanged:** D1 is still *untrusted tagging* (D-062). That was a separate
  decision about a defense's label, made for a separate reason — the old name
  collided with the UI's own red-border highlight — and reverting the project
  name does not disturb it.
- **D-061 stays in this log.** A decision that was made, applied and then
  reversed is a record of what happened; deleting it would leave the entries
  around it referring to a name that appears nowhere.

### D-072 The recorded replay is chosen for whether the defenses act, not for the outcome
- **Problem:** S4 and S5 had no recordings, and the existing rule — keep the
  run matching each cell's *modal* outcome, stated in `record_representative`'s
  docstring rather than here — can select a run in which
  the model never asked for the privileged tool. A replay holds what the model
  said; D1, D2 and D3 re-execute on playback. So that run renders a defended
  column where nothing was blocked — not because a defense failed but because
  there was nothing to block, which is the amber "nothing stopped it" verdict
  and the reason S3 left the picker.
- **Decision:** prefer runs in which the model *complied with* the scenario's
  target call — the tool **and every argument the fixture names** — and, for a
  two-stage scenario, carried through to the second stage; break the tie on the
  modal outcome, as before. `choose_run` in `scripts/eval.py`.
- **Compliance is measured on requested calls, not on the outcome.** The
  outcome records calls that were *performed* (an M1 fix: a blocked call must
  not score as the attacker winning), so in the defended arm a model that
  complied and was stopped is indistinguishable from one that refused. Those
  are opposite events and the selection has to tell them apart.
- **The arguments matter, found the hard way.** Matching on the tool name alone
  selected an S5 run that closed the alert as `resolved` on the model's own
  reasoning rather than the `benign` the injection asked for — a recording of a
  scenario about a working attack, with no attack in it.
- **Why this is not cherry-picking the flattering run.** The criterion is
  whether the enforcement layer was exercised, not whether it succeeded. In the
  defended arm it selects *against* the run that would look best for D1 — a run
  where the model refused on its own — and for one where D1 failed to persuade
  it and the deterministic gate had to catch it. Every file now carries a
  `selection` key naming the rule and the cell's true rate, and `eval.md` states
  that the recordings are biased towards runs where something visibly happens
  and that the rate column, not the replay, is the measurement.
- **Two alignment bugs fixed on the way.** `run_cell` appended each stage's
  flag as it happened but its trace only at the end, so a two-stage run failing
  in stage 2 desynchronised `stage1` from `traces` — and every selection rule
  indexes across the two. Flags, tokens and trace are now committed as a unit.
  Separately, the table scored `attacker_goal_achieved` for every scenario,
  which for S4 (`kind: legitimate`, no attacker) is False in every run: a column
  of zeros reading as "the attack never worked" for a scenario that has no
  attack. S4 now counts the correct action being taken, labelled in the table.

### D-073 The demo counts 1–4, and says which mode it is actually in
Four UI corrections, all of them things a viewer would have had to ask about.

- **The picker now reads Case 1 – Case 4.** The fixture ids run S1, S2, S4, S5
  because S3 left the picker (D-067) while remaining a real, tested scenario
  with five red-team variants. Renumbering the fixtures would collide with it,
  or delete D3's primary matrix coverage to free the number. A display label
  (`UI_LABELS`, used by `/api/scenarios` and the `run_started` title) costs
  nothing and the ids keep keying the replays, the matrix and the eval table.
- **The mode badge described the wrong thing.** It printed `resolve_mode()` —
  the service's default for a run that names no mode — and never updated when
  the dropdown changed. On a `MODE=live` deployment it therefore read "mode:
  live" permanently, next to a dropdown set to something else. It now names
  what the *next run* will use, in words: "recorded real run", "scripted
  model", "calling the model now".
- **The page opens in `replay`, and so does autoplay.** Previously autoplay
  forced `mock`, chosen when the recordings were incomplete. They are complete
  now (D-072), and a recorded real run is as repeatable as a mock while being
  a recording of a model that actually did this. Mock remains the fallback.
- **`replay_available` probed S1 only.** It advertised `true` while S4 and S5
  had no recordings and 404'd the moment they were picked. A capability flag
  has to cover the surface it claims, so it now checks every scenario, arm and
  stage the picker can ask for.

Measured after the change: autoplay is **65 seconds**, an even 15.6s per case.
The earlier "about 90 seconds" was an estimate, and a first attempt to measure
it read three minutes — an artefact of a hidden browser tab, where timers are
throttled. Worth knowing before recording, not after.

### D-074 Renamed to Prompt Injection Firewall
- **Decision:** the project is *Prompt Injection Firewall*. This is the third
  name (D-061 renamed it to Project Injection Firewall, D-071 reverted it to
  Memory Firewall) and the churn is worth admitting rather than hiding.
- **Why this one holds up:** "Memory Firewall" names D2 — one defense of three.
  The demo's subject is prompt injection against a retrieval-and-memory agent,
  and two of the four cases (S4, S5) have nothing to do with memory at all.
  The name a reader meets should describe the whole, not its middle third.
- **What did not change, deliberately:** the Cloud Run service id
  (`memory-firewall`), the live URL it determines, the GitHub repository name,
  and the on-disk database path. A Cloud Run service cannot be renamed — you
  deploy a new one and the old URL dies — and that URL is a submitted
  deliverable cited from the README, the run sheet and a test. Breaking a live
  link to make an identifier match a display name is a bad trade, and the
  README says so where a reader would otherwise wonder.
- **D-061 and D-071 keep the old name in their text.** They are the record of
  what was decided at the time; rewriting them would leave the entries around
  them referring to a name that appears nowhere.

### D-075 The spend cap bills model calls, not replays
- **Defect:** `SESSION_TOKEN_CAP` charged every run, including replays. A
  replay makes no API call, and one hands-free pass of the four demo cases
  reports ~107,000 tokens against the deployed cap of 150,000 — so a visitor
  got a single pass and then met "Token budget reached" on every subsequent
  run. `/api/reset` clears memory and deliberately not spend (D-051), so the
  only way out was a new cookie. Found by using the deployed service, not by
  the 530 tests.
- **Decision:** the cap applies to clients that reach a model. `bills_tokens()`
  excludes `replay` and `mock`. Usage is still measured and still reported in
  the trace — D-053's reason for recording real numbers was fidelity in the
  trace, which is untouched.
- **Why this is the right direction:** the cap exists to bound spend on a
  public URL (§7). A path that cannot spend anything is a path it has no
  business limiting, and limiting it turned the guardrail into the outage —
  the same shape as the run-slot leak in D-060.
- **Tests:** the two existing cap tests drove the mechanism through `mock`, so
  they now bill explicitly and keep testing the cap rather than the exclusion.
  A new test runs three full passes in one session and asserts no run ends in
  `token_cap`; another pins which clients bill.

### D-076 Known-open defects at hand-off
Two findings from the post-build review are recorded and **not fixed**. Both
are in `mcp_server.py`, neither affects the hosted service, and both are
written up in POSTMORTEM §1 rather than quietly carried.

- **The MCP server discards D2's fail-closed signal.** It filters untrusted
  provenance to ids that resolve to a chunk, which undoes `chunk_trust`'s
  deliberate fail-closed on unresolvable ids (D-012). The same provenance
  quarantines on the web surface and lands in `long_term` over MCP. The fix is
  to lift the context tracker into `defenses.py` so both surfaces share it,
  and to replace the identity assertion with a differential test that drives
  both and compares outcomes.
- **`MF_DEFENSES` fails open.** An unrecognised value yields all three
  defenses off, contradicting the rule stated for `RATE_LIMIT_PER_MIN`
  (D-049). The fix is to fall back to the default set and to test a typo.

Recorded rather than fixed because the hosted demo is the deliverable and
neither is reachable from it. Shipping with a known defect written down is a
defensible position; shipping with one not written down is not.

### D-077 The picker carries two cases; S4 and S5 leave the demo
- **Decision:** `UI_SCENARIOS` is `("S1", "S2")`. Case 1 is the retrieval
  hijack, Case 2 the memory poisoning. S4 and S5 join S3 (D-067) as scenarios
  that remain in the suite, the matrix, the eval and the recordings without
  appearing on screen.
- **Why:** both ended in a red verdict on the defended side, and red reads as
  failure. S4's refusal is the *cost* of D3 and S5's silence is the blind
  spot — findings, not defeats — and on screen they raised more questions than
  they answered. A `watch_for` line was added to every case first, saying "this
  is the cost, not a failure" and "this is the blind spot, not a bug", and the
  judgement after seeing it was that two cases which need a paragraph of
  framing to read correctly are better argued in prose than demonstrated.
- **What is lost, stated plainly:** the demo no longer shows what the defenses
  cost or where they go blind. That was the strongest answer to "what does this
  break?", and it now lives only in POSTMORTEM, the matrix notes and the
  rationale. A viewer who only runs the demo sees defenses winning twice.
- **What is kept:** `s4_*.json` and `s5_*.json` recordings, the fixtures, their
  matrix rows and the 25-of-26 measurement. Nothing was deleted, so restoring
  them to the picker is a one-line change.
- **`watch_for` stays** for the two remaining cases. It was built for S4 and S5
  and turned out to earn its place on S1 and S2 as well.
