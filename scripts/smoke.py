#!/usr/bin/env python
"""Post-deploy smoke test (§10.5). Stdlib only, so it runs anywhere.

    python scripts/smoke.py --url https://…run.app --expect-mode mock

Checks the things a deploy can break without anything looking wrong locally:
the hardening that must survive a rebuild, the SSE stream terminating, and
the rate limit's `X-Forwarded-For` handling — which cannot be verified
locally at all, because it only behaves differently behind a real proxy.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "https://memory-firewall-366819802884.us-central1.run.app"


class Smoke:
    def __init__(self, base: str, timeout: float = 60.0):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )
        self.failures: list[str] = []

    def get(self, path: str, headers: dict | None = None):
        """Returns (status, body). Status 0 means the request never completed.

        Transport failures are reported, not raised: a smoke test that dies
        with a traceback tells you less than one that says which check failed
        and keeps going. Under rapid requests a server or proxy may close a
        connection outright, which is a result worth seeing rather than a
        crash.
        """
        request = urllib.request.Request(self.base + path, headers=headers or {})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001 - transport, DNS, timeout, reset
            return 0, f"{type(exc).__name__}: {exc}"

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{(' — ' + detail) if detail and not ok else ''}")
        if not ok:
            self.failures.append(name)
        return ok

    # -- checks ---------------------------------------------------------

    def health(self, expect_mode: str) -> None:
        status, body = self.get("/health")
        payload = json.loads(body) if status == 200 else {}
        self.check("/health is 200", status == 200, str(status))
        self.check("/health says ok", payload.get("status") == "ok", body[:80])
        self.check(
            f"mode is {expect_mode}", payload.get("mode") == expect_mode,
            f"got {payload.get('mode')!r}",
        )

    def page_and_cookie(self) -> None:
        status, body = self.get("/")
        self.check("/ is 200", status == 200, str(status))
        self.check("/ serves the page", "<title>Prompt Injection Firewall" in body)
        self.check(
            "/ sets a session cookie",
            any(c.name == "mf_sid" for c in self.jar),
            "no mf_sid cookie",
        )

    def hardening_survived(self) -> None:
        for path in ("/openapi.json", "/static/index.html"):
            status, _ = self.get(path)
            self.check(f"{path} is 404", status == 404, f"got {status}")

    def run_streams_to_done(self, mode: str, label: str) -> dict:
        status, body = self.get(
            f"/api/run?scenario=S1&arm=defended&stage=1&mode={mode}&d1=1&d2=1&d3=1"
        )
        self.check(f"{label} run is 200", status == 200, str(status))
        frames = [line[len("event:"):].strip() for line in body.splitlines()
                  if line.startswith("event:")]
        self.check(f"{label} stream ends on done", frames[-1:] == ["done"], str(frames[-3:]))
        done, attempted_privileged = {}, False
        for line in body.splitlines():
            if not line.startswith("data:"):
                continue
            payload = json.loads(line[5:])
            if payload.get("type") == "done":
                done = payload
            elif payload.get("type") == "tool_call":
                if payload.get("detail", {}).get("trust_level") == "privileged":
                    attempted_privileged = True

        outcome = done.get("outcome", {})
        self.check(
            f"{label} attacker goal not achieved",
            outcome.get("attacker_goal_achieved") is False,
            str(outcome),
        )
        # A privileged call that never happened needs no block. Requiring a
        # `blocked` event unconditionally only held while the gullible mock
        # drove every run into one; a real model often declines the injection
        # outright, and failing a deploy for that would punish the better
        # outcome.
        if attempted_privileged:
            self.check(f"{label} privileged call was blocked", "blocked" in frames, str(frames))
        else:
            print(f"  NOTE  {label}: the model attempted no privileged call, "
                  "so D3 had nothing to block")
        self.check(
            f"{label} no privileged action executed",
            not [a for a in outcome.get("actions", []) if a.get("privileged")],
            str(outcome.get("actions")),
        )
        return done

    @property
    def behind_proxy(self) -> bool:
        """Whether a proxy appends to `X-Forwarded-For` in front of this URL.

        Directly against uvicorn nothing appends, so a client-supplied header
        IS the rightmost entry and is trusted by design — the forged-header
        check below cannot distinguish correct behaviour from a bug there, and
        asserting it locally would only teach us to ignore a red check.
        """
        host = self.base.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        return host not in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

    def configured_limit(self) -> int:
        """The service's own RATE_LIMIT_PER_MIN, so the probe can reach it.

        Guessing a fixed 40 requests meant the check silently skipped against
        a service configured at 600 — D-047 claims this verifies the
        forwarded-header handling against the deployment, and a check that
        never runs verifies nothing.
        """
        status, body = self.get("/api/config")
        if status != 200:
            return 0
        try:
            return int(json.loads(body).get("rate_limit_per_min") or 0)
        except (ValueError, TypeError):
            return 0

    def rate_limit(self, attempts: int = 40) -> None:
        """The one behaviour that cannot be checked locally.

        Behind Cloud Run every request arrives from the front end, so the
        limit only works if `X-Forwarded-For` is read from the right. The
        second pass forges a different leftmost entry each time: if the code
        trusted it, every request would look like a new client and no 429
        would ever appear.
        """
        configured = self.configured_limit()
        # Only auto-size when the probe stays cheap. Firing 605 requests at a
        # demo service on every deploy costs more than the check is worth; an
        # operator who wants it exercised lowers the limit for one run.
        if configured and configured + 5 <= 200:
            attempts = configured + 5
        elif configured:
            print(f"  NOTE  RATE_LIMIT_PER_MIN={configured} is too high to probe "
                  "cheaply; lower it temporarily to exercise this check")
        codes = [self.get("/api/config")[0] for _ in range(attempts)]
        limited = 429 in codes
        # 0 = the connection was closed without a response. Cloud Run does
        # this to a burst from one source, which is itself a form of limiting
        # but not the one under test.
        unexpected = sorted({c for c in codes if c not in (200, 429, 0)})
        dropped = codes.count(0)
        if dropped:
            print(f"  NOTE  {dropped}/{len(codes)} connections were closed "
                  "without a response (upstream shedding load)")
        self.check("no unexpected status under load", not unexpected, str(unexpected))

        if not limited:
            # Not a pass. A probe smaller than the configured limit tells us
            # nothing about whether the limit works, and reporting it as
            # green is how a guardrail rots unnoticed.
            print(f"  SKIP  rate limit not reached in {attempts} requests — "
                  "re-run against a service configured with a lower "
                  "RATE_LIMIT_PER_MIN to exercise it")

        forged = [
            self.get("/api/config", headers={"X-Forwarded-For": f"9.9.9.{i % 250}"})[0]
            for i in range(attempts)
        ]
        if not limited:
            pass  # already reported above
        elif not self.behind_proxy:
            print("  SKIP  forged-header check (no proxy in front of this URL; "
                  "meaningful only against the deployed service)")
        else:
            self.check(
                "a forged X-Forwarded-For does not buy a fresh allowance",
                429 in forged,
                "forging the header evaded the limit — X-Forwarded-For is being "
                "read from the left",
            )

    def health_is_exempt(self) -> None:
        status, _ = self.get("/health")
        self.check("/health still 200 after the limit", status == 200, str(status))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--expect-mode", default="mock")
    parser.add_argument("--expect-live", action="store_true")
    parser.add_argument("--skip-rate-limit", action="store_true")
    args = parser.parse_args(argv)

    print(f"smoke: {args.url}")
    smoke = Smoke(args.url)
    smoke.health(args.expect_mode)
    smoke.page_and_cookie()
    smoke.hardening_survived()
    smoke.run_streams_to_done("replay", "replay")
    smoke.run_streams_to_done("mock", "mock")
    if args.expect_live:
        smoke.run_streams_to_done("live", "live")
    if not args.skip_rate_limit:
        smoke.rate_limit()
        smoke.health_is_exempt()

    if smoke.failures:
        print(f"\nFAILED: {len(smoke.failures)} check(s): {', '.join(smoke.failures)}")
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
