# waf_evasion

Adaptive WAF detection and evasion for authorized security testing.

Part of the Orcha family. **Extracts** the WAF handling that already exists in
`acscan` (device profiling, request polymorphism, cache busting, WAF-aware rate
calibration) and closes the loop those pieces leave open.

## The problem

The family can tell you it got blocked, and it can mutate requests — but nothing
connects the two.

```
blocked?  ──yes──>  pause          (detection, passive)
                      │
request   ───────────┘              (evasion, blind: fires the same way
                                     whether or not a WAF exists)
```

So a WAF-fronted target and an unexploitable one look identical in the output.
For a hunter that is worse than a clean result, because a blocked scan is
indistinguishable from a target with nothing to find.

## The loop

```
   ┌──────────────────────────────────────────────┐
   │                                              │
   ▼                                              │
classify(response) ──> strategy(WAF) ──> adapt(next request)
   │                     │
   │                     └──> record(blocked)  ──┘
   ▼
unknown ──> conservative defaults, retry slower
```

A classifier that does not recognise a fingerprint returns `unknown` with low
confidence. It never guesses and presents the guess as fact — that pattern is
what produced the gRPC false positive in `infra_killer`, where any non-`UNIMPLEMENTED`
reply became a MEDIUM "reflection enabled" on every WAF-fronted host.

## Status

**Phase 1a landed: the extraction.** `is_waf_blocked`, the device-profile
engine, request polymorphism, the request-mutation entry point and WAF-aware
rate calibration were lifted out of `acscan` verbatim — every moved file is
byte-identical to its source, so `diff` against the acscan path is empty.

No new capability yet, and `acscan` is untouched: nothing imports from here
yet. That wiring is Phase 1b and is blocked on packaging, not on code. See
[ARCHITECTURE.md](ARCHITECTURE.md) for what moved, what deliberately did not,
the three design questions and how they were decided, and four defects found
while testing that are recorded rather than fixed.

See [HANDOFF.md](HANDOFF.md) before starting — it records the mistakes from the
session that built the sibling repos, several of which are easy to repeat.

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Scope

Authorized testing only. This package mutates outbound requests to reach a
target the operator is permitted to test. It has no use against systems you are
not authorized to assess, and that is not what it is for.