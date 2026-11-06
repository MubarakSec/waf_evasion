# waf_evasion

Adaptive WAF detection and evasion for authorized security testing.

Part of the Orcha family. **Extracts** the WAF handling that already exists in
`acscan` (device profiling, request polymorphism, cache busting, WAF-aware rate
calibration) and closes the loop those pieces leave open.

## The problem

The family can detect blocking responses and mutate requests. This package
provides shared detection and classification to help distinguish blocked
coverage from a clean result.

Without explicit coverage reporting, a WAF-fronted target can be mistaken for a
target with nothing to find. Integrations must surface blocking evidence rather
than treating the absence of findings as proof of clean coverage.

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

The extracted library includes WAF detection, classification, response
assessment, request mutation and rate calibration. acscan imports its detection,
assessment, request mutation and rate calibration components. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the extraction history and design
decisions; its phase-status notes describe the earlier extraction snapshot.

See [HANDOFF.md](HANDOFF.md) before starting — it records the mistakes from the
session that built the sibling repos, several of which are easy to repeat.

## Install

Use the Orcha root environment and installation workflow; root-managed
dependency resolution is still being unified. See the root
`docs/MONOREPO_UNIFICATION.md` for the current work.

## Scope

Authorized testing only. This package mutates outbound requests to reach a
target the operator is permitted to test. It has no use against systems you are
not authorized to assess, and that is not what it is for.
