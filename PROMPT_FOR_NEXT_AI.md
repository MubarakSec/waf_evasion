You are continuing work on `waf_evasion`, a new package in the Orcha family at
/home/mobarkm919/github/Orcha. I built the skeleton and committed it; you are
starting the actual implementation.

## Read first, before writing any code

    cat /home/mobarkm919/github/Orcha/waf_evasion/HANDOFF.md

That file is not background reading, it is a list of ways this family has
already been bitten. It records five specific mistakes from the session that
fixed the sibling repos. Two of them I made twice. Do not repeat them.

Also read:
    cat /home/mobarkm919/github/Orcha/waf_evasion/README.md
    cat /home/mobarkm919/github/Orcha/docs/TOOL_BOUNDARIES.md   # section on waf_evasion

## What we are building

A shared, adaptive WAF detection and evasion package for authorized security
testing. It is part of a 6-repo family (umbrella repo with submodules) used for
bug bounty hunting.

The family already has four pieces of WAF handling, all inside acscan:
  - `acscan/engine/pipeline/executor/waf.py`   `is_waf_blocked()` -> bool for 429 / 403-HTML / 5xx
  - `acscan/engine/waf_mapper.py`              WAF-aware rate calibration
  - `acscan/engine/replay/polymorphic.py`       request polymorphism
  - `acscan/engine/replay/evasion.py`           device profile, IP spoof, cache bust, header shuffle, timing

They do not compose. `is_waf_blocked()` returns a bool and the executor pauses.
`apply_evasion()` fires pre-emptively and identically whether or not a WAF
exists. Nothing connects a block to a change in the next request.

Consequence, and this is the thing that actually matters: a WAF-fronted target
and an unexploitable one produce indistinguishable output. For a bounty hunter
a blocked scan looks exactly like a target with nothing to find.

## The loop we want

    request -> blocked? -> classify(response) -> strategy(waf) -> adapt(next request)
                  |                |                    |
                  no               unknown               +-> record(blocked)
                                   |                     +-> conservative defaults
                                   v
                            conservative, retry slower

## The mandate: extract, do not rewrite

Move and generalise the four acscan pieces into this repo. acscan must then
import from here and delete its own copies. One implementation only.

Sequence matters, and getting it wrong makes regressions unreproducible:

  Phase 1. Land the extraction with acscan importing from `waf_evasion` and its
           full suite green. No new capability. Do not begin Phase 2 until this
           is merged.
  Phase 2. Add the classifier, strategies, and the feedback loop.

Do not add a new evasion implementation while acscan still has four copies. That
creates the duplication this package exists to remove.

## Hard constraints

- Python >= 3.12. `[tool.ruff]` already has an explicit rule set — extend it,
  do not remove rules to make something pass.
- Every runtime dependency must be declared in `pyproject.toml`. A clean
  `pip install -e .` must import. A sibling shipped with three undeclared deps
  and could not be imported at all.
- No hard file-size rule anywhere in this family. Keep modules cohesive.
- CI must stay green. It was red on `main` in a sibling repo for weeks because
  nobody read it.
- Comments should explain WHY, not restate what the code does. That is the
  convention across this family.

## Non-negotiable quality bar

Every detector must have a negative test: a response that must NOT produce a
finding. The gRPC reflection detector in a sibling repo reported
"reflection enabled" on any non-`UNIMPLEMENTED` reply, so a 151-byte Cloudflare
HTML 403 became a MEDIUM finding on every WAF-fronted target. False positives
are the single biggest cost to this operator — more than missed bugs.

The classifier must return `unknown` with low confidence for anything it does
not recognise. Never guess and present the guess as fact.

## Open questions — decide these, write the reasoning into ARCHITECTURE.md

1. Does strategy choice persist across runs (a re-scan starts informed) or stay
   per-session? Persisting is more useful but makes a scan non-reproducible.
2. Does the loop adapt mid-scan, or only between runs? Mid-scan is more
   effective and more likely to look hostile to the target.
3. How is "blocked" surfaced to the operator — a separate finding type, or a
   field on the scan?

Do not leave these implicit in code.

## Start here

Read HANDOFF.md, then look at the four acscan files above, then propose a short
plan for Phase 1 (the extraction) before writing code. Phase 1 is mostly moving
code; the interesting design work is Phase 2.

Verify your work with real commands and report actual exit codes, not `echo $?`
after a pipe. acscan's suite takes ~25 minutes and OOMs on a 964 MB box — run it
in chunks, or deselect the four subprocess CLI tests:
  --deselect tests/test_cli_smoke.py::test_cli_help_via_subprocess
  --deselect tests/test_cli_smoke.py::test_cli_ui_help_via_subprocess
  --deselect tests/test_imports.py::test_import_cli_openapi_help
  --deselect tests/test_imports.py::test_import_cli_postman_help

Do not push to any branch other than one you create for this work. Four PRs
across the family are already open.