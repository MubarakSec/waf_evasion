# HANDOFF — read this before writing code

You are picking up `waf_evasion`. Another session built the skeleton and fixed
several bugs in the sibling repos that constrain how you should work. This file
exists so you do not rediscover them.

## What this project is

Adaptive WAF detection and evasion for **authorized** security testing. Not a
tool for attacking systems you are not permitted to test.

## The gap it fills

The family already has four pieces. Together they are not adaptive:

| Piece | Location | Behaviour |
|---|---|---|
| WAF detection | `acscan/engine/pipeline/executor/waf.py:29` | `is_waf_blocked()` → bool for 429 / 403-HTML-challenge / 5xx |
| WAF rate calibration | `acscan/engine/waf_mapper.py`, used at `acscan/engine/attack/core.py:94` | tunes RPS and burst to the target |
| Request polymorphism | `acscan/engine/replay/polymorphic.py` | |
| Generic evasion | `acscan/engine/replay/evasion.py` | device profile, IP spoofing, cache busting, header shuffle, timing sleep |

`is_waf_blocked()` returns a bool and `pause_executor()` halts. `apply_evasion()`
fires pre-emptively and identically whether or not a WAF exists. **Nothing
connects a block to a change in the next request.**

So a WAF-fronted target and an unexploitable one produce indistinguishable
output. For a bounty hunter that is worse than a clean result: it means a
blocked scan is indistinguishable from a target with nothing to find.

## Mandate: extract, do not rewrite

Move and generalise the four pieces above into this repo. **acsan must then
import from here and delete its own copies** — one implementation only. If you
add a fifth copy while acscan keeps its four, you have created exactly the
duplication this repo was meant to remove.

Order matters: land the extraction with acscan importing from here and its
suite green, *before* adding new capability. A new feature and a refactor in
one change makes the regression unreproducible.

## Mistakes from the previous session — do not repeat these

**1. Ruff autofix deletes deliberate re-exports.** This happened twice.

`RUF100` removed a block-level `# noqa: F401`, then `F401` deleted four
intentional re-exports from `acscan/normalize.py`, surfacing days later as an
`ImportError` in CI. Worse, ruff's isort fix *splits* a parenthesised import
block and drops the aliased entries entirely — restoring them inside a block just
deletes them again on the next `--fix`.

If you need to re-export, use one-line statements each carrying its own
trailing noqa, where the suppression is actually anchored. Run the import guard
after every autofix, not before.

**2. Declare every runtime dependency.** `family_orcha` shipped with `pyyaml`,
`cryptography` and `httpx` all undeclared. A clean `pip install -e .` produced a
package that could not be imported at all. The shared umbrella `.venv` masked
it completely; only isolated CI found it. A clean install must import cleanly.

**3. Pin the rule set.** reconnV2 had no `[tool.ruff]` section and CI installed
ruff unpinned, so the gate ran 413 rules from whatever the defaults were and sat
red on `main` for three weeks with 4,636 errors. Explicit `select`, and pinned
ruff in CI.

**4. Verify assertions before trusting a detector.** `is_waf_blocked()` and the
gRPC reflection detector both reported on any non-UNIMPLEMENTED reply, so a
Cloudflare HTML 403 became a MEDIUM "gRPC reflection enabled" finding. Verified
by hand: 151-byte HTML page, `file(1)` says "HTML document". Every detector
needs a negative test — a response that must NOT produce a finding.

**5. Do not assume a "hang" is a hang.** A test that looked deadlocked was
`EvasionConfig.random_delay_max = 5.0` sleeping up to 5s per replay across
hundreds of replays. Found with `faulthandler` and an asyncio task-stack walk.

## Constraints

- **No hard file-size rule.** An earlier 2000-line ceiling flagged exactly one
  real outlier out of the whole family. It was noise. Keep modules cohesive.
- **Python >= 3.12.** `requires-python = ">=3.12,<3.15"` is the family norm.
- **CI from the first commit.** acscan's gate had been failing on `main` since
  at least 2026-10-10; nobody knew because red had become the background.
- **Rate limiting is a safety feature, not a knob.** Note that `random_delay_max`
  defaults to 5.0 in acscan — every replay sleeps 0–5s, and there is no fast
  mode to turn it off. Do not make that mistake here.

## Layout

```
evasion/
  classify/     fingerprint a WAF from a response
  strategies/   per-WAF evasion choices
  loop/         blocked -> classify -> adapt -> retry, and record
```

## Acceptance criteria

1. `pip install -e .` in a clean venv, then `import evasion` — no missing deps.
2. Classifier returns a WAF identity plus a confidence, and **`unknown` with low
   confidence for anything it does not recognise** — never a guess presented as
   a fact.
3. Each detector has a negative test proving a non-WAF response yields nothing.
4. A blocked target is recorded as blocked, distinguishable from clean.
5. acscan imports from here and no longer has its own copies.

## Open questions the previous session did not resolve

- Should strategy choice persist across runs (a re-scan starts informed) or be
  per-session? Persisting is more useful but makes a scan non-reproducible.
- Does the loop adapt mid-scan, or only between runs? Mid-scan is more effective
  and more likely to look like an attack from the target's side.
- How is "blocked" surfaced to the operator? A separate finding type, or a field
  on the scan?

Decide these, write the reasoning into `ARCHITECTURE.md`, and do not leave them
implicit in code.