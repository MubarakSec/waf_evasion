# ARCHITECTURE — waf_evasion

## Status: Phase 1a landed, Phase 2 not started

Phase 1a is the extraction only. No new capability. acscan is **untouched** —
nothing imports from this package yet, and this package imports nothing from
acscan. The wiring is Phase 1b and is currently blocked on packaging; see
[Phase 1b](#phase-1b-the-wiring-blocked).

## What moved

Every file below is byte-identical to its acscan source. `diff` against the
acscan path is empty, which is what makes the move reviewable and any later
behaviour change attributable to a specific commit rather than to the refactor.

| acscan path | here | lines |
|---|---|---|
| `acscan/engine/chameleon.py` | `evasion/chameleon.py` | 137 |
| `acscan/engine/replay/polymorphic.py` | `evasion/polymorphic.py` | 45 |
| `acscan/engine/waf_mapper.py` | `evasion/waf_mapper.py` | 67 |
| `acscan/engine/replay/evasion.py` | `evasion/evade.py` | 124 |
| `acscan/engine/pipeline/executor/waf.py:29` (`is_waf_blocked`) | `evasion/detect.py` | — |
| `acscan/engine/replay/utils.py:46` (`_generate_random_ip`) | `evasion/_net.py` | — |

`evade.py` differs from its source in exactly four lines, all of them imports
re-pointed at local modules. No other byte differs.

### What deliberately did not move

`pause_event`, `pause_executor`, `resume_executor`, `waf_paused`,
`waf_pause_reason` and `current_loop` stayed in `acscan/engine/pipeline/
executor/waf.py`. They are module-global mutable `asyncio` state bound to the
executor's event loop and read by the UI (`acscan/ui/routes/attack.py:113,189,
207`). Exporting that from a shared library couples this package to acscan's
execution lifecycle, and `docs/TOOL_BOUNDARIES.md` puts the attack/replay path
in acscan. Only `is_waf_blocked` — the detection logic — is generic.

`get_ja3_context` has no callers anywhere in the family. It moved verbatim
rather than being deleted, because dropping code during a move is exactly the
unreproducible change the mandate forbids.

### Why `chameleon.py` came too

`replay/evasion.py` lazily imported `acscan.engine.chameleon.ChameleonEngine`.
Moving `apply_evasion` without it would have made this package depend on acscan,
which inverts the intended direction. It is stdlib-only (`logging`, `random`,
`ssl`) and had exactly one consumer, so moving it removes the backwards
dependency outright rather than papering over it with an injectable parameter.

## The three open questions, decided

### 1. Does strategy choice persist across runs, or stay per-session?

**Persist the observations; never persist the decision.**

Persisting a *chosen strategy* would mean a re-scan of the same target produced
different request shapes than the first one, which is precisely what makes a
scan irreproducible when you need to defend a finding.

So the split is:

- **Persisted** — the WAF fingerprint and the evidence for it (which headers,
  which body markers, at which confidence). This is evidence about the target,
  it is cheap, and it means a re-scan starts informed.
- **Not persisted** — the strategy. Strategy is re-derived deterministically from
  `(fingerprint, scan_seed)`. Same seed, same target, same fingerprint, same
  sequence of strategies. Same target, different seed, a different but equally
  valid sequence.

The practical effect is that a re-scan is both informed and reproducible. The
alternative — persisting the decision — buys nothing extra, because the
fingerprint already encodes everything the decision was based on.

### 2. Mid-scan adaptation, or only between runs?

**Mid-scan, under four constraints.**

Between-runs-only adaptation means the operator pays a full blocked scan to
learn something the second scan would have used. That is a real cost. But
mid-scan adaptation is also the behaviour most likely to read as an attack from
the target's side, and "out-of-scope requests get the operator banned from a
program" is an explicit family constraint.

So adaptation is allowed mid-scan, bounded by:

1. **Trigger only on a confirmed block.** Never on a guess. An unrecognised
   fingerprint gets conservative defaults, not a new strategy.
2. **Reduce before you vary.** The first adaptation must lower rate and widen
   timing. Polymorphic retry is the last resort, not the first, because it is
   the most obviously hostile move available.
3. **Budget it.** A hard cap on adaptations per target per window, so a
   pathological loop cannot escalate indefinitely.
4. **Record every adaptation.** Each one is evidence in the scan output.

### 3. How is "blocked" surfaced — a finding, or a field on the scan?

**A field on the scan outcome. Never a finding.**

A block is not a vulnerability. Findings drive triage, severity and payout;
putting a non-bug in that channel is precisely the false-positive cost this
operator cares about most.

But "never a finding" is not enough on its own — it is the current bug in
disguise. A blocked scan that reports zero findings is read as "nothing to
find", which is the exact confusion this package exists to remove. So the scan
outcome carries:

- `blocked`: whether the target blocked us at all
- `waf_fingerprint` + `confidence`, `unknown` with low confidence when
  unrecognised
- `blocked_responses` / `total_responses`
- a **verdict** — and this is the part that matters:

| blocked fraction | verdict |
|---|---|
| 0 | `clean` — zero findings means zero findings |
| below threshold | `partial` — findings valid, coverage reduced |
| at or above threshold | **`inconclusive`** — not "no findings" |

`inconclusive` must be impossible to read as a clean bill of health. An operator
who sees it knows to change approach rather than file "nothing found".

## Verified defects, recorded not fixed

Phase 1a moved code without changing behaviour. Four defects were found while
writing the tests. Each is captured as a `strict=True` `xfail`, so fixing it
forces the marker off and the defect cannot be quietly forgotten.

**1. acscan's WAF sentinel can never fire.**
`acscan/engine/pipeline/executor/core.py:229` passes the dict returned by
`_format_replay_result` — keys `res_status` / `res_body` — into
`is_waf_blocked`, which reads `.status_code` / `.text`. `getattr` yields `0` and
`""`, so the function returns `(False, "")` for every result and the sentinel
never pauses.
*(`tests/test_detect.py::test_dict_result_shape_is_detected`)*

**2. The rate-limit sentinel has the same defect.** `core.py:307` reads
`res.get("status")`; the real key is `res_status`. Both WAF sentinels in acscan
are dead code. This is why a blocked scan currently looks exactly like a clean
one — the gap is not only the missing adaptive loop, it is that detection is
never invoked successfully at all. *Not covered by an xfail: the bug is in
acscan, which is untouched in Phase 1a.*

**3. `_generate_random_ip` can emit non-routable addresses.** It rejects
127/8, 10/8, 172.16/12, 192.168/16 and 169.254/16, but not CGNAT (100.64/10,
RFC 6598), the TEST-NET documentation ranges, or 198.18/15 benchmarking space.
An `X-Forwarded-For` holding `100.114.194.137` is not globally routable, which
makes the chain look synthetic to exactly the WAFs the header exists to
satisfy. *(`tests/test_evade.py::test_spoofed_ip_is_never_special_use_space`)*

**4. `is_waf_blocked`'s 403 rule is keyword-based and will over-fire.**
`403` + any of `cloudflare, captcha, sucuri, waf, ddos` in the body. For an
access-control scanner, 403 is overwhelmingly the *expected* answer, and
`waf` is a three-letter substring that appears in ordinary page furniture. The
tests here pin the cases that matter (JSON auth failures and plain 403 pages do
not fire); the over-broad cases are left for the Phase 2 classifier, which
replaces keyword matching with fingerprinting.

Also noted: `get_ja3_context` triggers `DeprecationWarning` on 3.13 for
`ssl.OP_NO_TLSv1`. Left alone — same rule.

## Lint carve-outs

`[tool.ruff.lint.per-file-ignores]` scopes `S311`, `E701` and `PIE790` to the six
migrated files only. Inline suppressions were rejected: 16 of them would have
edited the moved code and destroyed the empty-`diff` property that makes the move
verifiable. The rules stay fully live for every new file — verified by dropping
a probe file containing both patterns into `evasion/` and confirming ruff still
flagged them.

Re-exports in `evasion/__init__.py` go through `__all__` rather than `noqa`.
HANDOFF records two rounds of `RUF100` deleting a block-level suppression and
then `F401` deleting the re-exports themselves; declaring `__all__` makes the
suppression unnecessary, so no autofix can remove it. Do not spell a `noqa`
token literally in that file's comments — ruff parses any comment line for
directives and emits "Invalid noqa directive" on every run.

## Baseline: acscan on `main`, before any wiring

Phase 1 ends with "acscan's full suite green". That claim is only meaningful
against a recorded starting point, so this is the state of `acscan` at
`010a6dd` on `main`, **before** any acscan file is touched. acscan is unmodified
in this branch; its only working-tree entry is a pre-existing untracked
`graphify-out/`.

Command, per the brief (chunked, with the four subprocess CLI tests deselected):

```
../.venv/bin/python -m pytest --ignore=tests/broken \
  -k "not test_e2e_vulnerable_api" \
  --deselect tests/test_cli_smoke.py::test_cli_help_via_subprocess \
  --deselect tests/test_cli_smoke.py::test_cli_ui_help_via_subprocess \
  --deselect tests/test_imports.py::test_import_cli_openapi_help \
  --deselect tests/test_imports.py::test_import_cli_postman_help <chunk>
```

Run in 10 chunks of 35 files. **Do not add `-q`** — acscan's `addopts` already
carries one, and a second makes it `-qq`, which suppresses the summary line and
leaves you with exit codes and no counts.

| chunk | exit | result |
|---|---|---|
| 01 | 0 | 166 passed in 89.74s |
| 02 | 0 | 179 passed, 1 skipped, 2 deselected in 149.73s |
| 03 | **1** | 321 passed, 1 deselected, **1 error** in 1457.98s |
| 04 | 0 | 141 passed, 2 deselected in 35.70s |
| 05 | 0 | 79 passed in 44.86s |
| 06 | 0 | 178 passed in 42.49s |
| 07 | 0 | 1046 passed, 1 skipped in 181.78s |
| 08 | 0 | 193 passed in 26.25s |
| 09 | 0 | 146 passed in 20.75s |
| 10 | 0 | 61 passed in 6.76s |

**2510 passed, 2 skipped, 6 deselected, 1 error.**

The single error is `test_e2e_full_pipeline.py::test_e2e_demo_api_full_pipeline`
and it is **not a code defect**. It is a module-scoped fixture that spawns
`uvicorn` and then polls for exactly 20 × 0.5s = 10s before calling
`pytest.fail("Demo API failed to start")`. On this box it lost that race when
94 MB was available, and passed on three subsequent runs at 180–213 MB
(11.15s, 6.94s, 4.02s — exit 0 each time).

So the suite is green, but that test has a **10-second server-boot budget with
no headroom** and will flake whenever the box is under memory pressure. Anyone
running this gate on a constrained machine should expect it, and should not
read it as a regression introduced by the extraction.

Two operational notes for whoever runs this next:

- `test_detector_module_hygiene.py` imports each of **117 detector modules in a
  fresh subprocess**. It alone accounted for 24 of the ~35 minutes. Chunk it
  separately or budget for it.
- This box peaks at ~65–220 MB available with 866 MB already in use. Full
  sequential runs, not parallel ones.

## Phase 1b: the wiring, blocked

acscan cannot import from here yet, and this is a packaging problem rather than
a code problem:

- acscan is a **submodule with its own repo**; its CI checks out only itself.
- its dependencies live in `setup.cfg`, not `[project]`.
- this package is **not a submodule**, is not published, and is not in the
  umbrella `.venv`.

So a hard `from evasion import ...` in acscan breaks `pip install -e .` for
anyone who clones acscan alone. That is the `family_orcha` failure from
HANDOFF rule 2, wearing a different hat.

Options, in rough order of preference:

1. **Publish `evasion`.** Unblocks everything and is the normal end state.
   Needs a decision on the name first — `evasion` is a very generic top-level
   module for a package installed into a shared `.venv` next to five other
   tools, and worth checking for a squatted distribution before committing.
2. **Vendor via CI.** acscan's workflow clones this repo and installs it before
   itself. No publish required, but acscan's build then depends on another
   repository's `main` and breaks whenever this one moves.
3. **Make it a real submodule**, which fixes both this and the publish path by
   giving the dependency a concrete address.

Until one of these is chosen, acscan's copies are the only live implementation.
There is exactly one implementation *of the extraction*; the acscan originals
are pending deletion, not parallel alternatives.

## Phase 2 scope

Not started. Sketched here so the Phase 1a boundary is clear.

- `evasion/classify/` — fingerprint from headers, body and status. Returns
  `unknown` with low confidence for anything unrecognised, never a guess
  presented as fact. Every detector gets a negative test.
- `evasion/strategies/` — per-WAF choices, expressed as adjustments to the
  knobs `apply_evasion` already has, so the extracted code stays the single
  mutation path.
- `evasion/loop/` — blocked → classify → adapt → retry → record, and the
  `clean` / `partial` / `inconclusive` verdict from decision 3.

The classifier is where defect 4 gets fixed properly, and the loop is where
defects 1 and 2 stop being dead code.

## Scope

Authorized testing only. This package mutates outbound requests to reach a
target the operator is permitted to assess. It has no use against systems the
operator is not authorized to test, and that is not what it is for.