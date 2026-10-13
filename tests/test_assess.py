"""Tests for assess/summarize.

The obligation here is not "does it detect a block" -- is_waf_blocked already has
that covered. It is: **a blocked target must never be reported as clean**, even
when the WAF cannot be named.

That is the failure that costs money. A WAF-fronted target and an unexploitable
one look identical unless something records the block, and a hunter who reads
"no findings" as "nothing there" reports nothing about a target they never
reached.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from evasion.loop.assess import assess, summarize


def resp(headers=None, text="", status: int = 200):
    return SimpleNamespace(headers=headers or {}, text=text, content=b"", status_code=status)


CF_BLOCK = resp({"cf-ray": "8a1b", "cf-mitigated": "challenge"},
                "<html><head><title>Attention Required! | Cloudflare</title></head>\n<body>Just a moment...</body></html>", 403)
CF_CLEAN = resp({"cf-ray": "8a1b", "server": "cloudflare"}, "<html>ok</html>", 200)
RATE_LIMIT = resp({"x-amzn-requestid": "abc"}, "", 429)
# A real block, but with no vendor headers: an edge that challenges without
# identifying itself. This is the case that must never be reported as clean.
ANON_BLOCK = resp({"server": "envoy"}, "<h1>Just a moment...</h1>", 403)


# --- detection + classification together --------------------------------------

def test_blocked_cloudflare_block_is_named():
    a = assess(CF_BLOCK)
    assert a.blocked
    assert a.confident_waf
    assert a.waf == "cloudflare"
    assert "403" in a.reason


def test_clean_response_still_learns_the_vendor():
    """Knowing a target is behind Cloudflare before it blocks anything is worth
    having, so classification runs even when nothing was blocked."""
    a = assess(CF_CLEAN)
    assert not a.blocked
    assert a.confident_waf
    assert a.waf == "cloudflare"


def test_rate_limit_is_a_block_and_is_attributed():
    a = assess(RATE_LIMIT)
    assert a.blocked
    assert a.waf == "aws-waf"


def test_plain_response_is_neither_blocked_nor_identified():
    a = assess(resp({"content-type": "application/json"}, '{"ok":true}'))
    assert not a.blocked
    assert a.waf == "unknown"
    assert not a.confident_waf


# --- the property that matters -----------------------------------------------

def test_unnamed_waf_block_is_still_reported_as_blocked():
    """A generic 403 from an unidentifiable edge is still not a clean target.

    Guessing the vendor would be wrong. Reporting the target as clean would be
    worse. This is the exact trade the package refuses to get wrong.
    """
    a = assess(ANON_BLOCK)
    assert a.waf == "unknown"
    assert not a.confident_waf
    assert a.target_is_unreachable, "an unidentified block must not read as clean"


def test_blocked_targets_are_counted_separately_from_clean():
    """The field that stops a WAF'd target being reported as having nothing."""
    summary = summarize([assess(r) for r in (CF_BLOCK, CF_CLEAN, CF_CLEAN, RATE_LIMIT)])
    assert summary["responses"] == 4
    assert summary["blocked_responses"] == 2
    assert summary["blocked_targets"] == 2
    assert summary["vendors"] == {"cloudflare": 3, "aws-waf": 1}
    assert summary["confidently_identified"] == ["aws-waf", "cloudflare"]


def test_all_clean_scan_reports_zero_blocked():
    summary = summarize([assess(CF_CLEAN), assess(CF_CLEAN)])
    assert summary["blocked_targets"] == 0
    assert summary["responses"] == 2


def test_unknown_vendor_blocks_are_counted_separately():
    """An unnamed block is a finding about our coverage, not a vendor claim."""
    summary = summarize([assess(ANON_BLOCK), assess(CF_BLOCK)])
    assert summary["unknown_vendor_blocks"] == 1
    assert summary["blocked_targets"] == 2


def test_empty_scan_summarises_without_dividing_by_zero():
    s = summarize([])
    assert s == {
        "responses": 0, "blocked_responses": 0, "blocked_targets": 0,
        "vendors": {}, "unknown_vendor_blocks": 0, "confidently_identified": [],
    }


def test_assessment_is_immutable():
    """A strategy may hold one of these; it must not be able to edit it."""
    a = assess(CF_BLOCK)
    # dataclass(frozen=True) raises FrozenInstanceError, which subclasses
    # AttributeError. Naming it rather than Exception keeps the test honest
    # about what it is asserting.
    with pytest.raises(AttributeError):
        a.blocked = False  # type: ignore[misc]
