"""Negative and positive tests for `is_waf_blocked`.

Every detector in this package needs a negative test: a response that must NOT
be reported as a block. HANDOFF.md rule 4 records the cost of skipping this --
a detector that fires on clean traffic is worse than no detector, because for a
bounty hunter a false block is indistinguishable from a target with nothing to
find.

The negative cases below are the ones that actually bite acscan: it is an
access-control scanner, so a 403 is overwhelmingly the *expected* answer, not a
WAF block. Getting that backwards would mark every correctly-protected endpoint
as hostile.
"""

from __future__ import annotations

import httpx
import pytest

from evasion.detect import is_waf_blocked

# A real Cloudflare interstitial. 151 bytes of HTML in the original report.
CF_CHALLENGE = (
    "<!DOCTYPE html><html><head><title>Just a moment...</title></head>"
    "<body><div id='cf-wrapper'>Attention Required! | Cloudflare</div>"
    "<script src='/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1'></script>"
    "</body></html>"
)


def resp(status: int, body: str = "") -> httpx.Response:
    return httpx.Response(status, text=body)


# --- positive: these genuinely are blocks ------------------------------------


@pytest.mark.parametrize(
    ("status", "body", "expected_reason"),
    [
        (429, "", "Rate limit (429) detected."),
        (403, CF_CHALLENGE, "WAF block (403 HTML challenge) detected."),
        (403, "<html>Please solve the captcha to continue</html>", "WAF block (403 HTML challenge) detected."),
        (403, "<html>Access denied by Sucuri firewall</html>", "WAF block (403 HTML challenge) detected."),
        (403, "<html>Your request looks like a DDoS</html>", "WAF block (403 HTML challenge) detected."),
        (502, "<html>cloudflare error 1016</html>", "WAF gateway error (5xx) detected."),
    ],
)
def test_detects_real_blocks(status: int, body: str, expected_reason: str) -> None:
    blocked, reason = is_waf_blocked(resp(status, body))
    assert blocked is True
    assert reason == expected_reason


# --- negative: the important half -------------------------------------------


@pytest.mark.parametrize(
    ("status", "body", "why"),
    [
        (200, "<html>ok</html>", "a successful response is never a block"),
        (200, '{"users": []}', "a successful JSON response is never a block"),
        (404, "<html>Not Found</html>", "a 404 is a routing answer, not a block"),
        (
            403,
            '{"detail":"Not authenticated"}',
            "403 is the expected answer for an access-control scanner",
        ),
        (
            403,
            '{"detail":"You do not have permission to perform this action."}',
            "authorization denial must not read as a WAF block",
        ),
        (
            403,
            '<html><body><h1>403 Forbidden</h1><p>Access denied.</p></body></html>',
            "a plain 403 page with no vendor marker is not a WAF block",
        ),
        (401, '{"detail":"invalid token"}', "401 is an auth answer, not a block"),
        (500, "<html>Internal Server Error</html>", "an origin 500 is not a gateway block"),
        (502, "<html>Bad Gateway</html>", "a 502 without a vendor marker is not attributable"),
        (503, '{"error":"service unavailable"}', "an app-level 503 is not a WAF block"),
    ],
)
def test_clean_responses_are_not_blocks(status: int, body: str, why: str) -> None:
    blocked, reason = is_waf_blocked(resp(status, body))
    assert blocked is False, f"{status} {why}"
    assert reason == ""


def test_empty_body_is_not_a_block() -> None:
    assert is_waf_blocked(resp(403)) == (False, "")
    assert is_waf_blocked(resp(429, "")) == (True, "Rate limit (429) detected.")


def test_unrelated_object_is_not_a_block() -> None:
    """A response-like object missing the expected attributes must not crash or fire."""
    assert is_waf_blocked(object()) == (False, "")
    assert is_waf_blocked(None) == (False, "")


def test_status_is_checked_case_insensitively_in_body() -> None:
    blocked, _ = is_waf_blocked(resp(403, CF_CHALLENGE.upper()))
    assert blocked is True


# --- acscan's actual replay-result shape ------------------------------------
#
# acscan does not hand this package an httpx.Response. It hands it the dict built
# by `_format_replay_result` (`acscan/engine/replay/core.py:176`). The original
# attribute-only reader returned (False, "") for every one of those, so the WAF
# sentinel in `executor/core.py:340` could never count a block and never paused
# the executor. These tests pin the dict shape so that cannot silently return.


def test_acscan_replay_dict_is_detected() -> None:
    """The shape acscan really passes must reach the same verdict."""
    assert is_waf_blocked({"res_status": 429, "res_body": ""})[0] is True
    assert is_waf_blocked({"res_status": 403, "res_body": CF_CHALLENGE})[0] is True
    assert is_waf_blocked({"res_status": 502, "res_body": "cloudflare error 1016"})[0] is True


def test_acscan_replay_dict_does_not_create_false_blocks() -> None:
    """A clean replay dict must stay clean -- the FP half of the same fix.

    A false block is as expensive as a missed one: it tells the operator a
    target they were about to give up on is hostile, and vice versa.
    """
    assert is_waf_blocked({"res_status": 200, "res_body": '{"users": []}'}) == (False, "")
    assert is_waf_blocked({"res_status": 403, "res_body": '{"detail":"Not authenticated"}'}) == (False, "")
    assert is_waf_blocked({"res_status": 404, "res_body": "Not Found"}) == (False, "")


def test_string_status_is_tolerated() -> None:
    """Some replay paths store status as a string; '429' must not read as clean."""
    assert is_waf_blocked({"res_status": "429"})[0] is True


def test_bool_status_is_not_a_status() -> None:
    """bool subclasses int; True must never read as a status code."""
    assert is_waf_blocked({"res_status": True}) == (False, "")
