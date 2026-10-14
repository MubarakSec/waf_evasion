"""Block detection — decides whether a response is a WAF block.

Extracted verbatim from acscan `acscan/engine/pipeline/executor/waf.py:29`.
Only `is_waf_blocked` moved. The `pause_event` / `pause_executor` /
`resume_executor` globals in that module are acscan pipeline execution control
and stay in acscan; see ARCHITECTURE.md.

The detection rules below are still the source body, unchanged. The accessors
around them are not: see `response_field` for why `getattr`-only reading was
wrong in production.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# Markers a blocking interstitial actually uses. "attention required" is
# Cloudflare's challenge heading and was missing: a 403 whose body read only
# "Attention Required" -- which is what a trimmed or proxied challenge page
# looks like -- was reported as not blocked, i.e. as a clean target.
CHALLENGE_MARKERS: tuple[str, ...] = (
    "cloudflare", "captcha", "sucuri", "waf", "ddos",
    "attention required", "checking your browser", "just a moment",
    "enable javascript and cookies", "browser verification",
    # Deliberately NOT here: "access denied" and "request unsuccessful". Both
    # appear on an ordinary nginx 403 from any server, so including them made
    # every plain 403 read as a WAF block.
)


def response_field(resp: Any, obj_names: tuple[str, ...], dict_keys: tuple[str, ...]) -> Any:
    """Read one response field from either shape this package is handed.

    **Why this exists.** acscan does not pass an `httpx.Response` here. It passes
    the plain dict built by `_format_replay_result`
    (`acscan/engine/replay/core.py:176`), whose keys are `res_status`,
    `res_headers` and `res_body`. `getattr()` on a dict returns the default for
    *every* attribute, so the original attribute-only reader saw `status == 0`
    and `body == ""` for every replay and returned `(False, "")` unconditionally.

    That made `assess()` -> `pause_executor()` in
    `acscan/engine/pipeline/executor/core.py:340` unreachable, so the WAF
    sentinel never counted a block and never auto-paused. The failure is
    expensive rather than loud: a WAF-fronted target produced byte-identical
    output to one with nothing to find, and "we never got through" reads as
    "there is nothing here".

    Both shapes are accepted, and the mapping form is checked first. A missing
    field yields `None` rather than raising, so an unrecognised object stays
    "not a block" instead of exploding inside a sentinel.
    """
    if isinstance(resp, Mapping):
        for key in dict_keys:
            value = resp.get(key)
            if value is not None:
                return value
        return None
    for name in obj_names:
        value = getattr(resp, name, None)
        if value is not None:
            return value
    return None


def status_of(resp: Any) -> int:
    """Status as an int, or 0 when it cannot be read.

    Tolerates the string statuses some replay paths store, so `429` and `"429"`
    are the same answer. `bool` is rejected explicitly: it is an `int`
    subclass, and `True` must never read as a status.
    """
    raw = response_field(resp, ("status_code", "status"), ("res_status", "status", "status_code"))
    if isinstance(raw, bool) or raw is None:
        return 0
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        try:
            return int(raw.strip())
        except ValueError:
            return 0
    return 0


def body_of(resp: Any) -> str:
    """Lowercased body text, or `""`.

    Truncated to 4 KiB. The challenge markers this package matches are all in
    the first page, and an unbounded read over a large response is a cheap way
    to make every replay expensive.
    """
    raw = response_field(resp, ("text", "body"), ("res_body", "body", "text"))
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw[:4096]).decode("utf-8", errors="replace").lower()
    if isinstance(raw, str):
        return raw[:4096].lower()
    data = response_field(resp, ("content",), ("res_body_json",))
    if isinstance(data, (bytes, bytearray)):
        return bytes(data[:4096]).decode("utf-8", errors="replace").lower()
    return ""


def headers_of(resp: Any) -> dict[str, str]:
    """Lowercased header names -> values, or `{}`."""
    raw = response_field(resp, ("headers",), ("res_headers", "headers"))
    if raw is None:
        return {}
    try:
        return {str(k).lower(): str(v) for k, v in dict(raw).items()}
    except (TypeError, ValueError, AttributeError):
        return {}


def is_waf_blocked(resp: Any) -> tuple[bool, str]:
    status = status_of(resp)
    body = body_of(resp)
    if status == 429: return True, "Rate limit (429) detected."
    if status == 403 and any(kw in body for kw in CHALLENGE_MARKERS):
        return True, "WAF block (403 HTML challenge) detected."
    if status >= 500 and "cloudflare" in body:
        return True, "WAF gateway error (5xx) detected."
    return False, ""
