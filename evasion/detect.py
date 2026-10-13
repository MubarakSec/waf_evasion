"""Block detection — decides whether a response is a WAF block.

Extracted verbatim from acscan `acscan/engine/pipeline/executor/waf.py:29`.
Only `is_waf_blocked` moved. The `pause_event` / `pause_executor` /
`resume_executor` globals in that module are acscan pipeline execution control
and stay in acscan; see ARCHITECTURE.md.

Body is byte-identical to the source. Any correction lands separately.
"""

from __future__ import annotations

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


def is_waf_blocked(resp: Any) -> tuple[bool, str]:
    status = getattr(resp, "status_code", 0)
    body = str(getattr(resp, "text", "")).lower()
    if status == 429: return True, "Rate limit (429) detected."
    if status == 403 and any(kw in body for kw in CHALLENGE_MARKERS):
        return True, "WAF block (403 HTML challenge) detected."
    if status >= 500 and "cloudflare" in body:
        return True, "WAF gateway error (5xx) detected."
    return False, ""
