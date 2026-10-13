"""Block detection — decides whether a response is a WAF block.

Extracted verbatim from acscan `acscan/engine/pipeline/executor/waf.py:29`.
Only `is_waf_blocked` moved. The `pause_event` / `pause_executor` /
`resume_executor` globals in that module are acscan pipeline execution control
and stay in acscan; see ARCHITECTURE.md.

Body is byte-identical to the source. Any correction lands separately.
"""

from __future__ import annotations

from typing import Any

def is_waf_blocked(resp: Any) -> tuple[bool, str]:
    status = getattr(resp, "status_code", 0)
    body = str(getattr(resp, "text", "")).lower()
    if status == 429: return True, "Rate limit (429) detected."
    if status == 403 and any(kw in body for kw in ["cloudflare", "captcha", "sucuri", "waf", "ddos"]):
        return True, "WAF block (403 HTML challenge) detected."
    if status >= 500 and "cloudflare" in body:
        return True, "WAF gateway error (5xx) detected."
    return False, ""
