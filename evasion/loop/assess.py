"""One call that answers both questions a strategy needs.

`is_waf_blocked()` says whether a response looks like a block. `classify()` says
who sent it. Neither alone is enough: a strategy needs to know "blocked, and by
what" to choose a response, and the operator needs to know a target was blocked
so it is not mistaken for one that simply had nothing to find.

That second point is the one that costs money. A WAF-fronted target and an
unexploitable one currently produce indistinguishable output, so a blocked scan
reads exactly like a clean result -- which is how a hunter reports "nothing
found" about a target they never actually reached.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from evasion.classify import CONFIDENT, Classification, classify
from evasion.detect import is_waf_blocked


@dataclass(frozen=True)
class Assessment:
    """Outcome of looking at one response."""

    blocked: bool
    #: Why we think it was a block, from is_waf_blocked.
    reason: str
    #: Which WAF, or "unknown". May be populated even when blocked is False --
    #: learning that a target sits behind Cloudflare is useful before any block.
    classification: Classification

    @property
    def waf(self) -> str:
        return self.classification.waf

    @property
    def confident_waf(self) -> bool:
        """True only when the vendor is known with header evidence."""
        return self.classification.is_known and self.classification.confidence >= CONFIDENT

    @property
    def target_is_unreachable(self) -> bool:
        """Whether this target should be reported as blocked rather than clean.

        Deliberately conservative: an unrecognised WAF on a blocking response
        still means we did not get through. Claiming a vendor we cannot name
        would be the guess this package refuses to make, and reporting such a
        target as clean would be the costly error.
        """
        return self.blocked


def assess(resp: Any) -> Assessment:
    """Classify and detect in one pass over a response.

    Classification runs even on a clean response, because knowing a target is
    behind Cloudflare before it blocks anything is worth having.
    """
    blocked, reason = is_waf_blocked(resp)
    return Assessment(blocked=blocked, reason=reason, classification=classify(resp))


def summarize(assessments: list[Assessment]) -> dict[str, Any]:
    """Roll a scan's responses into a shape worth putting in a report.

    `blocked_targets` is the field that stops a WAF'd target being reported as
    clean. It is derived from the conservative rule above, so an unnamed WAF
    still counts as blocked.
    """
    blocked = [a for a in assessments if a.target_is_unreachable]
    vendors: dict[str, int] = {}
    for a in assessments:
        if a.classification.is_known:
            vendors[a.waf] = vendors.get(a.waf, 0) + 1

    return {
        "responses": len(assessments),
        "blocked_responses": len(blocked),
        "blocked_targets": len(blocked),
        "vendors": vendors,
        "unknown_vendor_blocks": sum(1 for a in blocked if not a.classification.is_known),
        "confidently_identified": sorted({a.waf for a in assessments if a.confident_waf}),
    }
