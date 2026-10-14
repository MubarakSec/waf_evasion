"""Fingerprint which WAF, if any, produced a response.

The rule this module exists to enforce: **never name a vendor without header
evidence.** Body markers alone produce a low-confidence guess, never a
confident claim.

That is the same failure that produced the gRPC false positive in
infra_killer, where any non-`UNIMPLEMENTED` reply became "reflection enabled" and
every WAF-fronted target scored a MEDIUM. A classifier that guesses is worse
than no classifier, because its output looks like knowledge.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Shared accessors. These read acscan's replay-result dict as well as a response
# object; reading attributes only made this classifier return UNKNOWN for every
# replay, which is the same defect `detect.response_field` documents.
from evasion.detect import body_of, headers_of

# Confidence bands. `UNKNOWN` is what an unrecognised response gets, and it is
# deliberately the most common outcome -- a classifier that rarely says "I don't
# know" is lying.
CONFIDENT = 0.75
SUGGESTED = 0.40
UNKNOWN_CONFIDENCE = 0.0


@dataclass(frozen=True)
class WAFSignature:
    """Evidence that points at one vendor.

    `headers` are checked as names only, so `cf-ray: 8a1b2c` matches regardless
    of value. `body_markers` are matched case-insensitively against the body and
    are never sufficient on their own.
    """

    name: str
    headers: tuple[str, ...] = ()
    body_markers: tuple[str, ...] = ()
    #: Body-only evidence is capped at this, because bodies lie. A generic
    #: nginx challenge page served in front of a CDN still says "nginx".
    body_only_cap: float = SUGGESTED


SIGNATURES: tuple[WAFSignature, ...] = (
    WAFSignature(
        name="cloudflare",
        headers=("cf-ray", "cf-cache-status", "cf-mitigated"),
        body_markers=("cf-ray", "cloudflare", "attention required", "cf-browser-verification"),
    ),
    WAFSignature(
        name="aws-waf",
        headers=("x-amzn-waf-action", "x-amzn-requestid", "x-amzn-waf"),
        body_markers=("request blocked", "awswaf"),
    ),
    WAFSignature(
        name="akamai",
        headers=("akamai-grn", "akamai-grn-akamai"),
        # "reference #" is Akamai's distinctive signature. "access denied" was
        # here too and is wrong: it is what an ordinary nginx 403 says, so
        # it named Akamai on any plain 403 -- this classifier guessing, which
        # is the one thing it exists not to do.
        body_markers=("reference #",),
    ),
    WAFSignature(
        name="imperva",
        headers=("x-iinfo", "x-cdn"),
        body_markers=("incapsula incident id", "request unsuccessful"),
    ),
    WAFSignature(
        name="fastly",
        headers=("x-fastly-request-id", "fastly-debug-digest"),
        body_markers=("fastly error",),
    ),
    # Generic only. `server: nginx` on its own is not evidence of a WAF, so
    # this signature deliberately has no headers and can never be confident.
    WAFSignature(name="nginx", headers=(), body_markers=("nginx",), body_only_cap=SUGGESTED),
)


@dataclass(frozen=True)
class Classification:
    """What we think produced a response, and how strongly we think it."""

    waf: str
    confidence: float
    #: Which signals matched. Empty for `unknown`, so a caller can always show
    #: their reasoning rather than being asked to trust a label.
    evidence: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_known(self) -> bool:
        return self.waf != "unknown"

    @property
    def is_confident(self) -> bool:
        return self.confidence >= CONFIDENT


UNKNOWN = Classification(waf="unknown", confidence=UNKNOWN_CONFIDENCE, evidence=())


def _headers_of(resp: Any) -> dict[str, str]:
    return headers_of(resp)


def _body_of(resp: Any) -> str:
    return body_of(resp)


def classify(resp: Any) -> Classification:
    """Identify the WAF behind `resp`.

    Returns UNKNOWN for anything unrecognised. Callers should treat a
    non-confident result as "assume the worst and slow down", never as a fact.
    """
    headers = _headers_of(resp)
    body = _body_of(resp)

    best: Classification | None = None
    for sig in SIGNATURES:
        matched_headers = tuple(h for h in sig.headers if h in headers)
        matched_body = tuple(m for m in sig.body_markers if m in body)

        if matched_headers:
            # Header evidence is vendor-specific and spoofable only by the vendor
            # itself, so it is allowed to be confident.
            confidence = CONFIDENT
            evidence = tuple(f"header:{h}" for h in matched_headers) + \
                       tuple(f"body:{m}" for m in matched_body)
        elif matched_body:
            # Bodies are generic. "nginx" or "access denied" can appear behind
            # any CDN, so this caps low and stays non-confident by construction.
            confidence = sig.body_only_cap
            evidence = tuple(f"body:{m}" for m in matched_body)
        else:
            continue

        if best is None or confidence > best.confidence or (
            confidence == best.confidence and len(evidence) > len(best.evidence)
        ):
            best = Classification(waf=sig.name, confidence=confidence, evidence=evidence)

    return best or UNKNOWN
