"""Tests for the WAF classifier.

Two obligations:

  1. It must identify real vendors from real header evidence.
  2. It must say "unknown" far more often than it guesses.

(2) is the one that matters. A classifier that names a vendor on thin evidence
produces findings that look like knowledge and are not -- which is how
infra_killer ended up reporting "gRPC reflection enabled" on every
Cloudflare-fronted target because any non-error reply counted.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from evasion.classify.classify import CONFIDENT, SUGGESTED, UNKNOWN, classify


def resp(headers=None, text="", status: int = 200):
    return SimpleNamespace(headers=headers or {}, text=text, content=b"", status_code=status)


# --- positive: header evidence ------------------------------------------------

@pytest.mark.parametrize(
    ("header", "value", "expected"),
    [
        ("cf-ray", "8a1b2c3d4e5f", "cloudflare"),
        ("cf-cache-status", "DYNAMIC", "cloudflare"),
        ("x-amzn-waf-action", "challenge", "aws-waf"),
        ("akamai-grn", "1.2.3.4", "akamai"),
        ("x-iinfo", "abc", "imperva"),
        ("x-fastly-request-id", "xyz", "fastly"),
    ],
)
def test_identifies_vendor_from_its_own_header(header, value, expected):
    """Each vendor's proprietary header identifies it -- these are not spoofable
    by anything other than the vendor itself."""
    result = classify(resp({header: value}))
    assert result.waf == expected
    assert result.is_confident
    assert result.confidence >= CONFIDENT
    assert any(e.startswith("header:") for e in result.evidence)


def test_header_match_is_case_insensitive():
    assert classify(resp({"CF-RAY": "abc"})).waf == "cloudflare"


def test_reports_the_evidence_not_just_the_label():
    """A caller must be able to show why, rather than be asked to trust it."""
    result = classify(resp({"cf-ray": "abc"}))
    assert "header:cf-ray" in result.evidence


# --- negative: must NOT guess -------------------------------------------------

def test_plain_response_is_unknown():
    result = classify(resp({"content-type": "text/html"}, "<html>hello</html>"))
    assert result.waf == "unknown"
    assert result.confidence == 0.0
    assert result.evidence == ()
    assert not result.is_known


def test_generic_headers_are_not_waf_evidence():
    """Server and content-type say what served the page, not that it was filtered."""
    result = classify(resp({"server": "nginx/1.25.3", "content-type": "text/html"}))
    assert result.waf == "unknown"
    assert not result.is_confident


def test_body_text_alone_never_yields_confidence():
    """A generic nginx/access-denied page can sit behind any CDN."""
    result = classify(resp({"server": "cloudflare"}, "<html><h1>nginx</h1></html>"))
    assert not result.is_confident


def test_cloudflare_body_marker_without_headers_is_low_confidence():
    result = classify(resp({"server": "nginx"}, "<p>Cloudflare Ray ID: abc</p>"))
    if result.is_known:
        assert result.confidence <= SUGGESTED
        assert not result.is_confident


def test_empty_response_is_unknown():
    assert classify(resp()).waf == "unknown"


def test_malformed_headers_do_not_raise():
    """A response object with headers that are not dict-able must not crash the
    scan. The old parsers in this family hex-encoded whatever they were given;
    robustness here is deliberate."""
    class Hostile:
        headers = object()          # not dict()-able
        text = None
        content = None

    result = classify(Hostile())
    assert result.waf in {"unknown", "nginx"}


def test_bytes_content_is_decoded_not_crashed():
    r = SimpleNamespace(headers={}, text=None, content=b"<h1>nginx</h1>")
    assert classify(r).waf == "nginx"


# --- honesty properties -------------------------------------------------------

def test_unknown_is_the_dominant_outcome_on_generic_input():
    """Sanity check on the failure mode this module exists to avoid."""
    generic = [
        resp({"content-type": "application/json"}, '{"ok":true}'),
        resp({"server": "gunicorn/21.2.0"}, "hello"),
        resp({}, ""),
        resp({"x-powered-by": "Express"}, "<html>app</html>"),
    ]
    assert sum(1 for r in generic if classify(r).waf == "unknown") >= 3


def test_every_signature_is_reachable():
    """A typo in SIGNATURES would silently drop a vendor."""
    from evasion.classify.classify import SIGNATURES

    for sig in SIGNATURES:
        probe = resp(dict.fromkeys(sig.headers, "x")) if sig.headers else resp(
            {}, " ".join(sig.body_markers)
        )
        assert classify(probe).waf == sig.name


def test_unknown_singleton_is_shared():
    assert UNKNOWN is classify(resp({}))
