"""Tests for the extracted device-profile engine.

The invariant that matters most here is not cosmetic: `apply_profile` rewrites
headers wholesale, and if it drops Authorization / Cookie / X-AC-Role the replay
loses its identity. A replay that silently turns anonymous would manufacture
false "missing auth" findings and mask real authorization bugs -- both of which
cost the operator money.
"""

from __future__ import annotations

import ssl

from evasion.chameleon import CHAMELEON_PROFILES, ChameleonEngine

# The headers the replay path depends on for identity. Line 91 of the source
# special-cases exactly these three.
SESSION_HEADERS = {
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
    "Cookie": "session=abc123",
    "X-AC-Role": "admin",
}


def test_session_headers_survive_profiling() -> None:
    for _ in range(200):
        out, _ciphers = ChameleonEngine.apply_profile(dict(SESSION_HEADERS))
        for key, value in SESSION_HEADERS.items():
            assert out[key] == value, f"{key} was dropped or rewritten"


def test_a_user_agent_is_always_present() -> None:
    known = {p["ua"] for p in CHAMELEON_PROFILES}
    for _ in range(50):
        out, _ = ChameleonEngine.apply_profile({})
        assert out["User-Agent"] in known


def test_profile_returns_preferred_ciphers() -> None:
    known = {p["ciphers"] for p in CHAMELEON_PROFILES}
    for _ in range(50):
        _out, ciphers = ChameleonEngine.apply_profile({})
        assert ciphers in known


def test_shuffle_changes_header_order() -> None:
    base = {f"X-Custom-{i}": str(i) for i in range(12)}
    orders = {tuple(ChameleonEngine.apply_profile(dict(base))[0]) for _ in range(30)}
    assert len(orders) > 1, "shuffle=True never varied the header order"


def test_randomize_case_is_applied() -> None:
    # _randomize_case flips each character independently, so a single draw can
    # legitimately reproduce the original casing (1/2**14 for this key). Assert
    # over many draws instead of betting on one.
    saw_change = False
    for _ in range(50):
        out, _ = ChameleonEngine.apply_profile({"X-Custom-Header": "v"}, randomize_case=True)
        assert "x-custom-header" in {k.lower() for k in out}, "the header was lost entirely"
        if "X-Custom-Header" not in out:
            saw_change = True
    assert saw_change, "case randomization never took effect"


def test_get_ja3_context_builds_an_ssl_context() -> None:
    # Moved verbatim and currently uncalled anywhere in the family. Assert the
    # shape only -- this helper disables certificate verification by design and
    # must not be treated as a supported code path.
    ctx = ChameleonEngine.get_ja3_context(CHAMELEON_PROFILES[0]["ciphers"])
    assert isinstance(ctx, ssl.SSLContext)


def test_get_ja3_context_survives_an_unknown_cipher_string() -> None:
    ctx = ChameleonEngine.get_ja3_context("NOT-A-REAL-CIPHER-SUITE")
    assert isinstance(ctx, ssl.SSLContext)
