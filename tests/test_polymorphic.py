"""Tests for request polymorphism.

`mutate_json` exists to defeat naive string matching while the request still
means the same thing to the server. Both halves matter: a variant the WAF
rejects is useless, and a variant that changes the payload's meaning turns an
authorized replay into a different request entirely -- which is how a scanner
manufactures phantom findings. So the invariant under test is semantic
equivalence, asserted over many iterations because every branch is random.
"""

from __future__ import annotations

import json

from evasion.polymorphic import PolymorphicTransformer

BODY = {
    "username": "admin",
    "password": "hunter2",
    "role": "root",
    "debug": True,
    "count": 0,
    "nested": {"id": "abc", "flag": False},
}


def test_mutated_json_still_parses_to_the_same_object() -> None:
    transformer = PolymorphicTransformer()
    for _ in range(500):
        raw = transformer.mutate_json(dict(BODY))
        assert isinstance(raw, str)
        assert json.loads(raw) == BODY, "polymorphism changed the payload's meaning"


def test_mutation_actually_varies_the_bytes_on_the_wire() -> None:
    """Must not be a no-op -- identical bytes would defeat the purpose."""
    transformer = PolymorphicTransformer()
    variants = {transformer.mutate_json(dict(BODY)) for _ in range(50)}
    assert len(variants) > 1


def test_empty_dict_is_handled() -> None:
    assert json.loads(PolymorphicTransformer().mutate_json({})) == {}


def test_unicode_escaping_stays_valid_json() -> None:
    """Sensitive words get \\uXXXX-escaped; the escapes must survive a round trip."""
    transformer = PolymorphicTransformer()
    seen_escape = False
    for _ in range(200):
        raw = transformer.mutate_json({"user": "admin", "role": "debug"})
        assert json.loads(raw) == {"user": "admin", "role": "debug"}
        if "\\u" in raw:
            seen_escape = True
    assert seen_escape, "the escape branch never executed in 200 iterations"


def test_method_override_only_applies_to_the_three_unsafe_methods() -> None:
    transformer = PolymorphicTransformer()
    for _ in range(200):
        method, headers = transformer.apply_method_override("GET", {"Accept": "*/*"})
        assert method == "GET"
        assert "X-HTTP-Method-Override" not in headers


def test_method_override_carries_the_original_method() -> None:
    transformer = PolymorphicTransformer()
    for original in ("PUT", "DELETE", "PATCH"):
        saw_override = False
        for _ in range(100):
            method, headers = transformer.apply_method_override(original, {})
            if method == "POST":
                saw_override = True
                assert headers["X-HTTP-Method-Override"] == original
            else:
                assert method == original
        assert saw_override, f"{original} was never overridden in 100 iterations"


def test_method_override_does_not_mutate_the_callers_headers() -> None:
    transformer = PolymorphicTransformer()
    original = {"Authorization": "Bearer t"}
    transformer.apply_method_override("PUT", original)
    assert "X-HTTP-Method-Override" not in original
