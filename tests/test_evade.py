"""Tests for the request-mutation entry point.

`apply_evasion` is the single place every outbound replay passes through, so
its invariant is the important one: mutation must never change who the request
is or what it says. A dropped Authorization header or a mangled body silently
turns an authenticated replay into an anonymous one and manufactures
"missing auth" findings; a dropped path parameter turns a real IDOR probe into
a request for a different resource.

`random_delay_max` is deliberately kept at 0 in these tests. acscan defaults it
to 5.0, which sleeps up to 5s per replay; HANDOFF.md rule 5 records a suite
that looked deadlocked for exactly that reason.
"""

from __future__ import annotations

import ipaddress
import random
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from evasion._net import _generate_random_ip
from evasion.evade import USER_AGENTS, apply_evasion, rotate_evasion_headers


def config(**overrides: object) -> SimpleNamespace:
    """Mirrors acscan's EvasionConfig defaults, with delays disabled."""
    base = {
        "random_delay_min": 0.0,
        "random_delay_max": 0.0,
        "rotate_user_agent": True,
        "spoof_ip": False,
        "cache_busting": False,
        "polymorphic": False,
        "orcha_infra_hints": [],
    }
    base.update(overrides)
    return SimpleNamespace(**base)


SESSION_HEADERS = {
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
    "Cookie": "session=abc123",
    "X-AC-Role": "admin",
}


# --- identity must survive ---------------------------------------------------


async def test_session_headers_survive_apply_evasion() -> None:
    for _ in range(100):
        headers, _url, _c, _m, _b = await apply_evasion(dict(SESSION_HEADERS), "https://t.test/a", config())
        for key, value in SESSION_HEADERS.items():
            assert headers[key] == value, f"{key} was dropped or rewritten by apply_evasion"


async def test_session_headers_survive_rotation() -> None:
    for _ in range(100):
        out = rotate_evasion_headers(dict(SESSION_HEADERS), config(spoof_ip=True))
        assert out["Authorization"] == SESSION_HEADERS["Authorization"]
        assert out["Cookie"] == SESSION_HEADERS["Cookie"]
        assert out["X-AC-Role"] == SESSION_HEADERS["X-AC-Role"]


async def test_no_config_falls_back_to_a_plain_user_agent() -> None:
    # config=None is falsy, so the profile branch is skipped entirely and the
    # `elif` sets a static UA. No device fingerprinting happens.
    headers, url, ciphers, method, body = await apply_evasion({}, "https://t.test/a", None)
    assert headers == {"User-Agent": USER_AGENTS[0]}
    assert url == "https://t.test/a"
    assert ciphers is None
    assert method == "GET"
    assert body is None


# --- individual behaviours ---------------------------------------------------


async def test_user_agent_is_set_when_rotation_is_off() -> None:
    headers = (await apply_evasion({}, "https://t.test/a", config(rotate_user_agent=False)))[0]
    assert headers["User-Agent"] in USER_AGENTS


async def test_existing_user_agent_is_not_overwritten_when_rotation_is_off() -> None:
    headers = (await apply_evasion({"User-Agent": "keep-me"}, "https://t.test/a", config(rotate_user_agent=False)))[0]
    assert headers["User-Agent"] == "keep-me"


async def test_spoofed_forwarded_for_is_a_chain_of_distinct_ips() -> None:
    headers = (await apply_evasion({}, "https://t.test/a", config(spoof_ip=True)))[0]
    chain = headers["X-Forwarded-For"].split(", ")
    assert len(chain) == 3
    assert len(set(chain)) == 3
    assert headers["X-Real-IP"] == chain[0]
    assert headers["True-Client-IP"] == chain[0]


async def test_spoofed_ip_excludes_private_and_loopback_ranges() -> None:
    # These are the ranges `_generate_random_ip` actually rejects, so this
    # assertion holds for every draw and cannot flake.
    blocked = [
        ipaddress.ip_network(n)
        for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
    ]
    for _ in range(200):
        headers = (await apply_evasion({}, "https://t.test/a", config(spoof_ip=True)))[0]
        for value in headers["X-Forwarded-For"].split(", "):
            addr = ipaddress.ip_address(value)
            assert not any(addr in net for net in blocked), f"{value} is a private/loopback address"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN DEFECT, not fixed in Phase 1a. `_generate_random_ip` rejects only "
        "127/8, 10/8, 172.16/12, 192.168/16 and 169.254/16, so it can still emit "
        "CGNAT (100.64/10, RFC 6598), the TEST-NET documentation ranges "
        "(192.0.2/24, 198.51.100/24, 203.0.113/24) and 198.18/15 benchmarking "
        "space. Those are not globally routable, which makes the X-Forwarded-For "
        "chain look synthetic to precisely the WAFs the header exists to satisfy. "
        "Seeded so the assertion is reproducible rather than a coin flip. Recorded "
        "in ARCHITECTURE.md; the fix is a behaviour change for a later commit. "
        "strict=True so that fixing it forces this marker off."
    ),
)
def test_spoofed_ip_is_never_special_use_space() -> None:
    random.seed(20261013)
    for _ in range(20000):
        assert ipaddress.ip_address(_generate_random_ip()).is_global


async def test_cache_buster_is_added_and_other_params_survive() -> None:
    _h, url, _c, _m, _b = await apply_evasion(
        {}, "https://t.test/a?page=2&q=x", config(cache_busting=True)
    )
    query = parse_qs(urlparse(url).query)
    assert "_cb" in query
    assert query["page"] == ["2"]
    assert query["q"] == ["x"]


async def test_cache_busting_varies_between_calls() -> None:
    _h, url, _c, _m, _b = await apply_evasion({}, "https://t.test/a", config(cache_busting=True))
    _h, url2, _c, _m, _b = await apply_evasion({}, "https://t.test/a", config(cache_busting=True))
    assert url != url2


async def test_path_is_never_rewritten() -> None:
    _h, url, _c, _m, _b = await apply_evasion(
        {}, "https://t.test/api/users/42/orders?x=1", config(cache_busting=True)
    )
    assert urlparse(url).path == "/api/users/42/orders"


async def test_polymorphism_preserves_the_payload_meaning() -> None:
    import json

    body = {"username": "admin", "role": "root", "id": "abc", "debug": True}
    for _ in range(100):
        _h, _u, _c, _m, out_body = await apply_evasion(
            {}, "https://t.test/a", config(polymorphic=True), "POST", dict(body)
        )
        assert json.loads(out_body) == body


async def test_non_json_string_body_is_left_alone() -> None:
    raw = "id=42&action=delete"
    _h, _u, _c, _m, out_body = await apply_evasion(
        {}, "https://t.test/a", config(polymorphic=True), "POST", raw
    )
    assert out_body == raw


async def test_all_evasion_off_leaves_the_request_untouched() -> None:
    """With every mutation off and a UA already present, nothing may change."""
    headers = {"User-Agent": "keep-me", **SESSION_HEADERS}
    original = dict(headers)
    out_headers, url, ciphers, method, body = await apply_evasion(
        dict(headers), "https://t.test/a?x=1", config(rotate_user_agent=False), "GET", None
    )
    assert out_headers == original
    assert url == "https://t.test/a?x=1"
    assert ciphers is None
    assert method == "GET"
    assert body is None


async def test_zero_delays_do_not_sleep() -> None:
    """Guards the slow-suite failure mode from HANDOFF.md rule 5."""
    import time

    started = time.monotonic()
    await apply_evasion({}, "https://t.test/a", config(random_delay_min=0.0, random_delay_max=0.0))
    assert time.monotonic() - started < 0.5


def test_rotation_without_config_is_a_no_op() -> None:
    original = {"Authorization": "Bearer t"}
    assert rotate_evasion_headers(original, None) is original
