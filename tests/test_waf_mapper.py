"""Tests for WAF-aware rate calibration.

`WAFMapper` is the one component here that actively probes a target, so its
negative tests carry extra weight: a false "block" here caps the scan at a rate
far below what the target tolerates and silently turns a thorough scan into a
token one. The clean-target case must come back as "no block found", full stop.
"""

from __future__ import annotations

import httpx
import pytest

from evasion.waf_mapper import WAFMapper

# Capture the real class BEFORE patching. AGENTS.md rule 2: a factory that calls
# the patched httpx.AsyncClient recurses to death.
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def patch_transport(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    def factory(**kwargs: object) -> httpx.AsyncClient:
        kwargs.pop("verify", None)  # MockTransport does not use it
        return _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def test_base_url_is_normalised() -> None:
    assert WAFMapper("https://t.test/").base_url == "https://t.test"
    assert WAFMapper("https://t.test").public_path == "/favicon.ico"


# --- negative: a clean target must never register as blocked -----------------


async def test_clean_target_is_never_reported_as_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_transport(monkeypatch, lambda request: httpx.Response(200, text="icon"))
    mapper = WAFMapper("https://t.test")
    assert await mapper._test_at_rps(20.0, duration=0.25) == 1.0


@pytest.mark.parametrize("status", [200, 204, 301, 302, 404, 500, 502])
async def test_non_blocking_statuses_count_as_success(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    patch_transport(monkeypatch, lambda request: httpx.Response(status))
    mapper = WAFMapper("https://t.test")
    assert await mapper._test_at_rps(20.0, duration=0.25) == 1.0


async def test_zero_requests_is_vacuously_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guards the divide-by-zero path: int(rps * duration) can round down to 0."""
    patch_transport(monkeypatch, lambda request: httpx.Response(200))
    mapper = WAFMapper("https://t.test")
    assert await mapper._test_at_rps(1.0, duration=0.001) == 1.0


# --- positive: a genuine block is detected -----------------------------------


@pytest.mark.parametrize("status", [429, 403])
async def test_blocking_statuses_are_detected(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    patch_transport(monkeypatch, lambda request: httpx.Response(status))
    mapper = WAFMapper("https://t.test")
    assert await mapper._test_at_rps(20.0, duration=0.25) == 0.0


async def test_transport_errors_count_as_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    patch_transport(monkeypatch, boom)
    mapper = WAFMapper("https://t.test")
    rate = await mapper._test_at_rps(20.0, duration=0.25)
    assert rate < 1.0


# --- threshold arithmetic ----------------------------------------------------


async def test_map_thresholds_backs_off_below_the_blocking_rate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mapper = WAFMapper("https://t.test")
    seen: list[float] = []

    async def fake_test_at_rps(rps: float, duration: float = 5.0) -> float:
        seen.append(rps)
        return 0.0 if rps >= 5.0 else 1.0

    monkeypatch.setattr(mapper, "_test_at_rps", fake_test_at_rps)
    thresholds = await mapper.map_thresholds()

    assert seen == [1.0, 3.0, 5.0], "step must stay at 2.0 starting from 1.0"
    assert thresholds.max_rps == pytest.approx(4.0)  # 5.0 * 0.8 safety margin
    assert thresholds.burst_limit == 10
    assert thresholds.block_duration == 60.0


async def test_map_thresholds_keeps_the_ceiling_when_nothing_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mapper = WAFMapper("https://t.test")

    async def fake_test_at_rps(rps: float, duration: float = 5.0) -> float:
        return 1.0

    monkeypatch.setattr(mapper, "_test_at_rps", fake_test_at_rps)
    thresholds = await mapper.map_thresholds()

    assert thresholds.max_rps == 50.0
    assert thresholds.burst_limit == 100
    assert thresholds.block_duration == 0.0


async def test_partial_failure_is_not_treated_as_a_block(monkeypatch: pytest.MonkeyPatch) -> None:
    """The block threshold is success_rate < 0.9; 0.9 must not trip it."""
    mapper = WAFMapper("https://t.test")
    states = iter([1.0, 1.0, 0.9, 0.9, 0.9, 0.9, 0.9, 0.9, 0.9, 0.9])

    async def fake_test_at_rps(rps: float, duration: float = 5.0) -> float:
        return next(states, 0.9)

    monkeypatch.setattr(mapper, "_test_at_rps", fake_test_at_rps)
    thresholds = await mapper.map_thresholds()

    assert thresholds.max_rps == 50.0, "a 0.9 success rate must not be read as a block"
    assert thresholds.block_duration == 0.0
