"""WAF Behavioral Mapper — probes the target to map rate-limit and blocking thresholds."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

class WAFThresholds:
    def __init__(self, max_rps: float, burst_limit: int, block_duration: float):
        self.max_rps = max_rps
        self.burst_limit = burst_limit
        self.block_duration = block_duration

class WAFMapper:
    """Probes a known public endpoint to find the WAF's breaking point."""

    def __init__(self, base_url: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.public_path = "/favicon.ico" # Usually public and lightweight
        self.results: list[dict[str, Any]] = []

    async def map_thresholds(self) -> WAFThresholds:
        """
        Incrementally increases RPS until a 429 or 403 block is detected.
        """
        logger.info("WAFMapper: Starting behavioral threshold mapping on %s", self.base_url)

        current_rps = 1.0
        step = 2.0
        max_test_rps = 50.0

        while current_rps <= max_test_rps:
            logger.debug("WAFMapper: Testing threshold at %.1f RPS...", current_rps)

            success_rate = await self._test_at_rps(current_rps)
            if success_rate < 0.9: # Significant block detected
                logger.warning("WAFMapper: Block detected at %.1f RPS (Success Rate: %.2f)", current_rps, success_rate)
                return WAFThresholds(max_rps=current_rps * 0.8, burst_limit=int(current_rps * 2), block_duration=60.0)

            current_rps += step

        return WAFThresholds(max_rps=max_test_rps, burst_limit=100, block_duration=0.0)

    async def _test_at_rps(self, rps: float, duration: float = 5.0) -> float:
        """Sends requests for a duration and calculates success rate."""
        total_requests = int(rps * duration)
        delay = 1.0 / rps

        successes = 0
        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            for _ in range(total_requests):
                try:
                    res = await client.request("GET", f"{self.base_url}{self.public_path}")
                    if res.status_code in (429, 403):
                        return 0.0
                    successes += 1
                except Exception as e:
                    logger.debug("WAF probe request failed: %s", e)
                    pass
                await asyncio.sleep(delay)

        return successes / total_requests if total_requests > 0 else 1.0
