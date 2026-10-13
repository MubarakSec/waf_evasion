from __future__ import annotations

import asyncio
import json
import logging
import random
import uuid
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from evasion._net import _generate_random_ip
from evasion.polymorphic import PolymorphicTransformer

logger = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

async def apply_evasion(headers: dict, url: str, config: Any, method: str = "GET", body: Any = None) -> tuple[dict, str, list[str] | None, str, Any]:
    """Applies Chameleon Engine, IP spoofing, random delays, cache busting, and polymorphism."""
    ciphers = None

    # 1. Device Profile (User-Agent/Ciphers/Header Shuffling)
    if config and getattr(config, "rotate_user_agent", True):
        from evasion.chameleon import ChameleonEngine
        shuffle = getattr(config, "shuffle_headers", True)
        randomize_case = getattr(config, "randomize_header_case", False)
        headers, ciphers = ChameleonEngine.apply_profile(headers, shuffle=shuffle, randomize_case=randomize_case)
    elif "User-Agent" not in headers:
        headers["User-Agent"] = USER_AGENTS[0]

    # 2. IP Spoofing
    if config and getattr(config, "spoof_ip", False):
        # Finding 13: Randomize headers and vary IPs
        ip = _generate_random_ip()
        core_spoof_headers = ["X-Forwarded-For", "X-Real-IP", "True-Client-IP"]
        extra_spoof_headers = ["Client-IP", "X-Client-IP"]

        # Always set core spoof headers
        for h_name in core_spoof_headers:
            if h_name == "X-Forwarded-For":
                chain = [ip, _generate_random_ip(), _generate_random_ip()]
                headers[h_name] = ", ".join(chain)
            else:
                headers[h_name] = ip

        # Optionally add extra randomized headers
        selected_extra = random.sample(extra_spoof_headers, k=random.randint(0, len(extra_spoof_headers)))
        for h_name in selected_extra:
            headers[h_name] = ip


    # 3. Cache Busting
    if config and getattr(config, "cache_busting", False):
        url = _add_cache_buster(url)
    elif config and getattr(config, "orcha_infra_hints", None):
        # Trio harmony: if infra hints (cache/waf/smuggling from Orcha), force cache bust + polymorphism
        # to increase chance of hitting infra-vulnerable paths (internal enhancement)
        hints = getattr(config, "orcha_infra_hints", []) or []
        if any(h in hints for h in ("cache", "waf", "smuggling", "host")):
            url = _add_cache_buster(url)

    # 4. Request Polymorphism
    if config and getattr(config, "polymorphic", False):
        transformer = PolymorphicTransformer()
        # Method Override
        method, headers = transformer.apply_method_override(method, headers)

        # Body Polymorphism
        if body and isinstance(body, dict):
            body = transformer.mutate_json(body)
        elif body and isinstance(body, str):
            try:
                # Try to parse as JSON for mutation
                js_body = json.loads(body)
                if isinstance(js_body, dict):
                    body = transformer.mutate_json(js_body)
            except Exception as e:
                logger.debug("JSON body evasion failed: %s", e)
    elif config and getattr(config, "orcha_infra_hints", None):
        hints = getattr(config, "orcha_infra_hints", []) or []
        if any(h in hints for h in ("waf", "smuggling", "cache")):
            # Infra harmony: enable polymorphism for evasion when Orcha indicates infra surface
            transformer = PolymorphicTransformer()
            method, headers = transformer.apply_method_override(method, headers)

    # 5. Timing (Sleep last to simulate real user delay before sending)
    if config and getattr(config, "random_delay_max", 0) > 0:
        delay = random.uniform(config.random_delay_min, config.random_delay_max)
        if delay > 0: await asyncio.sleep(delay)

    return headers, url, ciphers, method, body

def _add_cache_buster(url: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query["_cb"] = [str(uuid.uuid4())[:8]]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def rotate_evasion_headers(headers: dict, config: Any) -> dict:
    """Rotates IP spoofing, client headers, and browser profiles dynamically across retries."""
    if not config:
        return headers

    if getattr(config, "spoof_ip", False):
        ip = _generate_random_ip()
        headers["X-Forwarded-For"] = f"{ip}, {_generate_random_ip()}, {_generate_random_ip()}"
        headers["X-Real-IP"] = ip
        headers["True-Client-IP"] = ip
        headers["CF-Connecting-IP"] = ip
        headers["X-Originating-IP"] = ip
        headers["X-Client-IP"] = ip

    if getattr(config, "rotate_user_agent", False):
        from evasion.chameleon import ChameleonEngine
        shuffle = getattr(config, "shuffle_headers", True)
        randomize_case = getattr(config, "randomize_header_case", False)
        headers, _ = ChameleonEngine.apply_profile(headers, shuffle=shuffle, randomize_case=randomize_case)

    return headers

