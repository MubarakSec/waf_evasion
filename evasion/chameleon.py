"""Chameleon Service — performs TLS fingerprint and header randomization."""
from __future__ import annotations

import logging
import random
from typing import Any

logger = logging.getLogger(__name__)

# Representative User-Agents for different browser/OS combos
CHAMELEON_PROFILES = [
    {
        "name": "Chrome-Win10",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "headers": {
            "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "upgrade-insecure-requests": "1",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        },
        "ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
    },
    {
        "name": "Firefox-Linux",
        "ua": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "headers": {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
            "upgrade-insecure-requests": "1",
        },
        "ciphers": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    },
    {
        "name": "Safari-MacOS",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "headers": {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-GB,en;q=0.9",
        },
        "ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    },
    {
        "name": "iPhone-Safari",
        "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        "headers": {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "X-Requested-With": "com.apple.mobilesafari"
        },
        "ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    },
    {
        "name": "Android-Chrome-App",
        "ua": "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro Build/UQ1A.240205.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36",
        "headers": {
            "X-Requested-With": "com.android.chrome",
            "sec-ch-ua-platform": '"Android"',
            "sec-ch-ua-mobile": "?1"
        },
        "ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305"
    },
    {
        "name": "Mobile-Legacy-API",
        "ua": "TargetApp/2.4.1 (com.target.app; build:42; iOS 15.1.0) Alamofire/5.4.4",
        "headers": {
            "X-App-Version": "2.4.1",
            "X-OS-Version": "15.1.0",
            "X-Device-Model": "iPhone13,4",
        },
        "ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    }
]

class ChameleonEngine:
    """Randomizes request identities to bypass TLS and UA fingerprinting."""

    @staticmethod
    def apply_profile(headers: dict[str, str], shuffle: bool = True, randomize_case: bool = False) -> tuple[dict[str, str], str | None]:
        """Randomly selects a profile and returns mutated headers and preferred ciphers."""
        profile = random.choice(CHAMELEON_PROFILES)
        new_headers = {}

        # 1. Base Headers from Profile
        profile_headers = profile["headers"].copy()
        profile_headers["User-Agent"] = profile["ua"]

        # 2. Merge Original Headers (keep auth/session intact)
        for k, v in headers.items():
            kl = k.lower()
            if kl in ("authorization", "cookie", "x-ac-role") or not any(pk.lower() == kl for pk in profile_headers):
                new_headers[k] = v

        # Add profile specifics
        for pk, pv in profile_headers.items():
            if not any(k.lower() == pk.lower() for k in new_headers):
                new_headers[pk] = pv

        # 3. Optional: Randomize Case
        if randomize_case:
            new_headers = {ChameleonEngine._randomize_case(k): v for k, v in new_headers.items()}

        # 4. Optional: Shuffle Order (returns a list of tuples to preserve order)
        # Note: dict in Python 3.7+ is ordered, so we can just re-insert
        if shuffle:
            items = list(new_headers.items())
            random.shuffle(items)
            new_headers = dict(items)

        return new_headers, profile.get("ciphers")

    @staticmethod
    def _randomize_case(s: str) -> str:
        """Randomly changes the case of characters in a string (e.g. User-Agent -> user-Agent)."""
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    @staticmethod
    def get_ja3_context(ciphers: str | None = None) -> Any:
        """
        Generates a custom SSL context to spoof browser TLS fingerprints.
        """
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        if ciphers:
            try:
                context.set_ciphers(ciphers)
            except Exception as e:
                logger.debug("Chameleon: Failed to set custom ciphers: %s", e)

        # Additional TLS 1.3 settings if supported by the environment
        if hasattr(ssl, "OP_NO_TLSv1") and hasattr(ssl, "OP_NO_TLSv1_1"):
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        return context
