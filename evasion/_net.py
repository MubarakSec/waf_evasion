"""Network helpers used by the request-mutation path.

`_generate_random_ip` moved verbatim from acscan
`acscan/engine/replay/utils.py:46`. It had exactly one consumer --
`replay/evasion.py` -- so it came across with the code that needs it rather
than staying behind in acscan. Body unchanged.
"""

from __future__ import annotations

import random

def _generate_random_ip() -> str:
    """Generate a random IP address, avoiding reserved/special ranges."""
    while True:
        first = random.randint(1, 223)
        second, third, fourth = [random.randint(0, 255) for _ in range(3)]
        ip = f"{first}.{second}.{third}.{fourth}"
        if first in (127, 10): continue
        if first == 172 and 16 <= second <= 31: continue
        if first == 192 and second == 168: continue
        if first == 169 and second == 254: continue
        return ip
