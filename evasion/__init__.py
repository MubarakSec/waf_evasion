"""Adaptive WAF detection and evasion.

Extracts and generalises what already exists in the family:
  acscan/engine/replay/evasion.py        device profile, cache busting, timing
  acscan/engine/replay/polymorphic.py    request polymorphism
  acscan/engine/waf_mapper.py            WAF-aware rate calibration
  acscan/engine/pipeline/executor/waf.py is_waf_blocked()

The gap those four do not close: detection is passive and evasion is blind.
`is_waf_blocked()` returns a bool and the executor pauses; `apply_evasion()`
fires pre-emptively and identically whether or not a WAF exists. Nothing
connects a block to a change in the next request.

This package closes that loop.
"""

__all__ = [
    "USER_AGENTS",
    "ChameleonEngine",
    "PolymorphicTransformer",
    "WAFMapper",
    "WAFThresholds",
    "__version__",
    "apply_evasion",
    "is_waf_blocked",
    "rotate_evasion_headers",
]
__version__ = "0.1.0"

# Re-exported via __all__ rather than per-name F401 suppressions. HANDOFF.md
# records two rounds of RUF100 deleting block-level suppressions and then F401
# deleting the re-exports themselves; declaring __all__ makes the suppression
# unnecessary in the first place, so no autofix can remove it.
#
# Note: do not spell a noqa directive out in this comment. Ruff parses any
# comment line for directives, so a literal `noqa` token here is read as a real
# one and emits "Invalid noqa directive" on every run.
from evasion.chameleon import ChameleonEngine
from evasion.detect import is_waf_blocked
from evasion.evade import USER_AGENTS, apply_evasion, rotate_evasion_headers
from evasion.polymorphic import PolymorphicTransformer
from evasion.waf_mapper import WAFMapper, WAFThresholds
