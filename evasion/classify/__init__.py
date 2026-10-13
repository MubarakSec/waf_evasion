"""WAF fingerprinting from a response.

Public surface is re-exported here rather than imported as `classify.classify`
by callers, so the package has one obvious entry point.
"""

from evasion.classify.classify import (
    CONFIDENT,
    SIGNATURES,
    SUGGESTED,
    UNKNOWN,
    Classification,
    classify,
)

__all__ = [
    "CONFIDENT",
    "SIGNATURES",
    "SUGGESTED",
    "UNKNOWN",
    "Classification",
    "classify",
]
