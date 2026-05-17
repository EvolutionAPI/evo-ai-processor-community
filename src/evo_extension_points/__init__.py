"""Public extension contract of evo-ai-processor-community.

See ``EXTENSION_POINTS.md`` at the repository root for the full contract.
Each extension point is versioned independently via its own ``VERSION``
attribute; there is no aggregate version constant.
"""

from __future__ import annotations

from . import capability_gate, runtime_context, usage_reporter
from .registry import KNOWN_KEYS, impl_for, replace, reset
from .usage_reporter import ExecutionMetrics

__all__ = [
    "ExecutionMetrics",
    "KNOWN_KEYS",
    "capability_gate",
    "impl_for",
    "replace",
    "reset",
    "runtime_context",
    "usage_reporter",
]
