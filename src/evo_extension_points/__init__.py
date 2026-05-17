"""Public extension contract of evo-ai-processor-community.

See EXTENSION_POINTS.md at the repository root for the full contract.
The three sub-modules under this package ship no-op defaults; an
external consumer overrides a specific extension point at process start
via ``evo_extension_points.replace(name, impl)``.
"""

from __future__ import annotations

from .registry import (
    KNOWN_KEYS,
    UnknownExtensionPoint,
    impl_for,
    replace,
    reset,
)
from .usage_reporter import ExecutionMetrics

from . import capability_gate, runtime_context, usage_reporter

EXTENSION_POINTS_VERSION = "1.0.0"

__all__ = [
    "EXTENSION_POINTS_VERSION",
    "ExecutionMetrics",
    "KNOWN_KEYS",
    "UnknownExtensionPoint",
    "capability_gate",
    "impl_for",
    "replace",
    "reset",
    "runtime_context",
    "usage_reporter",
]
