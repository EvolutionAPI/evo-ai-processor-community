"""UsageReporter extension point.

Community default: no-op. The processor already persists execution
metrics locally; the reporter is the public surface that an external
consumer can subscribe to without patching the runner. A consumer
overrides via ``evo_extension_points.replace("usage_reporter", impl)``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .registry import impl_for


@dataclass(frozen=True)
class ExecutionMetrics:
    execution_id: str
    prompt_tokens: int
    candidate_tokens: int
    total_tokens: int
    cost: float


@runtime_checkable
class UsageReporter(Protocol):
    def report_execution(self, metrics: ExecutionMetrics) -> None: ...


class _DefaultUsageReporter:
    def report_execution(self, metrics: ExecutionMetrics) -> None:
        return None


_DEFAULT = _DefaultUsageReporter()


def report_execution(metrics: ExecutionMetrics) -> None:
    impl = impl_for("usage_reporter") or _DEFAULT
    impl.report_execution(metrics)
