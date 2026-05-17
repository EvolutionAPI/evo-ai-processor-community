"""Smoke test verifying the runner-side wiring of extension points.

The full runner cannot be exercised in a unit test (it requires google.adk,
a database session and an LLM client). This smoke test reproduces the
hook call sites the runner uses and verifies the override path works
end-to-end against the same call shape.
"""

from __future__ import annotations

import pytest

from src import evo_extension_points
from src.evo_extension_points import (
    ExecutionMetrics,
    capability_gate,
    runtime_context,
    usage_reporter,
)


@pytest.fixture(autouse=True)
def _reset_registry():
    evo_extension_points.reset()
    yield
    evo_extension_points.reset()


def _simulate_runner_hooks(metadata: dict | None) -> dict:
    """Mirror the three hook call sites used in standard_runner.run_agent."""
    capability = (metadata or {}).get("capability")
    if capability and not capability_gate.is_enabled(capability, context=metadata):
        return {"skipped": True, "context_id": None, "reported": False}

    context_id = runtime_context.current_context_id(metadata)

    reported_metrics: list[ExecutionMetrics] = []
    try:
        usage_reporter.report_execution(
            ExecutionMetrics(
                execution_id="adk-session-1",
                prompt_tokens=10,
                candidate_tokens=20,
                total_tokens=30,
                cost=0.0,
            )
        )
        reported = True
    except Exception:
        reported = False
        reported_metrics.clear()

    return {
        "skipped": False,
        "context_id": context_id,
        "reported": reported,
        "reported_metrics": reported_metrics,
    }


class TestRunnerSmokeWithDefaults:
    def test_defaults_do_not_block_execution(self):
        result = _simulate_runner_hooks({"capability": "vision"})
        assert result == {
            "skipped": False,
            "context_id": None,
            "reported": True,
            "reported_metrics": [],
        }

    def test_no_metadata_is_safe(self):
        result = _simulate_runner_hooks(None)
        assert result["skipped"] is False
        assert result["context_id"] is None
        assert result["reported"] is True


class TestRunnerSmokeWithOverrides:
    def test_capability_disabled_short_circuits(self):
        class DenyGate:
            def is_enabled(self, capability, *, context=None):
                return False

        evo_extension_points.replace("capability_gate", DenyGate())
        result = _simulate_runner_hooks({"capability": "blocked"})
        assert result["skipped"] is True

    def test_runtime_context_resolves_id(self):
        class IdFromMetadata:
            def current_context_id(self, source):
                if isinstance(source, dict):
                    return source.get("operational_context")
                return None

            def with_context(self, context_id, callable):
                return callable()

        evo_extension_points.replace("runtime_context", IdFromMetadata())
        result = _simulate_runner_hooks(
            {"capability": "vision", "operational_context": "ctx-77"}
        )
        assert result["context_id"] == "ctx-77"

    def test_usage_reporter_receives_metrics(self):
        seen: list[ExecutionMetrics] = []

        class Reporter:
            def report_execution(self, metrics):
                seen.append(metrics)

        evo_extension_points.replace("usage_reporter", Reporter())
        _simulate_runner_hooks({})
        assert len(seen) == 1
        assert seen[0].execution_id == "adk-session-1"
        assert seen[0].total_tokens == 30
