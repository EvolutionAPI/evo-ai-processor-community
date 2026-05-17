"""Tests for the public extension point package (EVO-1382)."""

from __future__ import annotations

import pytest

from src import evo_extension_points
from src.evo_extension_points import (
    ExecutionMetrics,
    UnknownExtensionPoint,
    capability_gate,
    runtime_context,
    usage_reporter,
)


@pytest.fixture(autouse=True)
def _reset_registry():
    evo_extension_points.reset()
    yield
    evo_extension_points.reset()


class TestReplace:
    def test_rejects_unknown_extension_point(self):
        with pytest.raises(UnknownExtensionPoint):
            evo_extension_points.replace("not_a_thing", object())

    def test_stores_impl_for_known_key(self):
        sentinel = object()
        evo_extension_points.replace("capability_gate", sentinel)
        assert evo_extension_points.impl_for("capability_gate") is sentinel

    def test_reset_clears_overrides(self):
        evo_extension_points.replace("capability_gate", object())
        evo_extension_points.reset()
        assert evo_extension_points.impl_for("capability_gate") is None


class TestCapabilityGate:
    def test_default_returns_true_for_any_capability(self):
        assert capability_gate.is_enabled("vision") is True
        assert capability_gate.is_enabled("anything", context={"model": "x"}) is True

    def test_override_is_called(self):
        class Custom:
            def __init__(self):
                self.calls: list[tuple[str, dict | None]] = []

            def is_enabled(self, capability, *, context=None):
                self.calls.append((capability, context))
                return capability == "ok"

        custom = Custom()
        evo_extension_points.replace("capability_gate", custom)
        assert capability_gate.is_enabled("ok", context={"k": "v"}) is True
        assert capability_gate.is_enabled("other") is False
        assert custom.calls == [("ok", {"k": "v"}), ("other", None)]


class TestRuntimeContext:
    def test_default_current_context_id_returns_none(self):
        assert runtime_context.current_context_id() is None
        assert runtime_context.current_context_id({"X-Operational-Context": "abc"}) is None

    def test_default_with_context_yields_callable_result(self):
        called = []

        def work():
            called.append("ran")
            return "payload"

        result = runtime_context.with_context("ctx-1", work)
        assert result == "payload"
        assert called == ["ran"]

    def test_override_resolves_context_id_from_mapping(self):
        class Custom:
            def current_context_id(self, source):
                if isinstance(source, dict):
                    return source.get("X-Operational-Context")
                return None

            def with_context(self, context_id, callable):
                return f"{context_id}:{callable()}"

        evo_extension_points.replace("runtime_context", Custom())
        assert (
            runtime_context.current_context_id({"X-Operational-Context": "abc"})
            == "abc"
        )
        assert runtime_context.with_context("ctx-2", lambda: "done") == "ctx-2:done"


class TestUsageReporter:
    def test_default_is_noop_and_does_not_raise(self):
        metrics = ExecutionMetrics(
            execution_id="exec-1",
            prompt_tokens=10,
            candidate_tokens=20,
            total_tokens=30,
            cost=0.0,
        )
        assert usage_reporter.report_execution(metrics) is None

    def test_override_receives_metrics(self):
        seen: list[ExecutionMetrics] = []

        class Custom:
            def report_execution(self, metrics):
                seen.append(metrics)

        evo_extension_points.replace("usage_reporter", Custom())
        metrics = ExecutionMetrics(
            execution_id="exec-42",
            prompt_tokens=100,
            candidate_tokens=200,
            total_tokens=300,
            cost=1.23,
        )
        usage_reporter.report_execution(metrics)
        assert seen == [metrics]


class TestExecutionMetricsDataclass:
    def test_is_frozen(self):
        metrics = ExecutionMetrics(
            execution_id="exec-1",
            prompt_tokens=1,
            candidate_tokens=1,
            total_tokens=2,
            cost=0.0,
        )
        with pytest.raises(AttributeError):
            metrics.cost = 9.99  # type: ignore[misc]
