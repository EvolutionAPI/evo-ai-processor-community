# Extension Points

**Contract version:** `1.0.0` (SemVer)

This document is the public contract between `evo-ai-processor-community`
and any external consumer that wants to plug into agent execution
without forking or patching community source. The authoritative
architectural decision behind this contract is **ADR13 — Extension
Points Versioning Strategy**; the rules below are self-contained.

The community release is fully usable on its own. Every extension point
ships with a working default; a consumer can **replace** the default
implementation of one or more of them without modifying files in `src/`,
`migrations/` or `tests/`.

If you are about to change any of the three extension points below, read
the [Compatibility Promise](#compatibility-promise) first.

---

## Compatibility Promise

Each extension point is versioned independently and treated as a public
API, with the same backward-compatibility rules as the HTTP endpoints
exposed by this service:

- **Backward compatibility is forever.** Once shipped at a given major,
  the name, arguments, return shape and observable behavior of an
  extension point do not change silently.
- **Breaking changes require a major bump** of the affected extension
  point and of the community release that ships it.
- **Deprecation window is at least one minor release.** The old shape
  keeps working alongside the new one, and the deprecated path emits a
  `DeprecationWarning` via `warnings.warn`.
- **Additive changes are minor bumps.** New extension point, or new
  optional capability on an existing one.
- **Bug fixes that preserve the contract are patch bumps.**

Bumping one extension point does not bump the others.

---

## Extension points

All three are exposed under the `evo_extension_points` package,
implemented by `src/evo_extension_points/` (shipped in a complementary
story). Contracts are declared as `typing.Protocol` so that consumers
get static type checking without inheritance. The aggregate contract
version is exposed at `evo_extension_points.EXTENSION_POINTS_VERSION`.

### 1. `capability_gate`

**Version:** `1.0.0`
**Default:** always returns `True`; the community release does not
filter capabilities.

```python
from typing import Protocol

class CapabilityGate(Protocol):
    def is_enabled(self, capability: str, *, context: dict | None = None) -> bool: ...
```

Default access:

```python
from evo_extension_points import capability_gate

capability_gate.is_enabled("vision", context={"model": "gpt-4o"})  # => True
```

Override:

```python
import evo_extension_points

class MyCapabilityGate:
    def is_enabled(self, capability: str, *, context: dict | None = None) -> bool:
        return my_consumer.capabilities.enabled(capability, context=context)

evo_extension_points.replace("capability_gate", MyCapabilityGate())
```

**Breaking-change policy:** renaming `is_enabled`, adding a required
positional argument, or changing the return type from `bool` is a major
bump. Adding a new key to `context` or a new accepted `capability`
string is a minor bump.

### 2. `runtime_context`

**Version:** `1.0.0`
**Default:** `current_context_id` returns `None`; `with_context` yields
the callable's result without binding any state (single-scope mode).

```python
from typing import Any, Protocol, Callable, TypeVar

T = TypeVar("T")

class RuntimeContext(Protocol):
    def current_context_id(self, source: Any) -> str | None: ...
    def with_context(self, context_id: str, callable: Callable[[], T]) -> T: ...
```

`source` is whatever the processor passes in at the call site — at the
agent-execution call site it is the request `metadata` dictionary, but
the contract accepts any object so a consumer can also be invoked with
a FastAPI `Request`, a plain mapping or `None`. The default
implementation reads nothing from `source` and binds no state;
consumers wire their own resolution from a neutral signal such as the
`X-Operational-Context` header or a `metadata["operational_context"]`
key.

Override:

```python
import evo_extension_points
from my_consumer import current_context

class MyRuntimeContext:
    def current_context_id(self, source) -> str | None:
        if isinstance(source, dict):
            return source.get("operational_context")
        if hasattr(source, "headers"):
            return source.headers.get("X-Operational-Context")
        return None

    def with_context(self, context_id, callable):
        with current_context.bound(context_id):
            return callable()

evo_extension_points.replace("runtime_context", MyRuntimeContext())
```

**Breaking-change policy:** renaming `current_context_id` /
`with_context`, or changing the return type of `current_context_id`
from `str | None`, is a major bump. Adding sibling helpers is a minor
bump.

### 3. `usage_reporter`

**Version:** `1.0.0`
**Default:** no-op; the community release already persists
`evo_agent_processor_execution_metrics` locally and calls the reporter
once with the same data, allowing external observability to mirror what
is already written in the local table.

```python
from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class ExecutionMetrics:
    execution_id: str
    prompt_tokens: int
    candidate_tokens: int
    total_tokens: int
    cost: float

class UsageReporter(Protocol):
    def report_execution(self, metrics: ExecutionMetrics) -> None: ...
```

`execution_id` is the neutral identifier of the agent execution emitted
by the processor; consumers correlate it back to their own systems.
`cost` is the monetary value (`float`) already computed by the processor
in its base currency.

The default implementation is a no-op. The processor invokes
`report_execution` synchronously after each execution finishes; a
consumer that needs asynchronous fan-out is expected to enqueue inside
its own override.

Override:

```python
import evo_extension_points
from evo_extension_points import ExecutionMetrics

class MyUsageReporter:
    def report_execution(self, metrics: ExecutionMetrics) -> None:
        my_consumer.metrics.publish(
            execution_id=metrics.execution_id,
            tokens=metrics.total_tokens,
            cost=metrics.cost,
        )

evo_extension_points.replace("usage_reporter", MyUsageReporter())
```

**Breaking-change policy:** renaming `report_execution`, removing or
retyping a field of `ExecutionMetrics`, or changing the call from
synchronous to asynchronous semantics is a major bump. Adding new
optional fields to `ExecutionMetrics` (with a sane default) is a minor
bump.

---

## How to use as a consumer

A consumer wires its replacements once, from its own bootstrap module,
and never patches files inside `evo-ai-processor-community`:

```python
import evo_extension_points
from evo_extension_points import ExecutionMetrics

class MyCapabilityGate:
    def is_enabled(self, capability: str, *, context: dict | None = None) -> bool:
        return my_consumer.capabilities.enabled(capability, context=context)

class MyRuntimeContext:
    def current_context_id(self, source) -> str | None:
        if isinstance(source, dict):
            return source.get("operational_context")
        if hasattr(source, "headers"):
            return source.headers.get("X-Operational-Context")
        return None

    def with_context(self, context_id, callable):
        with my_consumer.current_context.bound(context_id):
            return callable()

class MyUsageReporter:
    def report_execution(self, metrics: ExecutionMetrics) -> None:
        my_consumer.metrics.publish(
            execution_id=metrics.execution_id,
            tokens=metrics.total_tokens,
            cost=metrics.cost,
        )

def install_extension_points() -> None:
    evo_extension_points.replace("capability_gate", MyCapabilityGate())
    evo_extension_points.replace("runtime_context", MyRuntimeContext())
    evo_extension_points.replace("usage_reporter", MyUsageReporter())
```

A consumer is expected to declare the community version range it
supports in its own package metadata (`pyproject.toml`). A CI workflow
(`extension-points-contract`) runs a neutral consumer stub against
every community PR, failing the build on a contract break.

---

## Cross-references

- Companion contract on the CRM side:
  [evo-ai-crm-community/EXTENSION_POINTS.md](https://github.com/evolution-foundation/evo-ai-crm-community/blob/main/EXTENSION_POINTS.md).
- Companion contract on the auth-service side:
  [evo-auth-service-community/EXTENSION_POINTS.md](https://github.com/evolution-foundation/evo-auth-service-community/blob/main/EXTENSION_POINTS.md).
- The architectural decision that motivates this contract is **ADR13 —
  Extension Points Versioning Strategy**.

---

## Versioning history

- `1.0.0` — Initial contract: `CapabilityGate`, `RuntimeContext`,
  `UsageReporter`.
