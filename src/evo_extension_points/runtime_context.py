"""RuntimeContext extension point.

Community default: ``current_context_id`` returns ``None``; ``with_context``
yields the callable's result without binding any state. The default
implementation accepts any mapping (FastAPI ``Request``, plain ``dict``
or ``None``); consumers that need request-level resolution can read
headers, cookies, or any other neutral signal in their override.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Protocol, TypeVar, runtime_checkable

from .registry import impl_for

T = TypeVar("T")


@runtime_checkable
class RuntimeContext(Protocol):
    def current_context_id(self, source: Any) -> str | None: ...

    def with_context(self, context_id: str, callable: Callable[[], T]) -> T: ...


class _DefaultRuntimeContext:
    def current_context_id(self, source: Any) -> str | None:
        return None

    def with_context(self, context_id: str, callable: Callable[[], T]) -> T:
        return callable()


_DEFAULT = _DefaultRuntimeContext()


def current_context_id(source: Mapping[str, Any] | Any | None = None) -> str | None:
    impl = impl_for("runtime_context") or _DEFAULT
    return impl.current_context_id(source)


def with_context(context_id: str, callable: Callable[[], T]) -> T:
    impl = impl_for("runtime_context") or _DEFAULT
    return impl.with_context(context_id, callable)
