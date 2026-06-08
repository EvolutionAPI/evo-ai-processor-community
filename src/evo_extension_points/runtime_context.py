"""RuntimeContext extension point.

Community default: ``current_context_id`` returns ``None``;
``with_context`` yields the callable's result without binding any state
(single-scope mode); ``bind_context`` returns a no-op async context
manager so consumers can wire per-request context binding without the
community having to know what binding means.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Callable, Protocol, TypeVar, runtime_checkable

from . import registry

VERSION: str = "1.1.0"

T = TypeVar("T")


@runtime_checkable
class RuntimeContext(Protocol):
    def current_context_id(self, source: Any) -> str | None: ...

    def with_context(self, context_id: str, fn: Callable[[], T]) -> T: ...


class _DefaultRuntimeContext:
    def current_context_id(self, source: Any) -> str | None:
        return None

    def with_context(self, context_id: str, fn: Callable[[], T]) -> T:
        return fn()


_DEFAULT = _DefaultRuntimeContext()
registry._register_protocol("runtime_context", RuntimeContext)


@asynccontextmanager
async def _null_bind(_context_id: str) -> AsyncIterator[None]:
    yield


def current_context_id(source: Any = None) -> str | None:
    impl = registry.impl_for("runtime_context") or _DEFAULT
    return impl.current_context_id(source)


def with_context(context_id: str, fn: Callable[[], T]) -> T:
    impl = registry.impl_for("runtime_context") or _DEFAULT
    return impl.with_context(context_id, fn)


def bind_context(context_id: str):
    """Return an async context manager that binds ``context_id`` for the
    enclosed scope.

    Optional EP method (added in 1.1.0). The community default is a no-op
    async CM; consumers may expose a ``bind_context(context_id)``
    method on their impl to participate. Callers must use ``async with``.
    """
    impl = registry.impl_for("runtime_context") or _DEFAULT
    bind = getattr(impl, "bind_context", None)
    if bind is None:
        return _null_bind(context_id)
    return bind(context_id)
