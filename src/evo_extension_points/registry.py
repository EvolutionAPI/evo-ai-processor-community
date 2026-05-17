"""In-memory override registry shared by the three extension points."""

from __future__ import annotations

from typing import Any, Final

KNOWN_KEYS: Final[frozenset[str]] = frozenset(
    {"capability_gate", "runtime_context", "usage_reporter"}
)


class UnknownExtensionPoint(ValueError):
    """Raised when ``replace`` is called with an unknown extension point key."""


_registry: dict[str, Any] = {}


def replace(key: str, impl: Any) -> Any:
    if key not in KNOWN_KEYS:
        raise UnknownExtensionPoint(f"unknown extension point: {key!r}")
    _registry[key] = impl
    return impl


def impl_for(key: str) -> Any | None:
    return _registry.get(key)


def reset() -> None:
    _registry.clear()
