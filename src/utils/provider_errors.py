"""
Classify LLM-provider failures so the operator sees WHY a turn failed.

CRM-236: every exception raised while running an agent was funnelled into
`InternalServerError(str(e))` (standard_runner.py) and answered as a generic
`500 / -32603 Agent execution failed`. A quota exhaustion (429) and a genuine
bug in our code produced byte-identical responses, so the only way to find out
that the account had simply run out of free-tier requests was to open the
container logs.

This module reads the *cause chain* of an exception and, when it recognises a
provider-side condition, returns the status/code/message that should be sent
instead. Recognition is deliberately conservative: when nothing matches we
return None and the caller keeps the existing 500 behaviour.

Nothing here talks to a provider SDK — matching is done on the exception's
class name, its `status_code`/`code` attribute and its text, so it works for
litellm, google-genai, openai and anything else that follows the same
conventions, without importing any of them.
"""

import re
from dataclasses import dataclass
from typing import Any, List, Optional

from src.utils.logger import setup_logger

logger = setup_logger(__name__)

# How deep to walk __cause__/__context__. The runner wraps once
# (`raise InternalServerError(str(e)) from e`) and the SDKs may wrap once or
# twice more; 6 is comfortably beyond any real chain and bounds a cycle.
_MAX_CAUSE_DEPTH = 6


@dataclass(frozen=True)
class ProviderFailure:
    """A provider-side condition worth reporting verbatim to the operator."""

    kind: str  # rate_limit | unavailable | auth | context_length
    http_status: int
    # JSON-RPC reserves -32000..-32099 for implementation-defined server
    # errors, which is exactly what these are. -32603 (internal error) stays
    # reserved for failures that really are ours.
    jsonrpc_code: int
    message: str
    detail: str


# Secrets travel inside provider error strings more often than one would like:
# litellm echoes the request URL (`?key=AIza...`), and some SDKs include the
# Authorization header in the repr. `detail` is returned over the API, so it is
# redacted before it leaves this module.
_SECRET_PATTERNS = [
    # The optional quote BEFORE the separator matters: provider errors carry the
    # key both as a query string (`?key=AIza…`) and as JSON (`"api_key": "…"`),
    # and without it the closing quote of the JSON key blocks the match.
    re.compile(
        r"(?i)\b(api[_-]?key|key|token|access[_-]?token)[\"']?\s*[=:]\s*[\"']?([^\s\"'&,}]+)"
    ),
    re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]+=*)"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9\-_]{10,}"),
]


def redact_secrets(text: str) -> str:
    """Strip anything that looks like a credential out of provider text."""
    if not text:
        return ""
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(
            lambda m: m.group(0).replace(m.group(m.lastindex or 0), "[REDACTED]", 1),
            redacted,
        )
    return redacted


def _status_code_of(exc: BaseException) -> Optional[int]:
    """Best-effort HTTP status carried by an SDK exception."""
    for attribute in ("status_code", "http_status", "code"):
        value = getattr(exc, attribute, None)
        if isinstance(value, bool):
            continue
        if isinstance(value, int) and 100 <= value <= 599:
            return value
        # google-genai puts the numeric status in a string field
        if isinstance(value, str) and value.isdigit():
            number = int(value)
            if 100 <= number <= 599:
                return number
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, int) and 100 <= status <= 599:
        return status
    return None


def _cause_chain(exc: BaseException) -> List[BaseException]:
    """`exc` plus its __cause__/__context__ ancestors, de-duplicated."""
    chain: List[BaseException] = []
    seen = set()
    current: Optional[BaseException] = exc
    while current is not None and len(chain) < _MAX_CAUSE_DEPTH:
        if id(current) in seen:
            break
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


# Matched against the exception's class name AND its text, lowercased.
# Anchored on wording that only appears in provider errors — a bare "429" is
# NOT enough, since it also matches ids and token counts in unrelated messages.
_RATE_LIMIT_MARKERS = (
    "ratelimiterror",
    "rate_limit",
    "rate limit",
    "resource_exhausted",
    "resource exhausted",
    "resourceexhausted",
    "too many requests",
    "quota exceeded",
    "exceeded your current quota",
    "insufficient_quota",
)

# NOTE: no bare "timeout" and no "internalservererror" marker here. Our own
# wrapper is *named* InternalServerError and wraps every failure, so matching on
# it would classify genuine bugs in our code as provider outages. Likewise a
# bare "timeout" matches a database timeout just as well as a provider one.
_UNAVAILABLE_MARKERS = (
    "serviceunavailable",
    "service_unavailable",
    "service unavailable",
    "overloaded",
    "high demand",
    "apiconnectionerror",
    "apitimeouterror",
    "deadline_exceeded",
    "deadline exceeded",
)

_AUTH_MARKERS = (
    "authenticationerror",
    "permission_denied",
    "permissiondenied",
    "unauthenticated",
    "api key not valid",
    "invalid api key",
    "invalid_api_key",
    "api_key_invalid",
)

_CONTEXT_MARKERS = (
    "contextwindowexceeded",
    "context_length_exceeded",
    "maximum context length",
    "request payload size exceeds",
)


def _matches(haystack: str, markers) -> bool:
    return any(marker in haystack for marker in markers)


def classify_provider_error(exc: BaseException) -> Optional[ProviderFailure]:
    """Recognise a provider-side failure, or return None to keep the 500.

    Status codes win over text: an SDK that sets `status_code = 429` is stating
    the condition, whereas text matching is inference.
    """
    if exc is None:
        return None

    for link in _cause_chain(exc):
        haystack = f"{type(link).__name__} {link}".lower()
        status = _status_code_of(link)

        if status == 429 or _matches(haystack, _RATE_LIMIT_MARKERS):
            return _build(
                "rate_limit",
                429,
                -32001,
                "The model provider refused the request: rate limit or quota exhausted.",
                link,
            )

        if status in (502, 503, 504) or _matches(haystack, _UNAVAILABLE_MARKERS):
            return _build(
                "unavailable",
                503,
                -32002,
                "The model provider is unavailable or overloaded.",
                link,
            )

        if status in (401, 403) or _matches(haystack, _AUTH_MARKERS):
            return _build(
                "auth",
                502,
                -32004,
                "The model provider rejected our credentials.",
                link,
            )

        if _matches(haystack, _CONTEXT_MARKERS):
            return _build(
                "context_length",
                413,
                -32005,
                "The request exceeded the model's context window.",
                link,
            )

    return None


def _build(
    kind: str, http_status: int, jsonrpc_code: int, message: str, link: BaseException
) -> ProviderFailure:
    detail = redact_secrets(f"{type(link).__name__}: {link}")
    # Provider errors are verbose (full request echoes); keep the response bounded.
    if len(detail) > 600:
        detail = detail[:600] + "…"
    return ProviderFailure(
        kind=kind,
        http_status=http_status,
        jsonrpc_code=jsonrpc_code,
        message=message,
        detail=detail,
    )


def log_provider_failure(failure: ProviderFailure, agent_id: Any) -> None:
    """One line the operator can grep for without reading the whole trace."""
    logger.error(
        f"[CRM-236] provider failure kind={failure.kind} "
        f"http_status={failure.http_status} agent_id={agent_id} :: {failure.detail}"
    )
