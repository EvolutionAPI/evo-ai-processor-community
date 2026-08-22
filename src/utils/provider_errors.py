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
    # JSON-RPC reserves -32000..-32099 for implementation-defined server errors,
    # which is exactly what these are. -32603 (internal error) stays reserved for
    # failures that really are ours.
    #
    # The codes live at -3201x, NOT at the bottom of the range: src/schemas/
    # a2a_types.py already owns -32001 TaskNotFound, -32002 TaskNotCancelable,
    # -32003 PushNotificationNotSupported, -32004 UnsupportedOperation and
    # -32005 ContentTypeNotSupported, and a2a_routes.py emits them. Reasoning
    # about the reserved RANGE was not enough — an exhausted quota went on the
    # wire as "Task not found" to any conforming A2A client, which is the
    # opposite of this module's purpose. -32006..-32009 are left free so that
    # catalogue can grow without colliding again.
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


# Evidence that an exception came from an LLM provider at all.
#
# CRM-236 review: the first version trusted `status_code` on ANY link of the
# cause chain, with no provider anchor and with status taking precedence over
# text. The runner calls `raise_for_status()` against internal services
# (standard_runner.py:222 memory, :311 evo-kb-service), so their httpx errors
# entered the chain and were classified — a knowledge-base outage was reported
# as "The model provider is unavailable", and a wrong internal API token as
# "The model provider rejected our credentials".
#
# That is the exact inversion of the bug this module exists to fix: the care
# went into the text markers, none into the status match.
#
# The design choice here is to require an anchor rather than to blacklist
# internal hosts. A blacklist rots — every new internal service has to be
# remembered, and forgetting one silently reintroduces the inversion. Requiring
# positive evidence fails in the safe direction that this module already
# committed to: no anchor means no classification, and the response stays the
# honest 500.
_PROVIDER_MODULES = (
    "litellm",
    "openai",
    "anthropic",
    "google.genai",
    "google.generativeai",
    "google.api_core",
    "vertexai",
    "cohere",
    "mistralai",
    "groq",
    "boto3",
    "botocore",
)

_PROVIDER_CLASS_MARKERS = (
    "litellm",
    "openai",
    "anthropic",
    "vertexai",
    "gemini",
    "bedrock",
    "cohere",
)

# Text fingerprints. Deliberately specific: provider host names and SDK prefixes,
# never a bare vendor word like "google", which appears in unrelated URLs.
_PROVIDER_TEXT_MARKERS = (
    "litellm",
    "vertexaiexception",
    "geminiexception",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "api.openai.com",
    "api.anthropic.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "bedrock-runtime",
    "resource_exhausted",
    "gemini-",
    "gpt-",
    "claude-",
)


# Wording that ONLY an LLM provider produces, so it anchors on its own.
#
# The distinction that matters is between markers that are unambiguous and
# markers that are not. "resource_exhausted" or "maximum context length" cannot
# come from evo-kb-service; "rate limit", "too many requests", "service
# unavailable" and a bare 429/503 absolutely can. The first group anchors by
# itself, the second needs separate evidence — which is what kept a
# knowledge-base outage from being reported as a provider outage.
_SELF_ANCHORING_MARKERS = (
    "resource_exhausted",
    "resource exhausted",
    "resourceexhausted",
    "quota exceeded",
    "exceeded your current quota",
    "insufficient_quota",
    "api key not valid",
    "invalid api key",
    "invalid_api_key",
    "api_key_invalid",
    "model is overloaded",
    "overloaded",
    "high demand",
    "maximum context length",
    "context_length_exceeded",
    "contextwindowexceeded",
    "request payload size exceeds",
    "ratelimiterror",
    "authenticationerror",
    "apiconnectionerror",
    "apitimeouterror",
)


def _provider_anchored(exc: BaseException) -> bool:
    """Is there positive evidence that this exception came from an LLM provider?"""
    module = (getattr(type(exc), "__module__", "") or "").lower()
    if any(marker in module for marker in _PROVIDER_MODULES):
        return True

    name = type(exc).__name__.lower()
    if any(marker in name for marker in _PROVIDER_CLASS_MARKERS):
        return True

    haystack = f"{name} {exc}".lower()
    if any(marker in haystack for marker in _SELF_ANCHORING_MARKERS):
        return True

    return any(marker in haystack for marker in _PROVIDER_TEXT_MARKERS)


def classify_provider_error(exc: BaseException) -> Optional[ProviderFailure]:
    """Recognise a provider-side failure, or return None to keep the 500.

    A link is only considered when it is provider-anchored (see
    _provider_anchored). Within an anchored link, status codes win over text: an
    SDK that sets `status_code = 429` is stating the condition, whereas text
    matching is inference.
    """
    if exc is None:
        return None

    for link in _cause_chain(exc):
        # Without this, an httpx error from one of OUR services (evo-kb-service,
        # the memory service, EvoAuth) carries a 5xx/401 into the chain and gets
        # reported as a provider outage. See _provider_anchored.
        if not _provider_anchored(link):
            continue

        haystack = f"{type(link).__name__} {link}".lower()
        status = _status_code_of(link)

        if status == 429 or _matches(haystack, _RATE_LIMIT_MARKERS):
            return _build(
                "rate_limit",
                429,
                -32010,
                "The model provider refused the request: rate limit or quota exhausted.",
                link,
            )

        if status in (502, 503, 504) or _matches(haystack, _UNAVAILABLE_MARKERS):
            return _build(
                "unavailable",
                503,
                -32011,
                "The model provider is unavailable or overloaded.",
                link,
            )

        if status in (401, 403) or _matches(haystack, _AUTH_MARKERS):
            return _build(
                "auth",
                502,
                -32012,
                "The model provider rejected our credentials.",
                link,
            )

        if _matches(haystack, _CONTEXT_MARKERS):
            return _build(
                "context_length",
                413,
                -32013,
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
