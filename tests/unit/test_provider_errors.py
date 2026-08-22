"""
CRM-236: a provider refusing us for quota reasons must not look like a bug in
our code. Before this, `standard_runner` wrapped EVERY failure in
`InternalServerError(str(e))` and the A2A route answered a flat
`500 / -32603 / INTERNAL_ERROR` — so a 429 and a NameError were byte-identical
from outside, and the only way to tell them apart was reading container logs.
"""

import pytest

from src.core.exceptions import InternalServerError
from src.utils.provider_errors import (
    classify_provider_error,
    redact_secrets,
)
from src.utils.response import map_status_to_error_code


# --- the incident, reproduced -------------------------------------------------

# Verbatim shape of what litellm raised during the outage that opened CRM-236.
GEMINI_QUOTA_ERROR = (
    "litellm.RateLimitError: VertexAIException - 429 RESOURCE_EXHAUSTED. "
    "Quota exceeded for metric "
    "generativelanguage.googleapis.com/generate_content_free_tier_requests, "
    "limit: 20, model: gemini-2.5-flash"
)


def test_quota_exhaustion_is_reported_as_rate_limit_not_as_our_bug():
    # Wrapped exactly like the runner wraps it.
    wrapped = InternalServerError(GEMINI_QUOTA_ERROR)
    wrapped.__cause__ = Exception(GEMINI_QUOTA_ERROR)

    failure = classify_provider_error(wrapped)

    assert failure is not None, "the operator would still be hunting a phantom bug"
    assert failure.kind == "rate_limit"
    assert failure.http_status == 429
    assert failure.jsonrpc_code == -32001


def test_the_429_reaches_the_envelope_as_rate_limit_exceeded():
    """The status is only useful if the response `code` follows it.

    `map_status_to_error_code` had no 429 entry, so it fell through to
    INTERNAL_ERROR and the envelope kept saying "our fault".
    """
    assert map_status_to_error_code(429) == "RATE_LIMIT_EXCEEDED"
    assert map_status_to_error_code(499) == "CLIENT_CLOSED_REQUEST"
    assert map_status_to_error_code(413) == "PAYLOAD_TOO_LARGE"


def test_high_demand_503_is_reported_as_unavailable():
    failure = classify_provider_error(
        Exception("The model is overloaded. Please try again later.")
    )
    assert failure is not None
    assert failure.kind == "unavailable"
    assert failure.http_status == 503


def test_status_code_attribute_wins_over_text():
    """An SDK that states 429 is stating it; text matching is only inference."""

    class SdkError(Exception):
        status_code = 429

    failure = classify_provider_error(SdkError("something went sideways"))
    assert failure is not None and failure.kind == "rate_limit"


def test_rejected_credentials_are_not_an_internal_error():
    failure = classify_provider_error(Exception("API key not valid. Please pass a valid API key."))
    assert failure is not None
    assert failure.kind == "auth"
    assert failure.http_status == 502  # ours to fix, but upstream-caused


def test_context_window_overflow_is_recognised():
    failure = classify_provider_error(
        Exception("This model's maximum context length is 8192 tokens")
    )
    assert failure is not None and failure.kind == "context_length"


# --- the part that must NOT fire ----------------------------------------------

def test_a_genuine_bug_in_our_code_stays_a_500():
    """The whole point is discrimination. If everything classifies as a
    provider fault, we have only moved the lie."""
    assert classify_provider_error(NameError("name 'foo' is not defined")) is None
    assert classify_provider_error(KeyError("contact_id")) is None
    assert classify_provider_error(ValueError("invalid literal for int()")) is None


def test_our_own_wrapper_name_does_not_read_as_a_provider_outage():
    """`InternalServerError` is OUR class and wraps every failure.

    An earlier draft of this module listed "internalservererror" as an
    unavailability marker, which would have classified every bug we ever write
    as a provider outage — the exact inversion of the bug being fixed.
    """
    assert classify_provider_error(InternalServerError("division by zero")) is None


def test_a_database_timeout_is_not_blamed_on_the_provider():
    """A bare "timeout" marker matched our own infrastructure just as well."""
    assert classify_provider_error(Exception("psycopg2 statement timeout")) is None


def test_a_number_that_merely_looks_like_a_status_is_ignored():
    """Ids and token counts contain 429 too."""
    assert classify_provider_error(Exception("contact 429 not found in pipeline")) is None


# --- credentials must never travel in the response ----------------------------

@pytest.mark.parametrize(
    "text,secret",
    [
        ("POST https://api.example.com/v1?key=AIzaSyD-EXAMPLE-KEY-1234567 failed", "AIzaSyD"),
        ("headers: {'Authorization': 'Bearer sk-proj-abcdef1234567890'}", "sk-proj-abcdef"),
        ('{"api_key": "super-secret-value-here"}', "super-secret-value-here"),
    ],
)
def test_credentials_are_redacted_before_leaving(text, secret):
    assert secret not in redact_secrets(text)
    assert "[REDACTED]" in redact_secrets(text)


def test_the_detail_returned_to_the_caller_is_redacted_and_bounded():
    failure = classify_provider_error(
        Exception("429 RESOURCE_EXHAUSTED calling https://x/v1?key=AIzaSyD-EXAMPLE-KEY-1234567 " + "x" * 2000)
    )
    assert failure is not None
    assert "AIzaSyD" not in failure.detail
    assert len(failure.detail) <= 601


def test_cause_chain_is_walked_but_bounded_by_a_cycle():
    """`raise InternalServerError(str(e)) from e` is the runner's pattern, and
    a self-referencing chain must not hang the classifier."""
    inner = Exception("quota exceeded")
    outer = InternalServerError("wrapped")
    outer.__cause__ = inner
    inner.__context__ = outer  # cycle

    failure = classify_provider_error(outer)
    assert failure is not None and failure.kind == "rate_limit"
