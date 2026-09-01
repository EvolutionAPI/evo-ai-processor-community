"""Unit tests for src.utils.tool_naming.sanitize_tool_name.

Pure function, no ADK/provider deps — runs standalone. Guards CRM-499: a custom
tool named with a space (the client's "testando ferramenta") used to reach the
LLM verbatim and get rejected with
``Invalid 'tools[0].function.name' ... pattern '^[a-zA-Z0-9_-]+$'`` (500).
"""

import re

import pytest

from src.utils.tool_naming import (
    FALLBACK_TOOL_NAME,
    MAX_TOOL_NAME_LENGTH,
    sanitize_tool_name,
)

OPENAI_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")


@pytest.mark.parametrize(
    "raw, expected",
    [
        # The exact case that broke the client's agent.
        ("testando ferramenta", "testando_ferramenta"),
        # Accents / punctuation collapse to a single separator.
        ("buscar café", "buscar_caf"),
        ("preço (BRL)!", "pre_o_BRL"),
        # Runs of whitespace collapse, edges trimmed.
        ("a   b", "a_b"),
        ("  spaced  ", "spaced"),
        # Already-valid names pass through untouched.
        ("get_weather", "get_weather"),
        ("brave-search", "brave-search"),
        ("Tool123", "Tool123"),
    ],
)
def test_sanitizes_to_expected(raw, expected):
    assert sanitize_tool_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["testando ferramenta", "buscar café", "preço (BRL)!", "a   b", "  ", "!!!"],
)
def test_output_always_matches_provider_pattern(raw):
    # The whole point: whatever the user typed, the emitted name is valid — so
    # the provider never 400s on tools[].function.name again.
    assert OPENAI_PATTERN.match(sanitize_tool_name(raw))


def test_empty_and_all_invalid_fall_back():
    assert sanitize_tool_name("") == FALLBACK_TOOL_NAME
    assert sanitize_tool_name("   ") == FALLBACK_TOOL_NAME
    assert sanitize_tool_name("@#$%") == FALLBACK_TOOL_NAME


def test_length_is_capped():
    long_name = "a" * 200
    result = sanitize_tool_name(long_name)
    assert len(result) <= MAX_TOOL_NAME_LENGTH
    assert OPENAI_PATTERN.match(result)
