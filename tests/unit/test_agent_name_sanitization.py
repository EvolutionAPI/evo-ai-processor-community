"""get_agent / get_agents_by_account must coerce the agent name into something
both the provider and the ADK accept. The provider constrains
tools[].function.name to ^[a-zA-Z0-9_-]+$; the ADK's BaseAgent additionally
requires a Python identifier, so a hyphen passes the first and fails the second.
CRM-501."""

from __future__ import annotations

import asyncio
import re
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

from google.adk.agents.llm_agent import LlmAgent

from src.services.agent_service import get_agent, get_agents_by_account

# Spelled out rather than imported from the helper: an assertion that reads the
# module's own regex back would pass whatever that regex rots into. Used with
# .fullmatch — .match on "^...$" would accept a trailing newline ($ matches
# before a final \n in Python), the exact false-green this fix closes.
VALID_FUNCTION_NAME = re.compile(r"[a-zA-Z0-9_-]+")


def assert_usable_as_agent_name(name):
    """Both halves of the contract, the second one against the real ADK.

    Asserting a regex of our own would only restate the helper; building an
    LlmAgent runs BaseAgent's own validator, which is what actually rejected the
    name in production.
    """
    assert VALID_FUNCTION_NAME.fullmatch(name), (
        f"name {name!r} is not a valid ^[a-zA-Z0-9_-]+$ function name — "
        "the provider 400s on it (CRM-501)"
    )
    LlmAgent(name=name, model="openai/gpt-4o")


def agent_named(name):
    """type="llm" so the sequential/parallel/loop repair path stays out of the
    way — only the name-sanitization block runs."""
    return SimpleNamespace(
        id=uuid.uuid4(),
        name=name,
        type="llm",
        model="openai/gpt-5.6-luna",
        config={},
        folder_id=None,
    )


def db_returning(agent):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = agent
    query = db.query.return_value
    query.order_by.return_value.offset.return_value.limit.return_value.all.return_value = [
        agent
    ]
    return db


def test_get_agent_sanitizes_accented_name_to_valid_function_name():
    # On the pre-fix code é/ç/ã survive (isalnum() is True) and the name comes
    # back "Café_Ação" — still invalid, still 400s the provider.
    agent = agent_named("Café Ação")
    db = db_returning(agent)

    result = asyncio.run(get_agent(db, agent.id))

    assert_usable_as_agent_name(result.name)
    assert db.commit.called, "the sanitized name must persist, like the old path did"


def test_get_agents_by_account_sanitizes_accented_name():
    agent = agent_named("José 1")
    db = db_returning(agent)

    agents = get_agents_by_account(db)

    assert_usable_as_agent_name(agents[0].name)
    assert db.commit.called


def test_a_hyphen_is_folded_because_the_adk_rejects_it():
    # The provider accepts "-", the ADK does not (BaseAgent.name must be a
    # Python identifier), and the UI's own sanitizeAgentName emits it — so
    # "Suporte - N1" reaches us as "suporte_-_n1" and used to fail to build.
    agent = agent_named("suporte_-_n1")
    db = db_returning(agent)

    result = asyncio.run(get_agent(db, agent.id))

    assert "-" not in result.name
    assert_usable_as_agent_name(result.name)
    assert db.commit.called


def test_a_leading_digit_gains_a_prefix():
    # "1_Agente" satisfies the provider and is not an identifier either.
    agent = agent_named("1 Agente")
    db = db_returning(agent)

    result = asyncio.run(get_agent(db, agent.id))

    assert_usable_as_agent_name(result.name)


def test_a_name_already_valid_is_left_untouched():
    # A name already inside the alphabet must not be rewritten — that would be a
    # silent behaviour change under a working agent.
    agent = agent_named("valid_name_1")
    db = db_returning(agent)

    result = asyncio.run(get_agent(db, agent.id))

    assert result.name == "valid_name_1"
    assert not db.commit.called


def test_an_over_long_name_is_truncated_and_the_truncation_persists():
    # The provider caps function.name at 64 chars, so a longer name is rewritten
    # in the database even when every character was already valid. Pinned here
    # because it is a rename the user never asked for and cannot undo.
    agent = agent_named("a" * 80)
    db = db_returning(agent)

    result = asyncio.run(get_agent(db, agent.id))

    assert result.name == "a" * 64
    assert db.commit.called


def test_empty_name_is_coerced_to_the_fallback_and_persists():
    # An empty name is invalid for tools[].function.name too. The old `if
    # agent.name` guard skipped it; now the helper's "tool" fallback fixes it.
    agent = agent_named("")
    db = db_returning(agent)

    result = asyncio.run(get_agent(db, agent.id))

    assert result.name == "tool"
    assert db.commit.called, "the fallback must persist so it stops 400ing"


def test_trailing_newline_name_is_sanitized_not_passed_through():
    # Python's `$` matches before a final newline, so a `^...$` passthrough would
    # keep "valid\n" — still an invalid function name. The helper (\A...\Z) must
    # reject it and sanitize.
    agent = agent_named("valid\n")
    db = db_returning(agent)

    result = asyncio.run(get_agent(db, agent.id))

    assert "\n" not in result.name
    assert_usable_as_agent_name(result.name)
