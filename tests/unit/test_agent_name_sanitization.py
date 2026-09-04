"""get_agent / get_agents_by_account must coerce the agent name to a valid LLM
function name (^[a-zA-Z0-9_-]+$). str.isalnum() is True for accented chars
("café".isalnum() is True), so the old inline guard let an accent through and the
provider 400'd on tools[].function.name when the agent was attached as a tool of
another agent (llm_agent_builder → AgentTool). CRM-501."""

from __future__ import annotations

import asyncio
import re
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

from src.services.agent_service import get_agent, get_agents_by_account

# Spelled out rather than imported from the helper: an assertion that reads the
# module's own regex back would pass whatever that regex rots into.
VALID_FUNCTION_NAME = re.compile(r"^[a-zA-Z0-9_-]+$")


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

    assert VALID_FUNCTION_NAME.match(result.name), (
        f"name {result.name!r} is not a valid ^[a-zA-Z0-9_-]+$ function name — "
        "an accent 400s the provider (CRM-501)"
    )
    assert db.commit.called, "the sanitized name must persist, like the old path did"


def test_get_agents_by_account_sanitizes_accented_name():
    agent = agent_named("José 1")
    db = db_returning(agent)

    agents = get_agents_by_account(db)

    assert VALID_FUNCTION_NAME.match(agents[0].name), agents[0].name
    assert db.commit.called


def test_a_name_already_valid_is_left_untouched():
    # Providers accept hyphens; a name already in the alphabet must not be
    # rewritten (that would be a silent behaviour change). The old code even
    # rewrote hyphens to underscores; the shared helper keeps them.
    agent = agent_named("valid-name_1")
    db = db_returning(agent)

    result = asyncio.run(get_agent(db, agent.id))

    assert result.name == "valid-name_1"
