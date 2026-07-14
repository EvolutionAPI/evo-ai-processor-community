"""Unit tests for Custom HTTP Tools — EVO-2125.

Covers the three broken links in the chain: the by-id getter the ADK builder
depends on, the rebuild of tools attached to an agent through `custom_tool_ids`,
and the reserved metadata keys that must never reach the wire.

No database: the session is a fake exposing only the query chain the service
uses.
"""

from __future__ import annotations

import inspect
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import SQLAlchemyError

from src.services import agent_service, custom_tool_service
from src.services.adk.custom_tools import MODES_META_KEYS, CustomToolBuilder
from src.services.adk.tool_builder import ToolBuilder


MODES_META = {"input": "nothing", "output": "an advice"}

# Tools attached by id are built by CustomToolBuilder; tools stored inline in the
# agent config go through ToolBuilder. Each carries its own _create_http_tool, so
# both have to strip the metadata.
BUILDERS = [CustomToolBuilder, ToolBuilder]


def _fake_db(result=None, raises: Exception | None = None) -> MagicMock:
    """A Session stand-in whose query(...).filter(...).first() is scripted."""

    db = MagicMock()
    query = db.query.return_value.filter.return_value
    if raises is not None:
        query.first.side_effect = raises
    else:
        query.first.return_value = result
    return db


def _tool(name: str = "advice", **overrides) -> SimpleNamespace:
    """A CustomTool row as the ORM model returns it — note: no `is_active`."""

    tool = SimpleNamespace(
        id=uuid.uuid4(),
        name=name,
        description="Gets an advice",
        method="GET",
        endpoint="https://api.adviceslip.com/advice",
        headers={},
        path_params={},
        query_params={},
        body_params={},
        error_handling={},
        values={"lang": "pt", "__evo_modes_meta__": MODES_META},
    )
    for key, value in overrides.items():
        setattr(tool, key, value)
    return tool


class TestGetCustomTool:
    def test_returns_the_row_for_a_known_id(self):
        expected = _tool()
        db = _fake_db(result=expected)

        assert custom_tool_service.get_custom_tool(db, expected.id) is expected

    def test_returns_none_for_an_unknown_id(self):
        assert (
            custom_tool_service.get_custom_tool(_fake_db(result=None), uuid.uuid4())
            is None
        )

    def test_swallows_database_errors(self):
        db = _fake_db(raises=SQLAlchemyError("connection lost"))

        assert custom_tool_service.get_custom_tool(db, uuid.uuid4()) is None

    def test_queries_the_orm_model_not_the_pydantic_schema(self):
        """db.query() must receive a mapped class, or SQLAlchemy raises."""

        from src.models.models import CustomTool as CustomToolModel

        assert custom_tool_service.CustomTool is CustomToolModel


class TestBuildToolsFromIds:
    def test_builds_a_tool_attached_by_id(self):
        tool = _tool()
        with patch.object(custom_tool_service, "get_custom_tool", return_value=tool):
            built = CustomToolBuilder().build_tools(
                {"custom_tool_ids": [str(tool.id)]}, db=_fake_db()
            )

        assert len(built) == 1
        assert built[0].func.__name__ == "advice"

    def test_skips_an_unknown_id_without_breaking_the_build(self):
        with patch.object(custom_tool_service, "get_custom_tool", return_value=None):
            built = CustomToolBuilder().build_tools(
                {"custom_tool_ids": [str(uuid.uuid4())]}, db=_fake_db()
            )

        assert built == []

    def test_requires_a_db_session(self):
        with pytest.raises(ValueError):
            CustomToolBuilder().build_tools({"custom_tool_ids": [str(uuid.uuid4())]})


class TestReconstructCustomConfigurations:
    """The agent config carries only the ids; the http_tools are rebuilt on read."""

    def test_rebuilds_http_tools_from_the_attached_ids(self):
        tool = _tool()
        agent = SimpleNamespace(
            id=uuid.uuid4(), config={"custom_tool_ids": [str(tool.id)]}
        )
        db = _fake_db()

        with patch.object(custom_tool_service, "get_custom_tool", return_value=tool):
            agent_service._reconstruct_custom_configurations(db, agent)

        http_tools = agent.config["custom_tools"]["http_tools"]
        assert [t["name"] for t in http_tools] == ["advice"]

    def test_the_expansion_is_never_written_back(self):
        """Persisting it would freeze a copy of the tool inside the agent: the
        guard skips the expansion once http_tools is populated, so the stale copy
        would be served forever and editing the tool would never reach the agent.
        It is a read-path hydration — a GET must not write."""

        tool = _tool()
        agent = SimpleNamespace(
            id=uuid.uuid4(), config={"custom_tool_ids": [str(tool.id)]}
        )
        db = _fake_db()

        with patch.object(custom_tool_service, "get_custom_tool", return_value=tool):
            agent_service._reconstruct_custom_configurations(db, agent)

        db.commit.assert_not_called()

    def test_an_edit_to_the_tool_reaches_the_agent_on_the_next_read(self):
        """The expansion is recomputed from the catalog row on every read, so a
        tool edited in the catalog takes effect without touching the agent."""

        tool = _tool(endpoint="https://api.adviceslip.com/advice")
        agent = SimpleNamespace(
            id=uuid.uuid4(), config={"custom_tool_ids": [str(tool.id)]}
        )

        with patch.object(custom_tool_service, "get_custom_tool", return_value=tool):
            agent_service._reconstruct_custom_configurations(_fake_db(), agent)
        assert agent.config["custom_tools"]["http_tools"][0]["endpoint"] == (
            "https://api.adviceslip.com/advice"
        )

        # the user edits the tool in the catalog, then the agent is read again
        tool.endpoint = "https://api.adviceslip.com/advice/search"
        agent.config["custom_tools"]["http_tools"] = []
        with patch.object(custom_tool_service, "get_custom_tool", return_value=tool):
            agent_service._reconstruct_custom_configurations(_fake_db(), agent)

        assert agent.config["custom_tools"]["http_tools"][0]["endpoint"] == (
            "https://api.adviceslip.com/advice/search"
        )

    def test_the_reserved_metadata_is_not_copied_into_the_agent_config(self):
        tool = _tool()
        agent = SimpleNamespace(
            id=uuid.uuid4(), config={"custom_tool_ids": [str(tool.id)]}
        )

        with patch.object(custom_tool_service, "get_custom_tool", return_value=tool):
            agent_service._reconstruct_custom_configurations(_fake_db(), agent)

        values = agent.config["custom_tools"]["http_tools"][0]["values"]
        assert values == {"lang": "pt"}

    def test_an_unknown_id_is_skipped_not_raised(self):
        agent = SimpleNamespace(
            id=uuid.uuid4(), config={"custom_tool_ids": [str(uuid.uuid4())]}
        )

        with patch.object(custom_tool_service, "get_custom_tool", return_value=None):
            agent_service._reconstruct_custom_configurations(agent=agent, db=_fake_db())

        assert agent.config["custom_tools"]["http_tools"] == []

    def test_is_synchronous(self):
        """get_agents_by_account is sync and calls it without await: as a
        coroutine it would silently never run."""

        assert not inspect.iscoroutinefunction(
            agent_service._reconstruct_custom_configurations
        )


class TestAToolAttachedByIdIsRegisteredOnce:
    """The config the builders receive is the expanded one: it carries the
    custom_tool_ids AND the http_tools those IDs expand to. Reading both sources
    naively registers the same tool under one name several times — the LLM then
    gets N identical function declarations."""

    def _expanded_config(self, tool):
        agent = SimpleNamespace(
            id=uuid.uuid4(), config={"custom_tool_ids": [str(tool.id)]}
        )
        with patch.object(custom_tool_service, "get_custom_tool", return_value=tool):
            agent_service._reconstruct_custom_configurations(_fake_db(), agent)
        return agent.config

    def test_the_expanded_config_builds_exactly_one_tool(self):
        tool = _tool()
        config = self._expanded_config(tool)
        assert config["custom_tool_ids"] and config["custom_tools"]["http_tools"]

        with patch.object(custom_tool_service, "get_custom_tool", return_value=tool):
            built = ToolBuilder().build_tools(config, db=_fake_db())

        assert [t.func.__name__ for t in built] == ["advice"]

    def test_an_inline_tool_of_its_own_still_gets_built(self):
        """Only the expanded copies are dropped — a legacy inline tool that is not
        one of the attached IDs must survive."""

        tool = _tool()
        config = self._expanded_config(tool)
        config["custom_tools"]["http_tools"].append(
            {
                "name": "legacy_inline",
                "description": "Configured by hand, not in the catalog",
                "method": "GET",
                "endpoint": "https://example.test/legacy",
                "parameters": {},
                "values": {},
            }
        )

        with patch.object(custom_tool_service, "get_custom_tool", return_value=tool):
            built = ToolBuilder().build_tools(config, db=_fake_db())

        assert sorted(t.func.__name__ for t in built) == ["advice", "legacy_inline"]


@pytest.mark.parametrize("builder", BUILDERS, ids=lambda b: b.__name__)
class TestReservedMetadataKeysNeverReachTheWire:
    def _call(self, builder, tool_config, **kwargs):
        """Build the tool, invoke it, and hand back the intercepted request."""

        built = builder()._create_http_tool(tool_config)
        target = f"{builder.__module__}.requests.request"
        with patch(target) as request:
            request.return_value = MagicMock(status_code=200, json=lambda: {"ok": True})
            built.func(**kwargs)
        return request.call_args.kwargs

    @pytest.mark.parametrize("meta_key", sorted(MODES_META_KEYS))
    def test_metadata_is_not_sent_as_a_query_param(self, builder, meta_key):
        sent = self._call(
            builder,
            {
                "name": "advice",
                "description": "Gets an advice",
                "method": "GET",
                "endpoint": "https://api.adviceslip.com/advice",
                "parameters": {},
                "values": {"lang": "pt", meta_key: MODES_META},
            },
        )

        assert meta_key not in sent["params"]
        assert sent["params"] == {"lang": "pt"}

    @pytest.mark.parametrize("meta_key", sorted(MODES_META_KEYS))
    def test_metadata_is_not_sent_in_the_body(self, builder, meta_key):
        sent = self._call(
            builder,
            {
                "name": "create_note",
                "description": "Creates a note",
                "method": "POST",
                "endpoint": "https://example.test/notes",
                "parameters": {
                    "body_params": {
                        "title": {
                            "type": "string",
                            "required": True,
                            "description": "Title",
                        }
                    }
                },
                "values": {meta_key: MODES_META},
            },
            title="hello",
        )

        assert meta_key not in (sent["json"] or {})
        assert meta_key not in sent["params"]
        assert sent["json"] == {"title": "hello"}

    def test_metadata_does_not_leak_into_the_tool_docstring(self, builder):
        built = builder()._create_http_tool(
            {
                "name": "advice",
                "description": "Gets an advice",
                "method": "GET",
                "endpoint": "https://api.adviceslip.com/advice",
                "parameters": {},
                "values": {"lang": "pt", "__evo_modes_meta__": MODES_META},
            }
        )

        assert "__evo_modes_meta__" not in built.func.__doc__
        assert "lang: pt" in built.func.__doc__

    def test_real_default_values_still_reach_the_request(self, builder):
        sent = self._call(
            builder,
            {
                "name": "advice",
                "description": "Gets an advice",
                "method": "GET",
                "endpoint": "https://api.adviceslip.com/advice",
                "parameters": {"query_params": {"format": "json"}},
                "values": {"lang": "pt", "__evo_modes_meta__": MODES_META},
            },
        )

        assert sent["params"] == {"format": "json", "lang": "pt"}
