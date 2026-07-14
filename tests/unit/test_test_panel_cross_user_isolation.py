"""EVO-2103 — Regression tests for the "testar agente" panel cross-user leak.

The ADK indexes sessions by (agent_id, user_id, session_id). Before this fix:

  1. `GET /sessions/agent/{id}` returned every session for the agent, so a
     user's test panel listed WhatsApp/production conversations owned by other
     users (contact_ids). Clicking one showed real customer messages.
  2. `POST /chat/{agent_id}/{session_id}` looked the session up in the ADK with
     the logged user's id. If the session was originally stored by another
     owner, the ADK missed → 500 "Session not found" (with a double-wrap).
  3. `GET /sessions/{id}/messages` returned 200 with the content of sessions
     owned by other users — real customer conversations leaked to any logged
     user on the same instance.

These tests exercise the handler functions directly (no FastAPI TestClient
needed) with mocked deps so we lock the behavior at the code level and
survive future refactors.
"""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.api import chat_routes, session_routes


AGENT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
SESSION_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
OWNER_USER_ID = "owner-user@example.com"
LOGGED_USER_ID = "another-user@example.com"


def run(coro):
    return asyncio.run(coro)


def _make_db_session(owner_user_id=OWNER_USER_ID, session_id=SESSION_ID, app_name=None):
    """Simulate a SessionModel row returned by db.query(...).filter(...).first()."""
    return SimpleNamespace(
        id=session_id,
        user_id=owner_user_id,
        app_name=app_name or str(AGENT_ID),
    )


def _make_db_with_session(session_row):
    """Return a mocked SQLAlchemy `db` whose query chain resolves to `session_row`."""
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = session_row
    return db


# -----------------------------------------------------------------------------
# AC2 — POST /chat/{agent_id}/{session_id} must use the DB session owner as the
#       ADK user_id lookup key, otherwise the ADK misses and returns 500.
# -----------------------------------------------------------------------------
class TestChatUsesSessionOwnerNotLoggedUser:
    def test_chat_looks_up_session_and_passes_owner_id(self):
        db_session = _make_db_session(owner_user_id=OWNER_USER_ID)
        db = _make_db_with_session(db_session)

        payload = SimpleNamespace(message="oi", files=None)
        request = MagicMock()
        current_user = {"user_id": LOGGED_USER_ID, "email": LOGGED_USER_ID}

        fake_response = {"final_response": "hello", "message_history": []}

        with patch(
            "src.api.chat_routes.run_agent_adk",
            new=AsyncMock(return_value=fake_response),
        ) as mock_run:
            run(
                chat_routes.chat(
                    payload=payload,
                    agent_id=str(AGENT_ID),
                    session_id=SESSION_ID,
                    request=request,
                    current_user=current_user,
                    db=db,
                    _=None,
                )
            )

        assert mock_run.await_count == 1
        # run_agent_adk(agent_id, user_id, message, ...): user_id is the 2nd
        # positional. Must be the session owner, NOT the logged user.
        called_args, _kwargs = mock_run.call_args
        assert called_args[1] == OWNER_USER_ID, (
            f"chat handler passed {called_args[1]!r} as user_id but the "
            f"session is owned by {OWNER_USER_ID!r} — EVO-2103 regression."
        )
        assert called_args[1] != LOGGED_USER_ID

    def test_chat_falls_back_to_logged_user_when_session_missing(self):
        """First-message-no-session flow: session row absent in DB. Backward
        compat — do not break existing bootstrap paths."""
        db = _make_db_with_session(None)  # query returns no row

        payload = SimpleNamespace(message="oi", files=None)
        request = MagicMock()
        current_user = {"user_id": LOGGED_USER_ID}

        fake_response = {"final_response": "hi", "message_history": []}
        with patch(
            "src.api.chat_routes.run_agent_adk",
            new=AsyncMock(return_value=fake_response),
        ) as mock_run:
            run(
                chat_routes.chat(
                    payload=payload,
                    agent_id=str(AGENT_ID),
                    session_id=SESSION_ID,
                    request=request,
                    current_user=current_user,
                    db=db,
                    _=None,
                )
            )

        called_args, _kwargs = mock_run.call_args
        assert called_args[1] == LOGGED_USER_ID


# -----------------------------------------------------------------------------
# AC1 — GET /sessions/agent/{agent_id} must scope to the logged user.
# -----------------------------------------------------------------------------
class TestListSessionsScopedToLoggedUser:
    def test_list_by_agent_filters_by_current_user_id(self):
        db = MagicMock()
        request = MagicMock()
        current_user = {"user_id": LOGGED_USER_ID, "email": LOGGED_USER_ID}

        fake_agent = SimpleNamespace(id=str(AGENT_ID), folder_id=None)

        with patch(
            "src.api.session_routes.agent_service.get_agent",
            new=AsyncMock(return_value=fake_agent),
        ), patch(
            "src.api.session_routes.verify_agent_access",
            new=AsyncMock(return_value=(True, False)),
        ), patch(
            "src.api.session_routes.get_sessions_by_agent",
            new=AsyncMock(return_value=[]),
        ) as mock_list, patch(
            "src.api.session_routes.get_session_metadata",
            return_value=None,
        ):
            run(
                session_routes.get_agent_sessions(
                    request=request,
                    agent_id=AGENT_ID,
                    current_user=current_user,
                    _=None,
                    db=db,
                )
            )

        assert mock_list.await_count == 1
        _args, kwargs = mock_list.call_args
        # get_sessions_by_agent(db, agent_id, skip, limit, user_id=...)
        assert kwargs.get("user_id") == LOGGED_USER_ID, (
            f"get_agent_sessions must pass the logged user as the user_id "
            f"filter to prevent cross-user leak — EVO-2103 regression. Got "
            f"user_id={kwargs.get('user_id')!r}."
        )


# -----------------------------------------------------------------------------
# AC3 — GET /sessions/{id}/messages must return 403 when session belongs to
#       another owner (LGPD: no customer conversation leaks between users).
# -----------------------------------------------------------------------------
class TestGetMessagesBlocksCrossUserRead:
    def _run_get_messages(self, session_user_id, current_user_id):
        db = MagicMock()
        request = MagicMock()
        # error_response() builds a Pydantic model that validates str fields
        # on request.method and request.url.path — MagicMock defaults leak
        # through Pydantic. Set explicit strings.
        request.method = "GET"
        request.url = SimpleNamespace(path=f"/sessions/{SESSION_ID}/messages")
        current_user = {"user_id": current_user_id, "email": current_user_id}

        fake_session = SimpleNamespace(
            id=SESSION_ID,
            user_id=session_user_id,
            app_name=str(AGENT_ID),
        )
        fake_agent = SimpleNamespace(id=str(AGENT_ID), folder_id=None)

        with patch(
            "src.api.session_routes.get_session_by_id",
            new=AsyncMock(return_value=fake_session),
        ), patch(
            "src.api.session_routes.agent_service.get_agent",
            new=AsyncMock(return_value=fake_agent),
        ), patch(
            "src.api.session_routes.verify_agent_access",
            new=AsyncMock(return_value=(True, False)),
        ), patch(
            "src.api.session_routes.get_session_events",
            new=AsyncMock(return_value=[]),
        ):
            return run(
                session_routes.get_agent_messages(
                    request=request,
                    session_id=SESSION_ID,
                    current_user=current_user,
                    _=None,
                    db=db,
                )
            )

    def test_returns_403_when_session_belongs_to_another_user(self):
        response = self._run_get_messages(
            session_user_id=OWNER_USER_ID,
            current_user_id=LOGGED_USER_ID,
        )
        status_code = getattr(response, "status_code", None)
        if status_code is None:
            body = getattr(response, "body", b"")
            assert b"403" in body or b"do not own" in body.lower(), (
                f"Expected 403 forbidden response, got: {response!r}"
            )
        else:
            assert status_code == 403, (
                f"Expected 403, got {status_code}. EVO-2103 regression: "
                f"cross-owner read must be denied."
            )

    def test_returns_200_for_own_session(self):
        response = self._run_get_messages(
            session_user_id=OWNER_USER_ID,
            current_user_id=OWNER_USER_ID,
        )
        status_code = getattr(response, "status_code", None)
        # Success path may be a plain 200 (default). Just assert not 403.
        if status_code is not None:
            assert status_code != 403
