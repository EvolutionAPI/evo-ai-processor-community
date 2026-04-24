"""Integration tests for EVO-972.

These tests mount a minimal FastAPI app that reuses the processor's
``success_response`` / ``error_response`` helpers (same ones used by
``session_routes``, ``a2a_routes``, ``chat_routes``) and verify that a
payload shaped like a Google ADK event — with ``set``/``frozenset`` fields
deep in the tree — round-trips as HTTP 200 with the expected JSON body.

This is the end-to-end regression guard for AC 1 / AC 3 / AC 4 of EVO-972:
the test chat's ``GET /sessions/{id}/messages`` endpoint blew up with
``TypeError: Object of type set is not JSON serializable`` on exactly this
shape before SafeJSONResponse was wired into the response helpers.

The a2a flow (AC 2) shares the same helpers, so coverage here implicitly
covers the WhatsApp channel path as well.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.utils.response import error_response, success_response


def _build_adk_like_event() -> dict:
    """Emulate the `event.model_dump()` shape that broke prod."""
    return {
        "id": "evt_123",
        "author": "assistant",
        "actions": {
            "artifact_delta": {"doc:1", "doc:2"},
            "state_delta": {},
            "transfer_to_agent": None,
        },
        "content": {
            "parts": [
                {
                    "text": "hello",
                    "metadata": {
                        # The exact shape that triggers review #5 (sets inside
                        # lists inside lists).
                        "tool_calls": [[{"tools_used": frozenset({"search", "calc"})}]],
                    },
                }
            ]
        },
    }


def _make_app() -> FastAPI:
    app = FastAPI()

    @app.get("/messages")
    async def messages(request: Request):
        return success_response(data=[_build_adk_like_event()])

    @app.get("/boom")
    async def boom(request: Request):
        return error_response(
            request=request,
            code="UPSTREAM_UNAVAILABLE",
            message="Authentication service is temporarily unavailable.",
            details={
                "upstream_service": "evo_auth",
                "upstream_url": "http://evo-auth:3001/api/v1/auth/validate",
                "error_type": "connection_refused",
            },
            status_code=503,
        )

    return app


class TestSuccessResponseWithAdkEvent:
    def test_messages_endpoint_returns_200_with_set_payload(self) -> None:
        # Before the fix, the `artifact_delta` / `tools_used` sets tripped
        # json.dumps at render time and Starlette re-raised as a 500.
        client = TestClient(_make_app())

        response = client.get("/messages")

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        event = body["data"][0]
        assert sorted(event["actions"]["artifact_delta"]) == ["doc:1", "doc:2"]
        deep_tools = event["content"]["parts"][0]["metadata"]["tool_calls"][0][0][
            "tools_used"
        ]
        assert sorted(deep_tools) == ["calc", "search"]


class TestErrorResponseSurface:
    def test_503_carries_structured_details_and_standard_shape(self) -> None:
        client = TestClient(_make_app())

        response = client.get("/boom")

        assert response.status_code == 503
        body = response.json()
        assert body["success"] is False
        assert body["error"]["code"] == "UPSTREAM_UNAVAILABLE"
        assert body["error"]["details"]["upstream_service"] == "evo_auth"
        assert body["error"]["details"]["error_type"] == "connection_refused"
        assert body["meta"]["path"] == "/boom"
        assert body["meta"]["method"] == "GET"
