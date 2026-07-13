"""Authentication tests for the token shapes evo-auth actually returns.

evo-auth serializes an OAuth/bearer token with the field ``access_token`` and an
API access token with the field ``token`` (see ``TokenSerializer`` in
evo-auth-service). Both must authenticate against the processor. EVO-2123.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.middleware.evo_auth import EvoAuthMiddleware
from src.schemas.auth import EvoAuthResponse, TokenInfo

AGENT_ID = "11111111-1111-1111-1111-111111111111"
SESSION_ID = f"display1_{AGENT_ID}"

USER_PAYLOAD = {
    "id": "8a7c6792-0000-0000-0000-000000000001",
    "name": "Test User",
    "email": "test@example.com",
}
ACCOUNTS_PAYLOAD = [
    {
        "id": "acc-1",
        "name": "Test Account",
        "status": "active",
        "locale": "pt_BR",
    }
]

# Exactly what evo-auth returns for an api_access_token (TokenSerializer.access_token)
API_ACCESS_TOKEN_PAYLOAD = {
    "user": USER_PAYLOAD,
    "accounts": ACCOUNTS_PAYLOAD,
    "token": {
        "id": "8a7c6792-0000-0000-0000-000000000002",
        "name": "meu-token",
        "token": "90c737e950aabbccdd",
        "scopes": '["*"]',
        "expires_at": None,
        "created_at": "2026-07-13T00:00:00Z",
        "type": "api_access_token",
    },
}

# Exactly what evo-auth returns for a bearer token (TokenSerializer.oauth)
BEARER_PAYLOAD = {
    "user": USER_PAYLOAD,
    "accounts": ACCOUNTS_PAYLOAD,
    "token": {
        "access_token": "bearer-token-value",
        "expires_in": 7200,
        "refresh_token": "refresh-value",
        "created_at": "2026-07-13T00:00:00Z",
        "scopes": ["public"],
        "type": "bearer",
    },
}


def build_client(auth_response):
    """FastAPI app guarded by EvoAuthMiddleware, with evo-auth stubbed out."""
    app = FastAPI()

    @app.get("/api/v1/sessions/{session_id}/events")
    async def events(session_id: str, request: Request):
        return {"token_info": request.state.user_context["token_info"]}

    app.add_middleware(EvoAuthMiddleware)

    auth_service = MagicMock()
    auth_service.validate_token = AsyncMock(return_value=auth_response)
    return TestClient(app), auth_service


class TestTokenInfoSchema:
    def test_parses_api_access_token_field_name(self):
        """evo-auth names the api_access_token field `token`, not `access_token`."""
        info = TokenInfo(**API_ACCESS_TOKEN_PAYLOAD["token"])

        assert info.access_token == "90c737e950aabbccdd"
        assert info.type == "api_access_token"

    def test_parses_bearer_field_name(self):
        info = TokenInfo(**BEARER_PAYLOAD["token"])

        assert info.access_token == "bearer-token-value"
        assert info.type == "bearer"

    def test_dict_exposes_access_token_for_downstream_consumers(self):
        """permission_service and contextutils read token_info['access_token']."""
        response = EvoAuthResponse(**API_ACCESS_TOKEN_PAYLOAD)

        assert response.token.dict()["access_token"] == "90c737e950aabbccdd"

    def test_rejects_token_without_any_value(self):
        with pytest.raises(Exception):
            TokenInfo(type="api_access_token")


class TestMiddlewareTokenTypes:
    def test_api_access_token_authenticates(self):
        """AC1: a valid api_access_token returns 200, not 401."""
        auth_response = EvoAuthResponse(**API_ACCESS_TOKEN_PAYLOAD)
        client, auth_service = build_client(auth_response)

        with patch("src.middleware.evo_auth.get_auth_service", return_value=auth_service):
            response = client.get(
                f"/api/v1/sessions/{SESSION_ID}/events",
                headers={"api_access_token": "90c737e950aabbccdd"},
            )

        assert response.status_code == 200
        token_info = response.json()["token_info"]
        assert token_info["access_token"] == "90c737e950aabbccdd"
        assert token_info["type"] == "api_access_token"

    def test_bearer_still_authenticates(self):
        """AC2: the browser app path keeps working."""
        auth_response = EvoAuthResponse(**BEARER_PAYLOAD)
        client, auth_service = build_client(auth_response)

        with patch("src.middleware.evo_auth.get_auth_service", return_value=auth_service):
            response = client.get(
                f"/api/v1/sessions/{SESSION_ID}/events",
                headers={"Authorization": "Bearer bearer-token-value"},
            )

        assert response.status_code == 200
        assert response.json()["token_info"]["type"] == "bearer"

    def test_invalid_token_is_unauthorized(self):
        client, auth_service = build_client(None)

        with patch("src.middleware.evo_auth.get_auth_service", return_value=auth_service), patch(
            "src.middleware.evo_auth.get_db"
        ) as get_db, patch(
            "src.middleware.evo_auth.agent_service.validate_agent_api_key",
            AsyncMock(return_value=None),
        ):
            get_db.return_value = iter([MagicMock()])
            response = client.get(
                f"/api/v1/sessions/{SESSION_ID}/events",
                headers={"api_access_token": "bogus"},
            )

        assert response.status_code == 401


class TestAgentApiKeyPath:
    def test_agent_api_key_authenticates_when_evo_auth_rejects_token(self):
        """AC3: agent bots authenticate against the agent's own API key."""
        client, auth_service = build_client(None)

        with patch("src.middleware.evo_auth.get_auth_service", return_value=auth_service), patch(
            "src.middleware.evo_auth.get_db"
        ) as get_db, patch(
            "src.middleware.evo_auth.agent_service.validate_agent_api_key",
            AsyncMock(return_value={"valid": True, "agent_id": AGENT_ID, "agent_name": "bot"}),
        ):
            get_db.return_value = iter([MagicMock()])
            response = client.get(
                f"/api/v1/sessions/{SESSION_ID}/events",
                headers={"api_access_token": "agent-api-key"},
            )

        assert response.status_code == 200
        token_info = response.json()["token_info"]
        assert token_info["access_token"] == "agent-api-key"
        assert token_info["type"] == "agent_api_key"


class TestMiddlewareErrorReporting:
    def test_unexpected_error_logs_traceback(self):
        """The 503 must not swallow the real cause (EVO-2123, adjacent bug)."""
        client, auth_service = build_client(None)
        auth_service.validate_token = AsyncMock(side_effect=RuntimeError("boom"))

        with patch("src.middleware.evo_auth.get_auth_service", return_value=auth_service), patch(
            "src.middleware.evo_auth.logger"
        ) as logger:
            response = client.get(
                f"/api/v1/sessions/{SESSION_ID}/events",
                headers={"Authorization": "Bearer whatever"},
            )

        assert response.status_code == 503
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs.get("exc_info") is True
