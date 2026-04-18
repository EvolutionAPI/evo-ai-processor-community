"""
┌──────────────────────────────────────────────────────────────────────────────┐
│ @author: Neriton Dias                                                        │
│ @file: oauth_routes.py                                                       │
│ Developed by: Neriton Dias                                                   │
│ Creation date: Apr 18, 2026                                                  │
│ Contact: neriton.dias@live.com                                               │
├──────────────────────────────────────────────────────────────────────────────┤
│ @copyright © Evolution API 2025. All rights reserved.                        │
│ Licensed under the Apache License, Version 2.0                               │
│                                                                              │
│ You may not use this file except in compliance with the License.             │
│ You may obtain a copy of the License at                                      │
│                                                                              │
│    http://www.apache.org/licenses/LICENSE-2.0                                │
│                                                                              │
│ Unless required by applicable law or agreed to in writing, software          │
│ distributed under the License is distributed on an "AS IS" BASIS,            │
│ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.     │
│ See the License for the specific language governing permissions and          │
│ limitations under the License.                                               │
├──────────────────────────────────────────────────────────────────────────────┤
│ @important                                                                   │
│ For any future changes to the code in this file, it is recommended to        │
│ include, together with the modification, the information of the developer    │
│ who changed it and the date of modification.                                 │
└──────────────────────────────────────────────────────────────────────────────┘
"""

import os
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session
from pydantic import UUID4
from typing import Optional

from src.config.database import get_db
from src.api.dependencies import get_current_user
from src.schemas.schemas import (
    OAuthAuthStartRequest,
    OAuthAuthStartResponse,
    OAuthAuthCompleteRequest,
    OAuthStatusResponse,
)
from src.services.oauth_codex_service import (
    generate_auth_url,
    complete_auth_flow,
    get_oauth_status,
    disconnect_oauth,
    get_fresh_token,
)

import logging

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/agents/oauth/codex",
    tags=["oauth-codex"],
)


def client_id_from_header_or_user(
    x_client_id: Optional[str], current_user: dict
) -> uuid.UUID:
    """Resolve a client UUID from the x-client-id header or fall back to the user."""
    if x_client_id:
        try:
            return uuid.UUID(x_client_id)
        except ValueError:
            return uuid.uuid5(uuid.NAMESPACE_DNS, str(x_client_id))
    user_id = current_user.get("user_id", current_user.get("id", "default"))
    return uuid.uuid5(uuid.NAMESPACE_DNS, str(user_id))


@router.post(
    "/auth-start",
    response_model=OAuthAuthStartResponse,
    status_code=status.HTTP_200_OK,
    summary="Start OAuth Codex PKCE browser flow",
    description="Generates an authorization URL for the OAuth 2.0 PKCE browser flow for OpenAI Codex authentication.",
)
async def auth_start(
    request: OAuthAuthStartRequest,
    x_client_id: Optional[str] = Header(None, alias="x-client-id"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start the OAuth PKCE browser flow for OpenAI Codex.

    The client_id is taken from x-client-id header (same pattern as other endpoints).
    If not provided, a deterministic UUID is derived from the authenticated user's ID.
    """
    result = await generate_auth_url(
        db, client_id_from_header_or_user(x_client_id, current_user), request.name
    )
    return OAuthAuthStartResponse(**result)


@router.post(
    "/auth-complete",
    status_code=status.HTTP_200_OK,
    summary="Complete OAuth Codex PKCE browser flow",
    description="Exchanges the authorization callback URL for tokens to complete the PKCE flow.",
)
async def auth_complete(
    request: OAuthAuthCompleteRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Complete the PKCE browser flow by exchanging the callback URL for tokens."""
    result = await complete_auth_flow(db, request.key_id, request.callback_url)
    return result


@router.get(
    "/status/{key_id}",
    response_model=OAuthStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get OAuth Codex connection status",
    description="Returns the current OAuth connection status for a given API key.",
)
async def get_status(
    key_id: UUID4,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get OAuth connection status."""
    result = await get_oauth_status(
        db=db,
        key_id=key_id,
    )
    return OAuthStatusResponse(**result)


@router.delete(
    "/{key_id}",
    status_code=status.HTTP_200_OK,
    summary="Disconnect OAuth Codex",
    description="Disconnects an OAuth Codex key and clears stored tokens.",
)
async def disconnect(
    key_id: UUID4,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disconnect OAuth Codex authentication."""
    result = await disconnect_oauth(
        db=db,
        key_id=key_id,
    )
    return result


@router.post(
    "/internal/token/{key_id}",
    status_code=status.HTTP_200_OK,
    summary="Internal token retrieval for CRM service-to-service calls",
    description="Internal endpoint for CRM service-to-service OAuth token retrieval. Authenticated via x-api-token header.",
)
async def get_internal_token(
    key_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
):
    """Internal endpoint for CRM service-to-service token retrieval.
    Authenticated via EVOAI_CRM_API_TOKEN header.
    """
    api_token = request.headers.get("x-api-token")
    expected = os.getenv("EVOAI_CRM_API_TOKEN", "")
    if not api_token or api_token != expected:
        raise HTTPException(status_code=401, detail="Invalid service token")

    access_token, account_id = await get_fresh_token(db, key_id)
    return {"access_token": access_token, "account_id": account_id}
