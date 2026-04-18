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

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from pydantic import UUID4

from src.config.database import get_db
from src.api.dependencies import get_current_user
from src.schemas.schemas import (
    OAuthDeviceCodeRequest,
    OAuthDeviceCodeResponse,
    OAuthDevicePollRequest,
    OAuthDevicePollResponse,
    OAuthStatusResponse,
)
from src.services.oauth_codex_service import (
    start_device_code_flow,
    poll_device_code,
    get_oauth_status,
    disconnect_oauth,
)

import logging

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/oauth/codex",
    tags=["oauth-codex"],
)


@router.post(
    "/device-code",
    response_model=OAuthDeviceCodeResponse,
    status_code=status.HTTP_200_OK,
    summary="Start OAuth Codex device code flow",
    description="Initiates the OAuth 2.0 device code flow for OpenAI Codex authentication.",
)
async def start_device_code(
    request: OAuthDeviceCodeRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start the OAuth device code flow for OpenAI Codex."""
    result = await start_device_code_flow(
        db=db,
        client_id=request.client_id,
        name=request.name,
    )
    return OAuthDeviceCodeResponse(**result)


@router.post(
    "/device-poll",
    response_model=OAuthDevicePollResponse,
    status_code=status.HTTP_200_OK,
    summary="Poll OAuth Codex device code status",
    description="Polls the OAuth device code flow to check if the user has authorized the application.",
)
async def poll_device(
    request: OAuthDevicePollRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Poll for device code authorization status."""
    result = await poll_device_code(
        db=db,
        key_id=request.key_id,
    )
    return OAuthDevicePollResponse(**result)


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
