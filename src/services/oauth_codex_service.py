"""
┌──────────────────────────────────────────────────────────────────────────────┐
│ @author: Neriton Dias                                                        │
│ @file: oauth_codex_service.py                                                │
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

import httpx
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from fastapi import HTTPException, status

from src.models.models import ApiKey
from src.utils.crypto import encrypt_oauth_data, decrypt_oauth_data
from src.config.oauth_constants import (
    CODEX_CLIENT_ID,
    CODEX_DEVICE_AUTH_URL,
    CODEX_TOKEN_URL,
    CODEX_USERINFO_URL,
    CODEX_SCOPES,
    CODEX_GRANT_TYPE_DEVICE,
    CODEX_GRANT_TYPE_REFRESH,
    CODEX_DEFAULT_POLL_INTERVAL,
)

logger = logging.getLogger(__name__)


async def start_device_code_flow(
    db: Session,
    client_id: uuid.UUID,
    name: str,
) -> dict:
    """
    Start the OAuth device code flow for OpenAI Codex.
    Creates an ApiKey record in 'pending' state and returns the device code info.
    """
    # Request device code from OpenAI
    async with httpx.AsyncClient() as client:
        response = await client.post(
            CODEX_DEVICE_AUTH_URL,
            data={
                "client_id": CODEX_CLIENT_ID,
                "scope": CODEX_SCOPES,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if response.status_code != 200:
        logger.error(f"Device code request failed: {response.status_code} {response.text}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to start device code flow: {response.text}",
        )

    device_data = response.json()

    # Create an ApiKey record in pending state
    oauth_pending_data = {
        "device_code": device_data.get("device_code"),
        "status": "pending",
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "expires_in": device_data.get("expires_in", 900),
        "interval": device_data.get("interval", CODEX_DEFAULT_POLL_INTERVAL),
    }

    encrypted_oauth = encrypt_oauth_data(oauth_pending_data)

    api_key_record = ApiKey(
        id=uuid.uuid4(),
        name=name,
        provider="openai",
        key=None,
        auth_type="oauth_codex",
        oauth_data=encrypted_oauth,
        is_active=False,  # Not active until token is obtained
    )

    try:
        db.add(api_key_record)
        db.commit()
        db.refresh(api_key_record)
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Error creating OAuth API key record: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating OAuth API key record",
        )

    return {
        "user_code": device_data.get("user_code"),
        "verification_uri": device_data.get("verification_uri")
        or device_data.get("verification_url", "https://platform.openai.com/device"),
        "expires_in": device_data.get("expires_in", 900),
        "interval": device_data.get("interval", CODEX_DEFAULT_POLL_INTERVAL),
        "key_id": api_key_record.id,
    }


async def poll_device_code(
    db: Session,
    key_id: uuid.UUID,
) -> dict:
    """
    Poll for the device code token. Returns status and token info if ready.
    """
    api_key_record = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key record not found",
        )

    if api_key_record.auth_type != "oauth_codex":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key is not an OAuth Codex key",
        )

    oauth_data = decrypt_oauth_data(api_key_record.oauth_data)
    if not oauth_data or oauth_data.get("status") not in ("pending",):
        if oauth_data.get("status") == "connected":
            return {"status": "connected", "key_id": key_id, "message": "Already connected"}
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid OAuth state: {oauth_data.get('status', 'unknown')}",
        )

    device_code = oauth_data.get("device_code")
    if not device_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No device code found in OAuth data",
        )

    # Check expiry
    requested_at = datetime.fromisoformat(oauth_data["requested_at"])
    expires_in = oauth_data.get("expires_in", 900)
    if datetime.now(timezone.utc) > requested_at + timedelta(seconds=expires_in):
        oauth_data["status"] = "expired"
        api_key_record.oauth_data = encrypt_oauth_data(oauth_data)
        db.commit()
        return {"status": "expired", "message": "Device code has expired. Please start a new flow."}

    # Poll the token endpoint
    async with httpx.AsyncClient() as client:
        response = await client.post(
            CODEX_TOKEN_URL,
            data={
                "client_id": CODEX_CLIENT_ID,
                "grant_type": CODEX_GRANT_TYPE_DEVICE,
                "device_code": device_code,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    token_data = response.json()

    if response.status_code == 200 and "access_token" in token_data:
        # Success - store the tokens
        oauth_connected_data = {
            "status": "connected",
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token"),
            "token_type": token_data.get("token_type", "Bearer"),
            "expires_in": token_data.get("expires_in"),
            "connected_at": datetime.now(timezone.utc).isoformat(),
        }

        # Calculate token expiry
        if token_data.get("expires_in"):
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=token_data["expires_in"])
            oauth_connected_data["expires_at"] = expires_at.isoformat()

        # Try to get account info
        try:
            account_info = await _get_account_info(token_data["access_token"])
            if account_info:
                oauth_connected_data["account_id"] = account_info.get("id")
                oauth_connected_data["account_email"] = account_info.get("email")
                oauth_connected_data["plan_type"] = account_info.get("plan_type")
        except Exception as e:
            logger.warning(f"Could not fetch account info: {e}")

        api_key_record.oauth_data = encrypt_oauth_data(oauth_connected_data)
        api_key_record.is_active = True
        db.commit()

        return {
            "status": "connected",
            "key_id": key_id,
            "message": "Successfully connected to OpenAI Codex",
        }

    # Handle pending/slow_down states
    error = token_data.get("error", "")
    if error == "authorization_pending":
        return {"status": "pending", "message": "Waiting for user authorization..."}
    elif error == "slow_down":
        return {"status": "slow_down", "message": "Polling too fast. Please slow down."}
    elif error == "expired_token":
        oauth_data["status"] = "expired"
        api_key_record.oauth_data = encrypt_oauth_data(oauth_data)
        db.commit()
        return {"status": "expired", "message": "Device code has expired."}
    elif error == "access_denied":
        oauth_data["status"] = "denied"
        api_key_record.oauth_data = encrypt_oauth_data(oauth_data)
        db.commit()
        return {"status": "denied", "message": "User denied the authorization request."}
    else:
        logger.error(f"Unexpected token response: {token_data}")
        return {
            "status": "error",
            "message": f"Unexpected error: {error or 'unknown'}",
        }


async def get_oauth_status(
    db: Session,
    key_id: uuid.UUID,
) -> dict:
    """Get the current OAuth connection status for a key."""
    api_key_record = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key record not found",
        )

    if api_key_record.auth_type != "oauth_codex":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key is not an OAuth Codex key",
        )

    oauth_data = decrypt_oauth_data(api_key_record.oauth_data)

    result = {
        "key_id": key_id,
        "connected": oauth_data.get("status") == "connected",
    }

    if oauth_data.get("expires_at"):
        result["expires_at"] = datetime.fromisoformat(oauth_data["expires_at"])

    if oauth_data.get("account_id"):
        result["account_id"] = oauth_data["account_id"]

    if oauth_data.get("plan_type"):
        result["plan_type"] = oauth_data["plan_type"]

    return result


async def disconnect_oauth(
    db: Session,
    key_id: uuid.UUID,
) -> dict:
    """Disconnect an OAuth Codex key (deactivate and clear tokens)."""
    api_key_record = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key record not found",
        )

    if api_key_record.auth_type != "oauth_codex":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key is not an OAuth Codex key",
        )

    # Clear OAuth data and deactivate
    api_key_record.oauth_data = encrypt_oauth_data({"status": "disconnected"})
    api_key_record.is_active = False
    db.commit()

    return {"status": "disconnected", "key_id": key_id}


async def get_fresh_token(
    db: Session,
    key_id: uuid.UUID,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Get a fresh access token for the given key, refreshing if necessary.
    Returns (access_token, account_id) or (None, None) if unavailable.
    """
    api_key_record = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not api_key_record or api_key_record.auth_type != "oauth_codex":
        return None, None

    if not api_key_record.is_active:
        return None, None

    oauth_data = decrypt_oauth_data(api_key_record.oauth_data)
    if oauth_data.get("status") != "connected":
        return None, None

    access_token = oauth_data.get("access_token")
    account_id = oauth_data.get("account_id")

    # Check if token is expired and needs refresh
    expires_at_str = oauth_data.get("expires_at")
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str)
        # Refresh if token expires within 5 minutes
        if datetime.now(timezone.utc) > expires_at - timedelta(minutes=5):
            refresh_token = oauth_data.get("refresh_token")
            if refresh_token:
                try:
                    new_token_data = await _refresh_access_token(refresh_token)
                    if new_token_data and "access_token" in new_token_data:
                        access_token = new_token_data["access_token"]
                        oauth_data["access_token"] = access_token

                        if new_token_data.get("refresh_token"):
                            oauth_data["refresh_token"] = new_token_data["refresh_token"]

                        if new_token_data.get("expires_in"):
                            new_expires_at = datetime.now(timezone.utc) + timedelta(
                                seconds=new_token_data["expires_in"]
                            )
                            oauth_data["expires_at"] = new_expires_at.isoformat()

                        api_key_record.oauth_data = encrypt_oauth_data(oauth_data)
                        db.commit()
                        logger.info(f"Refreshed OAuth token for key {key_id}")
                except Exception as e:
                    logger.error(f"Error refreshing OAuth token for key {key_id}: {e}")
                    # Return existing token; it might still work briefly
            else:
                logger.warning(f"OAuth token expired and no refresh token for key {key_id}")

    return access_token, account_id


async def _refresh_access_token(refresh_token: str) -> Optional[dict]:
    """Refresh an OAuth access token using the refresh token."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            CODEX_TOKEN_URL,
            data={
                "client_id": CODEX_CLIENT_ID,
                "grant_type": CODEX_GRANT_TYPE_REFRESH,
                "refresh_token": refresh_token,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if response.status_code == 200:
        return response.json()

    logger.error(f"Token refresh failed: {response.status_code} {response.text}")
    return None


async def _get_account_info(access_token: str) -> Optional[dict]:
    """Get account information from OpenAI using the access token."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            CODEX_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if response.status_code == 200:
        return response.json()

    logger.warning(f"Account info request failed: {response.status_code}")
    return None


# ---------------------------------------------------------------------------
# Utility functions for LiteLLM chatgpt/ provider integration
# ---------------------------------------------------------------------------

def get_raw_oauth_tokens(db: Session, key_id: uuid.UUID) -> Optional[dict]:
    """Get decrypted OAuth token dict for writing to LiteLLM's auth.json.

    Returns dict with: access_token, refresh_token, expires_at, account_id
    or None if key not found/inactive.
    """
    from src.models.models import ApiKey
    from src.utils.crypto import decrypt_oauth_data

    key = db.query(ApiKey).filter(
        ApiKey.id == key_id,
        ApiKey.is_active == True,
    ).first()

    if not key or not key.oauth_data:
        return None

    return decrypt_oauth_data(key.oauth_data)


def write_chatgpt_auth_json(tokens: dict) -> None:
    """Write OAuth tokens to LiteLLM's chatgpt auth.json file.

    LiteLLM's chatgpt/ provider reads credentials from this file
    instead of accepting api_key parameter. This function writes
    the user's tokens so LiteLLM can use them.

    Thread safety: uses file locking (fcntl) to prevent concurrent writes.
    """
    import fcntl

    token_dir = os.environ.get(
        "CHATGPT_TOKEN_DIR",
        os.path.expanduser("~/.config/litellm/chatgpt"),
    )
    auth_file = os.environ.get("CHATGPT_AUTH_FILE", "auth.json")
    auth_path = os.path.join(token_dir, auth_file)
    lock_path = auth_path + ".lock"

    os.makedirs(token_dir, exist_ok=True)

    auth_data = {
        "access_token": tokens.get("access_token", ""),
        "refresh_token": tokens.get("refresh_token", ""),
        "expires_at": tokens.get("expires_at", 0),
        "account_id": tokens.get("account_id", ""),
    }

    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            with open(auth_path, "w") as f:
                json.dump(auth_data, f)
            logger.debug(f"Wrote chatgpt auth.json to {auth_path}")
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
