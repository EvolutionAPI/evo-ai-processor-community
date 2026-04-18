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

import hashlib
import httpx
import json
import logging
import os
import secrets
import uuid
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from fastapi import HTTPException, status

from src.models.models import ApiKey
from src.utils.crypto import encrypt_oauth_data, decrypt_oauth_data
from src.config.oauth_constants import (
    CODEX_CLIENT_ID,
    CODEX_TOKEN_URL,
    CODEX_USERINFO_URL,
    CODEX_SCOPES,
    CODEX_GRANT_TYPE_REFRESH,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PKCE Browser Flow
# ---------------------------------------------------------------------------


async def generate_auth_url(
    db: Session,
    client_id: uuid.UUID,
    name: str,
) -> dict:
    """
    Generate an OAuth authorization URL using PKCE (S256).
    Creates an ApiKey record in 'pending' state and returns the URL + key_id.
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    state = secrets.token_urlsafe(32)

    pending = encrypt_oauth_data({"pending_verifier": code_verifier, "state": state})

    api_key_record = ApiKey(
        id=uuid.uuid4(),
        name=name.strip() or "OpenAI Codex",
        provider="openai-codex",
        key=None,
        auth_type="oauth_codex",
        oauth_data=pending,
        is_active=False,
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

    params = {
        "response_type": "code",
        "client_id": CODEX_CLIENT_ID,
        "redirect_uri": "http://localhost:1455/auth/callback",
        "scope": CODEX_SCOPES,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "codex_cli_simplified_flow": "true",
    }
    url = f"https://auth.openai.com/oauth/authorize?{urlencode(params)}"
    return {"authorize_url": url, "key_id": api_key_record.id}


async def complete_auth_flow(
    db: Session,
    key_id: uuid.UUID,
    callback_url: str,
) -> dict:
    """
    Complete the PKCE flow by exchanging the authorization code for tokens.
    """
    key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not key or not key.oauth_data:
        raise ValueError("Key not found")

    pending = decrypt_oauth_data(key.oauth_data)
    code_verifier = pending.get("pending_verifier")
    if not code_verifier:
        raise ValueError("No pending verifier found")

    parsed = urlparse(callback_url)
    params = parse_qs(parsed.query)
    code = params.get("code", [None])[0]
    if not code:
        raise ValueError("No authorization code in callback URL")

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            CODEX_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost:1455/auth/callback",
                "client_id": CODEX_CLIENT_ID,
                "code_verifier": code_verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        tokens = resp.json()

    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token", "")
    id_token = tokens.get("id_token", "")
    account_id = _extract_account_id(id_token) or _extract_account_id(access_token) or ""
    expires_at = _extract_token_expiry(access_token)

    oauth_data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "expires_at": expires_at,
        "account_id": account_id,
        "plan_type": "plus",
    }
    key.oauth_data = encrypt_oauth_data(oauth_data)
    key.is_active = True
    db.commit()
    return {"status": "ok", "key_id": str(key_id), "message": "Connected successfully"}


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------


def _extract_account_id(token: str) -> Optional[str]:
    """Try to extract the account / org id from a JWT token (access_token or id_token)."""
    if not token:
        return None
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        # Fix base64 padding
        payload += "=" * (4 - len(payload) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload))
        return decoded.get("org_id") or decoded.get("sub") or decoded.get("account_id")
    except Exception:
        return None


def _extract_token_expiry(token: str) -> Optional[str]:
    """Try to extract the expiry (exp) from a JWT token and return as ISO string."""
    if not token:
        return None
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload))
        exp = decoded.get("exp")
        if exp:
            return datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Status, disconnect, fresh-token (kept from original)
# ---------------------------------------------------------------------------


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
        "connected": bool(oauth_data.get("access_token")),
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
    if not oauth_data.get("access_token"):
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
