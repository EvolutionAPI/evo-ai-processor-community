"""
┌──────────────────────────────────────────────────────────────────────────────┐
│ @author: Neriton Dias                                                        │
│ @file: oauth_constants.py                                                    │
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

# OpenAI Codex OAuth Configuration
CODEX_CLIENT_ID = os.getenv(
    "CODEX_OAUTH_CLIENT_ID",
    "app_EMoamEEZ73f0CkXaXp7hrann"  # OpenAI Codex public client ID
)

# OAuth Endpoints
CODEX_AUTH_URL = os.getenv(
    "CODEX_AUTH_URL",
    "https://auth.openai.com/oauth/authorize"
)

CODEX_DEVICE_AUTH_URL = os.getenv(
    "CODEX_DEVICE_AUTH_URL",
    "https://auth.openai.com/oauth/device/code"
)

CODEX_TOKEN_URL = os.getenv(
    "CODEX_TOKEN_URL",
    "https://auth.openai.com/oauth/token"
)

CODEX_USERINFO_URL = os.getenv(
    "CODEX_USERINFO_URL",
    "https://api.openai.com/v1/me"
)

# API Base URL for Codex-authenticated requests
CODEX_API_BASE = os.getenv(
    "CODEX_API_BASE",
    "https://api.openai.com/v1"
)

# Redirect URI for the PKCE browser flow. Must match what the user will see
# in the OpenAI callback (http://localhost:1455/auth/callback by default,
# which matches the upstream Codex CLI and is therefore accepted by
# auth.openai.com for the public Codex client).
CODEX_REDIRECT_URI = os.getenv(
    "CODEX_REDIRECT_URI",
    "http://localhost:1455/auth/callback"
)

# OAuth Scopes. Aligned with the upstream Codex CLI so the id_token carries
# the organization claims needed by _extract_account_id() and so that future
# Codex features (api.connectors.*) work without a re-consent.
CODEX_SCOPES = os.getenv(
    "CODEX_SCOPES",
    "openid profile email offline_access api.connectors.read api.connectors.invoke"
)

# When true, auth.openai.com adds organization claims (org_id, account_id)
# to the id_token. Required for multi-tenant ChatGPT accounts.
CODEX_ID_TOKEN_ADD_ORGS = os.getenv("CODEX_ID_TOKEN_ADD_ORGS", "true").lower() in ("1", "true", "yes")

# Grant type for device code flow
CODEX_GRANT_TYPE_DEVICE = "urn:ietf:params:oauth:grant-type:device_code"
CODEX_GRANT_TYPE_REFRESH = "refresh_token"

# Polling intervals and timeouts
CODEX_DEFAULT_POLL_INTERVAL = 5  # seconds
CODEX_DEVICE_CODE_EXPIRY = 900  # 15 minutes
