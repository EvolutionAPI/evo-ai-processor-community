"""
┌──────────────────────────────────────────────────────────────────────────────┐
│ @author: Davidson Gomes                                                      │
│ @file: permission_service.py                                                 │
│ Developed by: Davidson Gomes                                                 │
│ Creation date: January 27, 2025                                              │
│ Contact: contato@evolution-api.com                                           │
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

from typing import Optional
from fastapi import HTTPException, Request
from src.utils.logger import setup_logger
from src.services.evo_auth_service import EvoAuthService

logger = setup_logger(__name__)

class PermissionService:
    """Permission validation service for FastAPI
    
    Delegates permission checks to EvoAuthService for consistent behavior
    across all authentication and authorization operations.
    """
    
    def __init__(self, evo_auth_base_url: str):
        self.evo_auth_service = EvoAuthService(evo_auth_base_url)
        logger.info(f"Permission service initialized with EvoAuthService")
    
    async def check_permission(self, auth_token: str, permission_key: str, token_type: str = "bearer") -> bool:
        """Check if user has specific permission via evo-auth-service
        
        Delegates to EvoAuthService.check_permission for unified permission handling.
        
        Args:
            auth_token: Authentication token (bearer or api_access_token)
            permission_key: Permission key (e.g., 'ai_clients.usage')
            token_type: Type of token ('bearer' or 'api_access_token')
            
        Returns:
            True if user has permission, False otherwise
        """
        return await self.evo_auth_service.check_permission(auth_token, permission_key, token_type)
    
    async def validate_permission(self, request: Request, resource: str, action: str) -> None:        
        # Build permission key
        permission_key = f"{resource}.{action}"
        
        # Get user context from request state (set by EvoAuthMiddleware)
        user_context = getattr(request.state, 'user_context', None)
        
        if not user_context:
            logger.error("User context not found in request state")
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "Authentication required",
                    "code": "ERR_UNAUTHORIZED",
                    "message": "User context not available. Ensure EvoAuthMiddleware is configured."
                }
            )
        
        # Get token info
        token_info = user_context.get("token_info", {})
        token_type = token_info.get("type", "bearer")

        # Agent Bots have full access (validated by middleware)
        if user_context.get("is_agent_bot"):
            logger.info(f"Permission: Agent Bot access granted for permission {permission_key}")
            return
        
        auth_token = token_info.get("access_token")
        if not auth_token:
            logger.error("Token not found in user context")
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "Authorization token required",
                    "code": "ERR_UNAUTHORIZED",
                    "message": "Bearer token not available in user context"
                }
            )
        
        # Validate permission via evo-auth-service
        has_permission = await self.check_permission(auth_token, permission_key, token_type)
        
        logger.info(f"Permission: Has permission {permission_key}: {has_permission}")
        
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Insufficient permissions",
                    "code": "ERR_FORBIDDEN",
                    "message": f"User does not have required permission: {permission_key}",
                    "permission": permission_key
                }
            )
        
        logger.info(f"Permission: Access granted for permission {permission_key}")


# Global singleton instance
_permission_service: Optional[PermissionService] = None

def initialize_permission_service(evo_auth_base_url: str) -> None:
    """Initialize the global permission service"""
    global _permission_service
    _permission_service = PermissionService(evo_auth_base_url)
    logger.info("Global permission service initialized")

def permission_service() -> PermissionService:
    """Get the global permission service instance"""
    global _permission_service
    if _permission_service is None:
        raise RuntimeError("Permission service not initialized. Call initialize_permission_service first.")
    return _permission_service
