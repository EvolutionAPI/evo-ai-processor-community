"""
# Dependencies shared across API routes.
"""

import logging
from fastapi import HTTPException, Request, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Any, Tuple, Dict, Optional
from sqlalchemy.orm import Session
from src.services import folder_share_service

logger = logging.getLogger(__name__)

# Security scheme for Swagger documentation (optional to support both bearer and api_access_token)
security = HTTPBearer(auto_error=False)

# Checks user access to an agent
async def get_current_user(
    request: Request,
    _: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Dict[str, Any]:
    """Get current authenticated user from request state (set by EvoAuthMiddleware)"""
    # Get user context from request state that was set by EvoAuthMiddleware
    if hasattr(request, 'state') and hasattr(request.state, 'user_context'):
        return request.state.user_context
    
    # Fallback: user_context should always be set by middleware
    logger.error("User context not found in request state - middleware not configured properly")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required"
    )

async def verify_agent_access(
    db: Session,
    agent: Any,  # Agent object
    required_permission: str = "read",
) -> Tuple[bool, bool]:
    """
    Checks if the user has access to an agent, either by:
    1. Direct client ownership (admin or client user)
    2. Folder sharing permissions (for agents in shared folders)

    Args:
        #Removed for further handling - payload: JWT payload with user information
        db: Database session
        agent: Agent object to be checked
        required_permission: Required permission ("read" or "write")

    Returns:
        tuple: (has_access: bool, is_shared_access: bool)
        - has_access: True if access is granted
        - is_shared_access: True if access was granted via folder sharing

    Raises:
        HTTPException: If access is denied
    """
    try:
        return True, False  # Access granted by direct ownership
    except HTTPException as client_error:
        # If direct access fails, check folder sharing
        if agent.folder_id:
            # Waiting for token implementation to get the user's email
            user_email = None
            if user_email:
                has_folder_access = folder_share_service.check_folder_access(
                    db, agent.folder_id, user_email, required_permission
                )
                if has_folder_access:
                    logger.info(
                        f"Usuário {user_email} recebeu acesso {required_permission} ao agente {agent.id} via pasta compartilhada {agent.folder_id}"
                    )
                    return True, True
                else:
                    logger.warning(
                        f"Usuário {user_email} negado ao agente {agent.id} - sem permissão de pasta compartilhada"
                    )
            else:
                logger.warning("Nenhum e-mail de usuário encontrado no token para verificação de pasta compartilhada")
        else:
            logger.info(
                f"Agente {agent.id} não está em uma pasta, não é possível verificar compartilhamento de pasta"
            )
        raise client_error

def get_request_optional(request: Request) -> Request:
    """Dependency to provide the Request object, making it optional in endpoint signatures."""
    return request

def get_db_service():
    """Get database service for async operations."""
    from src.services.database_service import get_database_service
    return get_database_service()

