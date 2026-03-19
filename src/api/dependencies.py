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

async def verify_account_access(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> None:
    """
    Verify that the user has access to the account specified in the path.

    This is a simple verification that checks if the account_id from the path
    is in the user's list of accessible accounts.

    Args:
        request: FastAPI request object
        current_user: Current authenticated user

    Raises:
        HTTPException: If user doesn't have access to the account
    """
    # Get account_id from path parameters
    path_params = request.path_params
    account_id = path_params.get('account_id')

    if not account_id:
        # No account_id in path, skip verification
        return

    # Check if user has access to this account
    user_accounts = current_user.get('accounts', [])

    # Convert account_id to string for comparison
    account_id_str = str(account_id)
    user_account_ids = [str(acc) for acc in user_accounts]

    if account_id_str not in user_account_ids:
        logger.warning(
            f"User {current_user.get('id')} attempted to access account {account_id} "
            f"but only has access to accounts: {user_account_ids}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this account"
        )

# JWT authentication has been replaced by Evolution authentication
# Use get_current_account() instead