"""
Send Private Message Tool

This tool allows agents to send private messages (reminders) in conversations.
Private messages are only visible to agents, not to customers.
"""

from typing import Optional, Dict, Any
from google.adk.tools import FunctionTool, ToolContext
from src.services.adk.tools.evo_crm.base import EvoCrmClient
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def _extract_conversation_id_from_metadata(tool_context: Optional[ToolContext]) -> Optional[str]:
    """Extract conversation_id from tool_context metadata.
    
    Looks for conversation_id in various possible locations:
    - evoai_crm_data.conversation_id (UUID)
    - evoai_crm_data.conversation.id (display_id)
    - conversation_id (direct)
    - conversationId (camelCase)
    """
    if not tool_context or not hasattr(tool_context, 'state'):
        return None
    
    state = tool_context.state
    
    # Try evoai_crm_data
    evoai_crm_data = state.get("evoai_crm_data", {})
    if isinstance(evoai_crm_data, dict):
        # Try conversation_id (UUID)
        conversation_id = evoai_crm_data.get("conversation_id")
        if conversation_id:
            return str(conversation_id)
        
        # Try conversation.id (display_id)
        conversation = evoai_crm_data.get("conversation", {})
        if isinstance(conversation, dict):
            conv_id = conversation.get("id")
            if conv_id:
                return str(conv_id)
    
    # Try direct keys
    for key in ["conversation_id", "conversationId"]:
        if key in state:
            return str(state[key])
    
    return None


def create_send_private_message_tool() -> FunctionTool:
    """Create the send_private_message tool for sending private messages (reminders).

    This tool sends private messages in conversations that are only visible to agents.
    Useful for creating reminders, internal notes, or agent-to-agent communication.
    """
    
    client = EvoCrmClient()
    
    async def send_private_message(
        content: str,
        conversation_id: Optional[str] = None,
        tool_context: Optional[ToolContext] = None,
    ) -> Dict[str, Any]:
        """Send a private message (reminder) in a conversation.

        Use this tool when:
        - The user requests to set a reminder
        - You need to create an internal note for other agents
        - You want to leave a private message about the conversation
        - The agent configuration allows reminders ("permitir registrar lembretes")

        Private messages are only visible to agents and not shown to customers.
        They are useful for:
        - Setting reminders for follow-ups
        - Leaving notes about customer preferences
        - Recording important context for future interactions
        - Agent-to-agent communication

        Args:
            content: The content of the private message/reminder (required)
                    Can be plain text or HTML formatted
            conversation_id: The ID of the conversation to send the message in (optional,
                           will be extracted from metadata if not provided)
            tool_context: The tool context containing session information (optional)

        Returns:
            Dictionary with message status and details:
            {
                "status": "success" | "error",
                "message": "Human-readable message",
                "conversation_id": "...",
                "message_id": "...",
                "details": {...}
            }
        """
        try:
            # Extract conversation_id from metadata if not provided
            effective_conversation_id = conversation_id
            if not effective_conversation_id and tool_context:
                effective_conversation_id = _extract_conversation_id_from_metadata(tool_context)
                if effective_conversation_id:
                    logger.info(f"Extracted conversation_id from metadata: {effective_conversation_id}")
            
            # Validate required parameters
            if not effective_conversation_id:
                return {
                    "status": "error",
                    "message": "conversation_id is required. It should be automatically extracted from the conversation context, but if not available, please provide it explicitly.",
                    "conversation_id": None,
                }
            
            if not content or not content.strip():
                return {
                    "status": "error",
                    "message": "content is required and cannot be empty",
                    "conversation_id": effective_conversation_id,
                }
            
            logger.info(
                f"Sending private message in conversation {effective_conversation_id}: {content[:100]}..."
            )
            
            # Prepare request body
            # Content can be plain text or HTML - if it doesn't look like HTML, wrap in <p> tags
            formatted_content = content
            if not content.strip().startswith("<"):
                # Plain text, wrap in paragraph tag
                formatted_content = f"<p>{content}</p>"
            
            request_body: Dict[str, Any] = {
                "content": formatted_content,
                "message_type": "outgoing",
                "private": True,
            }
            
            # Make API request to create private message
            endpoint = f"/conversations/{effective_conversation_id}/messages"
            
            try:
                response = await client.post(
                    endpoint=endpoint,
                    json_data=request_body,
                )
                
                logger.info(
                    f"Successfully sent private message in conversation {effective_conversation_id}"
                )
                
                # Extract message info from response if available
                message_id = None
                if isinstance(response, dict):
                    message_id = response.get("id") or response.get("message_id")
                
                success_message = (
                    f"Private message successfully sent in conversation {effective_conversation_id}"
                    + (f" (message ID: {message_id})" if message_id else "")
                )
                
                return {
                    "status": "success",
                    "message": success_message,
                    "conversation_id": effective_conversation_id,
                    "message_id": message_id,
                    "content": content,
                    "details": response,
                }
                
            except Exception as api_error:
                error_message = str(api_error)
                
                # Provide more specific error messages
                if "404" in error_message or "not found" in error_message.lower():
                    error_message = (
                        f"Conversation {effective_conversation_id} not found. "
                        "Please verify the conversation ID is correct."
                    )
                elif "401" in error_message or "unauthorized" in error_message.lower():
                    error_message = (
                        "Authentication failed. Please check EVOAI_CRM_API_TOKEN configuration."
                    )
                elif "400" in error_message or "bad request" in error_message.lower():
                    error_message = (
                        f"Invalid request. Please check conversation_id ({effective_conversation_id}) "
                        "is valid and content is properly formatted."
                    )
                
                logger.error(f"Failed to send private message: {error_message}")
                
                return {
                    "status": "error",
                    "message": error_message,
                    "conversation_id": effective_conversation_id,
                    "content": content,
                    "error": str(api_error),
                }
                
        except Exception as e:
            error_msg = f"Unexpected error sending private message: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg,
                "conversation_id": effective_conversation_id if 'effective_conversation_id' in locals() else None,
                "content": content,
                "error": str(e),
            }
    
    # Set function metadata for better tool description
    send_private_message.__name__ = "send_private_message"
    send_private_message.__doc__ = """Send a private message (reminder) in a conversation.
    
    Private messages are only visible to agents and not shown to customers.
    Use this tool to create reminders, internal notes, or agent-to-agent communication.
    
    When to use:
    - User requests to set a reminder
    - Need to create internal notes for other agents
    - Want to leave private context about the conversation
    - Agent configuration allows reminders
    
    Args:
        content: The content of the private message/reminder (required)
                Can be plain text or HTML formatted
        conversation_id: The ID of the conversation to send the message in (optional,
                       will be automatically extracted from conversation context)
        tool_context: The tool context containing session information (automatically provided)
    
    Returns:
        Dictionary with message status and details
    """
    
    return send_private_message

