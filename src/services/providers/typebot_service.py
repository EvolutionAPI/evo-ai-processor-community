"""
Typebot provider service for external agent integration.
"""

import logging
from typing import Dict, Any, Optional, List
import httpx

logger = logging.getLogger(__name__)


class TypebotService:
    """Service for integrating with Typebot."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Typebot service.

        Args:
            config: Configuration dictionary with:
                - url: Base URL of Typebot instance
                - typebot: Public ID of the typebot
                - apiVersion: API version ('latest' or legacy version)
        """
        self.url = config.get("url")
        self.typebot = config.get("typebot")
        self.api_version = config.get("apiVersion", "latest")
        
        if not self.url:
            raise ValueError("Typebot url is required")
        if not self.typebot:
            raise ValueError("Typebot typebot ID is required")

    async def start_session(
        self,
        session_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Start a new Typebot session.

        Args:
            session_id: Session identifier
            context: Optional context variables

        Returns:
            Typebot session ID or None
        """
        if self.api_version == "latest":
            endpoint = f"{self.url}/api/v1/typebots/{self.typebot}/startChat"
            payload = {
                "prefilledVariables": {
                    "remoteJid": context.get("remoteJid", "") if context else "",
                    "pushName": context.get("pushName", "") if context else "",
                    "instanceName": context.get("instanceName", "") if context else "",
                    "serverUrl": context.get("serverUrl", "") if context else "",
                    "apiKey": context.get("apiKey", "") if context else "",
                    "ownerJid": context.get("ownerJid", "") if context else "",
                },
            }
        else:
            endpoint = f"{self.url}/api/v1/sendMessage"
            payload = {
                "startParams": {
                    "publicId": self.typebot,
                    "prefilledVariables": {
                        "remoteJid": context.get("remoteJid", "") if context else "",
                        "pushName": context.get("pushName", "") if context else "",
                        "instanceName": context.get("instanceName", "") if context else "",
                        "serverUrl": context.get("serverUrl", "") if context else "",
                        "apiKey": context.get("apiKey", "") if context else "",
                        "ownerJid": context.get("ownerJid", "") if context else "",
                    },
                },
            }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(endpoint, json=payload)
                response.raise_for_status()
                response_data = response.json()
                return response_data.get("sessionId")
        except Exception as e:
            logger.error(f"Error starting Typebot session: {e}")
            return None

    async def send_message(
        self,
        message: str,
        session_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Send a message to Typebot and get the response.

        Args:
            message: User message
            session_id: Typebot session ID
            context: Optional context variables

        Returns:
            Formatted response text from Typebot messages
        """
        if not session_id:
            # Start new session
            session_id = await self.start_session("new", context)
            if not session_id:
                raise Exception("Failed to start Typebot session")

        # Extract actual session ID (Typebot format: {id}-{sessionId})
        actual_session_id = session_id.split("-")[-1] if "-" in session_id else session_id

        # Continue chat
        if self.api_version == "latest":
            endpoint = f"{self.url}/api/v1/sessions/{actual_session_id}/continueChat"
            payload = {"message": message}
        else:
            endpoint = f"{self.url}/api/v1/sendMessage"
            payload = {
                "message": message,
                "sessionId": actual_session_id,
            }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(endpoint, json=payload)
                response.raise_for_status()
                response_data = response.json()
                
                # Process messages array and format text
                messages = response_data.get("messages", [])
                return self._format_messages(messages)
        except httpx.HTTPStatusError as e:
            logger.error(f"Typebot API error: {e.response.status_code} - {e.response.text}")
            raise Exception(f"Typebot API error: {e.response.status_code}")
        except Exception as e:
            logger.error(f"Error calling Typebot: {e}")
            raise

    def _format_messages(self, messages: List[Dict[str, Any]]) -> str:
        """
        Format Typebot messages array into plain text.

        Args:
            messages: Array of Typebot message objects

        Returns:
            Formatted text string
        """
        formatted_parts = []
        
        for message in messages:
            msg_type = message.get("type")
            
            if msg_type == "text":
                # Extract text from richText
                rich_text = message.get("content", {}).get("richText", [])
                for text_block in rich_text:
                    text_content = self._extract_text_from_rich_text(text_block)
                    if text_content:
                        formatted_parts.append(text_content)
            elif msg_type == "image":
                url = message.get("content", {}).get("url", "")
                if url:
                    formatted_parts.append(f"[Image: {url}]")
            elif msg_type == "video":
                url = message.get("content", {}).get("url", "")
                if url:
                    formatted_parts.append(f"[Video: {url}]")
            elif msg_type == "audio":
                url = message.get("content", {}).get("url", "")
                if url:
                    formatted_parts.append(f"[Audio: {url}]")
        
        return "\n".join(formatted_parts)

    def _extract_text_from_rich_text(self, element: Dict[str, Any]) -> str:
        """Recursively extract text from rich text element."""
        text = ""
        
        if element.get("text"):
            text += element["text"]
        
        children = element.get("children", [])
        for child in children:
            if child.get("type") != "a":  # Skip links for now
                text += self._extract_text_from_rich_text(child)
        
        # Apply formatting
        if element.get("type") == "p":
            text = text.strip() + "\n"
        elif element.get("type") == "ol":
            # Numbered list
            lines = text.split("\n")
            text = "\n".join(f"{i+1}. {line}" for i, line in enumerate(lines) if line)
        elif element.get("type") == "li":
            text = "  " + text
        
        # Apply bold, italic, underline
        formats = ""
        if element.get("bold"):
            formats += "*"
        if element.get("italic"):
            formats += "_"
        if element.get("underline"):
            formats += "~"
        
        if formats:
            text = f"{formats}{text}{formats[::-1]}"
        
        return text
