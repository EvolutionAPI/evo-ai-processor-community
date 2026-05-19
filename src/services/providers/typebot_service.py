"""
Typebot provider service for external agent integration.
"""

import logging
from typing import Dict, Any, Optional, List, Tuple
import httpx

logger = logging.getLogger(__name__)


class TypebotService:
    """Service for integrating with Typebot."""

    _session_cache: Dict[str, Dict[str, Optional[str]]] = {}

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
        self.integration_config = config
        self._cache_ns = f"{self.url}:{self.typebot}"
        
        if not self.url:
            raise ValueError("Typebot url is required")
        if not self.typebot:
            raise ValueError("Typebot typebot ID is required")

    async def start_session(
        self,
        session_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Optional[str]]]:
        """
        Start a new Typebot session.

        Args:
            session_id: Session identifier
            context: Optional context variables

        Returns:
            Typebot session ID or None
        """
        prefilled = {
            "remoteJid": context.get("remoteJid", "") if context else "",
            "pushName": context.get("pushName", "") if context else "",
            "instanceName": context.get("instanceName", "") if context else "",
            "serverUrl": context.get("serverUrl", "") if context else "",
            "apiKey": context.get("apiKey", "") if context else "",
            "ownerJid": context.get("ownerJid", "") if context else "",
        }

        is_only_registering = bool(config.get("isOnlyRegistering")) if isinstance(config := getattr(self, "integration_config", None), dict) else False

        if self.api_version == "latest":
            endpoint = f"{self.url}/api/v1/typebots/{self.typebot}/startChat"
            payload = {
                "resultId": session_id,
                "isOnlyRegistering": is_only_registering,
                "prefilledVariables": prefilled,
                "textBubbleContentFormat": "richText",
            }
        else:
            endpoint = f"{self.url}/api/v1/sendMessage"
            payload = {
                "startParams": {
                    "publicId": self.typebot,
                    "prefilledVariables": prefilled,
                },
            }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(endpoint, json=payload)
                response.raise_for_status()
                response_data = response.json()
                typebot_session_id = response_data.get("sessionId")
                if not typebot_session_id:
                    logger.error("Typebot startChat response missing sessionId")
                    return None

                reply_id = None
                input_obj = response_data.get("input") if isinstance(response_data, dict) else None
                if isinstance(input_obj, dict):
                    reply_id = input_obj.get("id")

                initial_messages = response_data.get("messages", [])
                initial_text = self._format_messages(initial_messages) if initial_messages else ""
                input_block = self._format_input_block(input_obj)
                if input_block:
                    initial_text = (initial_text.strip() + "\n\n" + input_block).strip() if initial_text else input_block

                return {
                    "session_id": typebot_session_id,
                    "reply_id": reply_id,
                    "initial_text": initial_text,
                }
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
            session_id: ADK session ID (used as correlation, not Typebot session)
            context: Optional context variables

        Returns:
            Formatted response text from Typebot messages
        """
        cache_key = f"{self._cache_ns}:{session_id or 'default'}"
        session_info = TypebotService._session_cache.get(cache_key)
        logger.info(f"Typebot send_message: session_id={session_id!r} cache_hit={session_info is not None}")

        if session_info:
            try:
                response_text, next_reply_id = await self._continue_chat(
                    session_info["session_id"],
                    message,
                    session_info.get("reply_id"),
                )
                session_info["reply_id"] = next_reply_id
                return response_text
            except Exception as e:
                if "404" in str(e):
                    logger.info("Typebot session expired, starting new one")
                    TypebotService._session_cache.pop(cache_key, None)
                    session_info = None
                else:
                    raise

        if not session_info:
            session_info = await self.start_session(session_id or cache_key, context)
            if not session_info:
                raise Exception("Failed to start Typebot session")
            TypebotService._session_cache[cache_key] = session_info

        initial_text = session_info.pop("initial_text", "") or ""

        if initial_text and session_info.get("reply_id"):
            logger.debug("Typebot new session: returning greeting, waiting for user input")
            return initial_text

        response_text, next_reply_id = await self._continue_chat(
            session_info["session_id"],
            message,
            session_info.get("reply_id"),
        )
        session_info["reply_id"] = next_reply_id

        if initial_text:
            combined = (initial_text.strip() + "\n\n" + response_text.strip()).strip()
            return combined
        return response_text

    async def _continue_chat(
        self,
        typebot_session_id: str,
        message: str,
        reply_id: Optional[str] = None,
    ) -> Tuple[str, Optional[str]]:
        """Continue an existing Typebot chat session."""
        # Extract actual session ID (Typebot format: {id}-{sessionId})
        actual_session_id = (
            typebot_session_id.split("-")[-1]
            if "-" in typebot_session_id
            else typebot_session_id
        )

        if self.api_version == "latest":
            metadata: Dict[str, Any] = {}
            if reply_id:
                metadata["replyId"] = reply_id

            message_payload = {
                "type": "text",
                "text": message,
                "metadata": metadata,
                "attachedFileUrls": [],
            }
            endpoint = f"{self.url}/api/v1/sessions/{actual_session_id}/continueChat"
            payload = {
                "message": message_payload,
                "textBubbleContentFormat": "richText",
            }
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
                next_input = response_data.get("input") if isinstance(response_data, dict) else None
                next_reply_id = next_input.get("id") if isinstance(next_input, dict) else None
                formatted = self._format_messages(messages)
                input_block = self._format_input_block(next_input)
                if input_block:
                    formatted = (formatted.strip() + "\n\n" + input_block).strip() if formatted else input_block
                return formatted, next_reply_id
        except httpx.HTTPStatusError as e:
            logger.error(f"Typebot API error: {e.response.status_code} - {e.response.text}")
            raise Exception(f"Typebot API error: {e.response.status_code}")
        except Exception as e:
            logger.error(f"Error calling Typebot: {e}")
            raise

    def _format_input_block(self, input_obj: Optional[Dict[str, Any]]) -> str:
        """
        Format a Typebot input block (choice, pictureChoice) as a numbered list.

        Returns empty string for free-text inputs (text, number, email, etc.)
        """
        if not isinstance(input_obj, dict):
            return ""

        input_type = input_obj.get("type", "")

        if input_type in ("choice", "multipleChoiceInput"):
            items = input_obj.get("items", [])
            lines = []
            for i, item in enumerate(items, 1):
                content = (item.get("content") or "").strip()
                if content:
                    lines.append(f"{i}. {content}")
            return "\n".join(lines)

        if input_type == "pictureChoice":
            items = input_obj.get("items", [])
            lines = []
            for i, item in enumerate(items, 1):
                title = (item.get("title") or "").strip()
                pic_src = (item.get("pictureSrc") or "").strip()
                if title and pic_src:
                    lines.append(f"{i}. {title}\n   {pic_src}")
                elif title:
                    lines.append(f"{i}. {title}")
            return "\n".join(lines)

        return ""

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
