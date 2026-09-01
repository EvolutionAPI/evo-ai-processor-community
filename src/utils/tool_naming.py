"""Tool-name sanitization for LLM tool/function payloads.

LLM providers constrain ``tools[].function.name`` to ``^[a-zA-Z0-9_-]+$``
(OpenAI rejects anything else with a 400; Anthropic is equally strict). A
custom tool whose name carries a space, accent or punctuation therefore breaks
the whole chat turn — the provider refuses the request and the agent answers
nothing. The readable label the user typed stays available in the tool
*description*, which providers do not constrain.

Only tools we execute by ``__name__`` (custom HTTP tools) should be renamed:
the name we send is the name the ADK dispatches back to us, so renaming is
self-consistent. MCP tools must NOT be renamed here — their names come from the
MCP protocol and are the key the toolset uses to route execution back to the
server, so a rename would break the call.
"""

import re

# Anything outside the provider-accepted alphabet becomes a single separator.
_INVALID_RUN = re.compile(r"[^a-zA-Z0-9_-]+")
_REPEAT_UNDERSCORE = re.compile(r"_+")

# OpenAI caps function names at 64 characters.
MAX_TOOL_NAME_LENGTH = 64

# Last-resort name when sanitization leaves nothing usable (e.g. a name made
# entirely of invalid characters), so the payload is always valid.
FALLBACK_TOOL_NAME = "tool"


def sanitize_tool_name(name: str) -> str:
    """Coerce ``name`` into ``^[a-zA-Z0-9_-]+$`` for an LLM function name.

    Invalid runs collapse to ``_``; repeated underscores are squeezed; leading
    and trailing separators are trimmed; the result is capped at 64 chars and
    falls back to ``"tool"`` when empty. Already-valid names pass through
    unchanged (aside from length capping).
    """
    if not name:
        return FALLBACK_TOOL_NAME

    sanitized = _INVALID_RUN.sub("_", name)
    sanitized = _REPEAT_UNDERSCORE.sub("_", sanitized).strip("_-")
    sanitized = sanitized[:MAX_TOOL_NAME_LENGTH].strip("_-")
    return sanitized or FALLBACK_TOOL_NAME
