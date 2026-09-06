"""Name sanitization for whatever reaches an LLM as a callable.

Two consumers, two contracts. Custom HTTP tools need only what the providers
accept in ``tools[].function.name`` -- ``^[a-zA-Z0-9_-]+$``, 64 chars max --
which is ``sanitize_tool_name``. Agent names go through the ADK first, whose
``BaseAgent`` also requires a Python identifier, so a hyphen is valid for the
provider and rejected by the ADK; that intersection is ``sanitize_agent_name``.

Only names we dispatch by ``__name__`` (custom HTTP tools) and agent names may
be renamed here: MCP tool names come from the protocol and are the key that
routes execution back to the server.
"""

import re
from itertools import count
from typing import Container

# What the providers accept verbatim. Anchored with \A...\Z (not ^...$): in
# Python `$` also matches just before a trailing newline, so "valid\n" would
# pass the check and be returned unchanged — still invalid for function.name.
_VALID_NAME = re.compile(r"\A[a-zA-Z0-9_-]+\Z")
# Anything outside that alphabet becomes a single separator.
_INVALID_RUN = re.compile(r"[^a-zA-Z0-9_-]+")
_REPEAT_UNDERSCORE = re.compile(r"_+")

# OpenAI caps function names at 64 characters.
MAX_TOOL_NAME_LENGTH = 64

# Last-resort name when sanitization leaves nothing usable (e.g. a name made
# entirely of invalid characters), so the payload is always valid.
FALLBACK_TOOL_NAME = "tool"


def sanitize_tool_name(name: str) -> str:
    """Coerce ``name`` into ``^[a-zA-Z0-9_-]+$`` for an LLM function name.

    A name the providers already accept comes back untouched — renaming a tool
    that works today would be a silent behaviour change. Otherwise invalid runs
    collapse to ``_``, repeated underscores are squeezed, the edges are trimmed
    and the result is capped at 64 chars, falling back to ``"tool"`` when
    nothing usable is left.
    """
    if not name:
        return FALLBACK_TOOL_NAME

    if _VALID_NAME.match(name) and len(name) <= MAX_TOOL_NAME_LENGTH:
        return name

    sanitized = _INVALID_RUN.sub("_", name)
    sanitized = _REPEAT_UNDERSCORE.sub("_", sanitized).strip("_-")
    sanitized = sanitized[:MAX_TOOL_NAME_LENGTH].strip("_-")
    return sanitized or FALLBACK_TOOL_NAME


def sanitize_agent_name(name: str) -> str:
    """Coerce ``name`` into a name both the ADK and the providers accept.

    ``sanitize_tool_name`` alone is not enough here: it keeps hyphens, which the
    providers allow but ``BaseAgent`` rejects (its name must be a Python
    identifier), so an agent named "suporte-n1" fails to build. Hyphens become
    underscores, a leading digit gains an underscore, and a name the ADK already
    accepts comes back untouched.
    """
    candidate = sanitize_tool_name(name)
    if candidate.isidentifier():
        return candidate

    collapsed = _REPEAT_UNDERSCORE.sub("_", candidate.replace("-", "_")).strip("_")
    if not collapsed:
        return FALLBACK_TOOL_NAME
    if collapsed[0].isdigit():
        collapsed = f"_{collapsed}"
    collapsed = collapsed[:MAX_TOOL_NAME_LENGTH].rstrip("_") or FALLBACK_TOOL_NAME
    return collapsed if collapsed.isidentifier() else FALLBACK_TOOL_NAME


def unique_tool_name(name: str, taken: Container[str] = ()) -> str:
    """Sanitized ``name``, numbered while another tool already answers to it.

    Distinct names can sanitize to the same string ("a b" and "a_b"), and so can
    two long names sharing their first 64 chars. Without this the provider gets
    two declarations under one name and the call lands on whichever tool the
    dispatch finds first.
    """
    candidate = sanitize_tool_name(name)
    if candidate not in taken:
        return candidate

    for suffix in count(2):
        marker = f"_{suffix}"
        numbered = candidate[: MAX_TOOL_NAME_LENGTH - len(marker)] + marker
        if numbered not in taken:
            return numbered
