"""EVO-2181: every incoming file (image included) must reach the model.

process_files used to append the file part to `file_parts` only `if is_audio`, so
images were blobbed + saved to artifacts but never sent to the LLM, and
create_content("", file_parts) returned None -> "No content to process".
"""

from __future__ import annotations

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock

from src.schemas.chat import FileData
from src.services.adk.runners.runner_utils import RunnerUtils


def _utils():
    # Bypass __init__ (which builds AgentBuilder(db)); the methods under test use
    # neither self.db nor self.agent_builder.
    return RunnerUtils.__new__(RunnerUtils)


def _artifacts():
    a = MagicMock()
    a.save_artifact = AsyncMock()
    return a


def _file(name, ctype):
    return FileData(
        filename=name, content_type=ctype, data=base64.b64encode(b"bytes-" + name.encode()).decode()
    )


def _run(coro):
    return asyncio.run(coro)


def test_image_is_appended_to_file_parts():
    parts, transcribed = _run(
        _utils().process_files([_file("photo.png", "image/png")], _artifacts(), "agent", "ext", "sess")
    )
    assert len(parts) == 1
    assert parts[0].inline_data.mime_type == "image/png"
    assert transcribed == []


def test_audio_still_appended():
    parts, _ = _run(
        _utils().process_files([_file("voice.ogg", "audio/ogg")], _artifacts(), "a", "e", "s")
    )
    assert len(parts) == 1
    assert parts[0].inline_data.mime_type == "audio/ogg"


def test_image_and_audio_both_appended():
    parts, _ = _run(
        _utils().process_files(
            [_file("p.png", "image/png"), _file("v.ogg", "audio/ogg")], _artifacts(), "a", "e", "s"
        )
    )
    assert len(parts) == 2


def test_create_content_with_image_only_is_not_none():
    utils = _utils()
    parts, _ = _run(utils.process_files([_file("photo.png", "image/png")], _artifacts(), "a", "e", "s"))
    content = utils.create_content("", parts)
    assert content is not None  # regression guard for "No content to process"
    assert content.role == "user"
    assert len(content.parts) == 2  # empty text part + the image file part


def test_create_content_empty_is_none():
    assert _utils().create_content("", []) is None
