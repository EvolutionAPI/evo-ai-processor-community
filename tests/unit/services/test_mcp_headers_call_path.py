"""The CALL PATH of vault header resolution for remote MCP servers.

EVO-2250, review of 2026-07-29 (blocker 1). `_resolve_mcp_headers` existed,
was unit tested, and had ZERO callers: `git grep` returned only its definition.
The real assembly point built `{"url": ..., "headers": custom_server.headers}`
raw, so a remote MCP configured with `credential_refs` and no inline header went
out UNAUTHENTICATED.

These tests assert on the SOURCE of the assembly point, not on the function.
A unit test over the function is exactly what let the defect ship: it passed
while nothing called it.
"""

import pathlib
import re

import pytest

_SERVICE = (
    pathlib.Path(__file__).resolve().parents[3] / "src" / "services" / "adk" / "mcp_service.py"
)


@pytest.fixture(scope="module")
def source() -> str:
    return _SERVICE.read_text()


def _assembly_block(source: str) -> str:
    """The literal that builds server_config for a custom (remote) MCP server."""
    match = re.search(
        r"server_config = \{\s*\n\s*\"url\": custom_server\.url,\s*\n(?P<headers>.*?)\n\s*\}",
        source,
        re.S,
    )
    assert match, "the custom MCP server_config literal moved; this guard needs updating"
    return match.group("headers")


def test_remote_mcp_assembly_resolves_headers_through_the_vault(source: str) -> None:
    """The assembly point must call the resolver, not read the column raw."""
    headers_line = _assembly_block(source)

    assert "_resolve_mcp_headers" in headers_line, (
        "the assembly point builds headers without the vault resolver: "
        f"got {headers_line.strip()!r}"
    )
    assert "custom_server.headers or {}" not in headers_line, (
        "the raw header read is still there, so credential_refs is ignored"
    )


def test_the_resolver_has_a_caller_outside_its_own_definition(source: str) -> None:
    """The regression guard for the whole defect class.

    A resolution helper with no caller is dead code that a green suite cannot
    see. This fails the moment the call is removed again.
    """
    uses = [
        line
        for line in source.splitlines()
        if "_resolve_mcp_headers" in line and not line.strip().startswith("def ")
    ]

    assert uses, "_resolve_mcp_headers has no caller: it is dead code again"


def test_official_mcp_env_is_resolved_through_the_vault(source: str) -> None:
    """Blocker 2: env vars of an official MCP server used to be copied verbatim.

    The read side must go through the resolver so a vault reference is honoured
    once the writer exists.
    """
    match = re.search(
        r"if \"env\" not in server_config:(?P<body>.*?)\n\n",
        source,
        re.S,
    )
    assert match, "the env assembly block moved; this guard needs updating"

    body = match.group("body")
    assert "_resolve_mcp_envs" in body, (
        f"env vars are still copied verbatim, bypassing the vault: {body.strip()!r}"
    )


_CONTEXT = (
    pathlib.Path(__file__).resolve().parents[3] / "src" / "services" / "adk" / "mcp_context.py"
)


@pytest.fixture(scope="module")
def context_source() -> str:
    return _CONTEXT.read_text()


# Review finding 13: both log sites masked ONLY `authorization`, so `X-API-Key`
# and any custom auth header went to the logs in cleartext.
def test_header_values_are_never_logged_verbatim(context_source: str) -> None:
    offending = [
        line.strip()
        for line in context_source.splitlines()
        if "Header values" in line
    ]

    assert not offending, f"header values still reach the log: {offending}"


def test_masking_covers_every_non_safe_header_name(context_source: str) -> None:
    """The classification must be an allowlist of SAFE names, not a denylist of
    auth-looking ones: a denylist misses `X-Tenant-Auth` and friends, which is
    the same lesson the backend redaction already learned."""
    assert "_SAFE_HEADER_NAMES" in context_source, (
        "masking is not derived from a safe-name allowlist"
    )
    assert 'key.lower() == "authorization"' not in context_source, (
        "the single-name heuristic is still there, so other auth headers leak"
    )


# Review of the Reviewer's own half: the env var key on the AGENT's MCP entry is
# `environments`, not `envs`.
#
# Evidence across the pipeline: the front's MCPConfigDialog writes
# `environments`, and the core validates and REWRITES the persisted entry with
# exactly {id, environments, tools} (config_processor.go:266,278-282). So a
# guard on `envs` never fires for an agent configured through the screen, and the
# resolution stayed inert even with the call wired.
def test_env_resolution_reads_the_key_the_pipeline_actually_writes(source: str) -> None:
    guard = re.search(
        r"(?P<cond>if server\.get\([^\n]*\n?[^\n]*\):)\s*\n\s*if \"env\" not in server_config",
        source,
    )
    assert guard, "the env guard moved; this test needs updating"

    assert "environments" in guard.group("cond"), (
        "the guard reads a key the pipeline never persists: "
        f"got {guard.group('cond')!r}, and the core writes 'environments'"
    )


def test_env_resolver_reads_environments_too(source: str) -> None:
    body = re.search(r"def _resolve_mcp_envs\(server, db\):(?P<body>.*?)\ndef ", source, re.S)
    assert body, "_resolve_mcp_envs moved; this test needs updating"

    assert "environments" in body.group("body"), (
        "_resolve_mcp_envs reads only 'envs', which the pipeline never writes"
    )
