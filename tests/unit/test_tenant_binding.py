"""The checkout listener SETs app.current_tenant_id from the runtime_context
tenant, validating it as a UUID first (so a malformed context id can never
reach the GUC) and passing it as a BOUND parameter (so it is never interpolated
into the SQL). CRM-532."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.config import tenant_binding


def _run_bind(context_id):
    conn = MagicMock()
    cursor = conn.cursor.return_value
    with patch.object(
        tenant_binding.runtime_context, "current_context_id", return_value=context_id
    ):
        tenant_binding._bind_current_tenant(conn, None, None)
    args, _ = cursor.execute.call_args
    sql, params = args
    cursor.close.assert_called_once()
    return sql, params


def test_bind_sets_the_bound_tenant_as_a_parameter():
    tenant = "11111111-1111-1111-1111-111111111111"
    sql, params = _run_bind(tenant)
    # value goes through the bound param, never interpolated into the SQL text
    assert "set_config('app.current_tenant_id'" in sql
    assert tenant not in sql
    assert params == (tenant,)


def test_bind_clears_the_guc_when_no_tenant_is_bound():
    # Community/standalone: current_context_id is None. The bind SETs '' so a
    # pooled connection never carries a previous request's tenant; the empty value
    # reads back as unbound (NULLIF ... '') and the fail-closed policy denies.
    _sql, params = _run_bind(None)
    assert params == ("",)


def test_bind_sanitizes_a_non_uuid_context_id_to_empty():
    # A context id that is not a valid UUID (or an injection attempt) must never
    # reach the GUC verbatim — it is coerced to empty (unbound). A regex that only
    # checked length/charset would let 36 hyphens through; uuid.UUID rejects it.
    for bad in ("'; DROP TABLE evo_ai_agent_processor_sessions; --", "-" * 36, "nope"):
        _sql, params = _run_bind(bad)
        assert params == ("",), f"{bad!r} must be sanitized to empty, got {params!r}"


def test_placeholder_is_chosen_per_driver():
    # psycopg2 -> %s ; the asyncpg sync-adapter -> $1. Picked off the driver module
    # so one listener binds correctly on both the sync and the ADK async engine.
    # Locally-defined classes carry the module we set without mutating any global.
    class _Psycopg2Conn:
        pass

    _Psycopg2Conn.__module__ = "psycopg2.extensions"

    class _AsyncpgConn:
        pass

    _AsyncpgConn.__module__ = "sqlalchemy.dialects.postgresql.asyncpg"

    assert tenant_binding._placeholder(_Psycopg2Conn()) == "%s"
    assert tenant_binding._placeholder(_AsyncpgConn()) == "$1"
