"""The checkout listener SETs app.current_tenant_id from the runtime_context
tenant, validating it as a UUID first so a malformed context id can never be
interpolated into the SET. CRM-532."""

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
    (sql,), _ = cursor.execute.call_args
    cursor.close.assert_called_once()
    return sql


def test_bind_sets_the_bound_tenant():
    tenant = "11111111-1111-1111-1111-111111111111"
    sql = _run_bind(tenant)
    assert f"set_config('app.current_tenant_id', '{tenant}', false)" in sql


def test_bind_clears_the_guc_when_no_tenant_is_bound():
    # Community/standalone: current_context_id is None. The SET clears the GUC so
    # a pooled connection never carries a previous request's tenant; the empty
    # value reads back as unbound (NULLIF ... '') and the fail-closed policy denies.
    sql = _run_bind(None)
    assert "set_config('app.current_tenant_id', '', false)" in sql


def test_bind_rejects_a_non_uuid_context_id_instead_of_interpolating_it():
    # A context id that is not a UUID (or an injection attempt) must never reach
    # the SET verbatim — it is coerced to empty (unbound), not interpolated.
    sql = _run_bind("'; DROP TABLE evo_ai_agent_processor_sessions; --")
    assert "DROP TABLE" not in sql
    assert "set_config('app.current_tenant_id', '', false)" in sql
