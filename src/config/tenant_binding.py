"""Bind the request's tenant onto every DB connection as ``app.current_tenant_id``.

The enterprise overlay (evo-enterprise-licensing-python) puts a fail-closed RLS
policy on the processor-owned tables and a GUC-based column DEFAULT
(``NULLIF(current_setting('app.current_tenant_id', true), '')::uuid``). With that,
an INSERT that does not name ``tenant_id`` — the processor's own metrics/metadata
writes AND the ADK ``DatabaseSessionService`` session write, which this code does
not control — picks up whatever tenant is bound on the connection; an unbound
connection defaults to NULL and the NOT NULL rejects it (fail-closed).

This module is the app half: on every pool checkout it SETs the GUC from the
``runtime_context`` tenant. That is ``None`` under community/standalone (the SET
clears the GUC, harmless — those deployments have no RLS/NOT NULL), and the real
tenant under enterprise. Binding at checkout (not once at connect) re-scopes a
pooled connection each time it is handed out, so it never carries a previous
request's tenant.

CRM-532 — the app-side prerequisite of CRM-510.
"""

import logging
import re

from sqlalchemy import event

from src.evo_extension_points import runtime_context

logger = logging.getLogger(__name__)

# The tenant id is a UUID (or empty when unbound). Validate before it reaches the
# SET so a malformed context id can never be interpolated into SQL.
_UUID_RE = re.compile(r"\A[0-9a-fA-F-]{36}\Z")


def _tenant_literal() -> str:
    tenant = runtime_context.current_context_id()
    if not tenant:
        return ""
    value = str(tenant)
    return value if _UUID_RE.match(value) else ""


def _bind_current_tenant(dbapi_connection, connection_record, connection_proxy):
    # set_config(..., is_local=false) = session scope, re-applied on each checkout.
    # A literal (validated UUID or empty) rather than a bound param so the same
    # handler works across drivers (psycopg2 %s vs asyncpg $1).
    sql = f"SELECT set_config('app.current_tenant_id', '{_tenant_literal()}', false)"
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(sql)
    finally:
        cursor.close()


def install_tenant_binding(engine) -> None:
    """Register the tenant-binding checkout listener on ``engine`` once."""
    if event.contains(engine, "checkout", _bind_current_tenant):
        return
    event.listen(engine, "checkout", _bind_current_tenant)
    logger.info("tenant binding installed on engine %r", engine.url.database)
