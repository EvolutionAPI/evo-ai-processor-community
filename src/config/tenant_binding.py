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
import uuid

from sqlalchemy import event

from src.evo_extension_points import runtime_context

logger = logging.getLogger(__name__)


def _tenant_value() -> str:
    """The runtime tenant as a canonical UUID string, or ``''`` when there is no
    tenant (community/standalone) or the context id is not a valid UUID.

    Parsing with ``uuid.UUID`` — not a length/charset regex — is deliberate: a
    look-alike that a ``[0-9a-fA-F-]{36}`` regex would accept (e.g. 36 hyphens)
    is NOT a UUID. Letting it through would bind garbage into the GUC and make the
    column DEFAULT's ``::uuid`` cast raise ``invalid input syntax for type uuid``
    on the next INSERT, instead of reading as unbound (empty -> fail-closed)."""
    tenant = runtime_context.current_context_id()
    if not tenant:
        return ""
    try:
        return str(uuid.UUID(str(tenant)))
    except (ValueError, AttributeError, TypeError):
        return ""


def _placeholder(dbapi_connection) -> str:
    """psycopg2 binds with pyformat (``%s``); the asyncpg sync-adapter binds with
    asyncpg's native numeric (``$1``). Pick by driver so ONE listener serves both
    the processor's sync engine and the ADK's async session engine."""
    return "$1" if "asyncpg" in type(dbapi_connection).__module__ else "%s"


def _bind_current_tenant(dbapi_connection, connection_record, connection_proxy):
    # set_config(..., is_local=false) = session scope, re-applied on each checkout.
    # The tenant is passed as a BOUND parameter (never interpolated into the SQL);
    # the only per-driver bit is the placeholder token, which carries no input.
    sql = (
        "SELECT set_config('app.current_tenant_id', "
        f"{_placeholder(dbapi_connection)}, false)"
    )
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(sql, (_tenant_value(),))
    finally:
        cursor.close()


def install_tenant_binding(engine) -> None:
    """Register the tenant-binding checkout listener on ``engine`` once."""
    if event.contains(engine, "checkout", _bind_current_tenant):
        return
    event.listen(engine, "checkout", _bind_current_tenant)
    logger.info("tenant binding installed on engine %r", engine.url.database)
