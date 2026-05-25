# Changelog

All notable changes to this microservice will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.0-rc4] - 2026-05-25

Point release — adds Typebot interactive button rendering. Other subsystems unchanged.

### Added

- **Typebot interactive buttons (#12)** — Typebot `choice` blocks now render as interactive button messages instead of plain text. Paired with corresponding changes in `evo-ai-crm-community` and `evo-ai-frontend-community`.

## [v1.0.0-rc3] - 2026-05-17

Integration release — adds native tools for the LLM agent (Knowledge Nexus search, manage_conversation_labels, link_product_to_pipeline_item), injection of the products catalog into the agent context, merging of integrations from the `agent_integrations` table into the agent config at runtime, and bug fixes in the Postgres handshake and chat handler binding. Also declares `EXTENSION_POINTS.md` as the public extension contract for the Enterprise edition.

### Added

- **EXTENSION_POINTS.md (EVO-1376)** (#9) — document with the extension points exposed by the processor to the Enterprise edition. Versioned contract, no new code.
- **`knowledge_nexus_search` — native tool** — agents gain access to semantic search on Nexus spaces directly from the prompt, without needing to configure a custom tool.
- **`manage_conversation_labels` — native tool** — list/add/remove labels on the conversation by the agent itself.
- **`link_product_to_pipeline_item` — native tool** — the agent can link catalog products to the active pipeline item.
- **Products catalog in the agent context** — products attached to the agent are injected into the prompt, letting the LLM have context about the offering.
- **Pipeline and labels usage hints in the prompt** — `pipeline_manipulation` and `manage_labels` gain structured hints in the system prompt to guide the LLM on when and how to use them.

### Changed

- **`llm-agent` — integrations merge** — integrations from the `agent_integrations` table are now merged into the agent config at runtime. Previously the config was static; now it reflects the latest state of integrations configured via the UI.
- **Docs** standardized for Evolution Foundation 2026 (README, LICENSE, NOTICE, TRADEMARKS).
- **Docs (org)** — GitHub URLs updated from `EvolutionAPI` to `evolution-foundation`.

### Fixed

- **DB — `sslmode` → `ssl` for asyncpg** — the asyncpg driver does not understand `sslmode` (a psycopg/libpq parameter). Connections with `sslmode=require` in the connection string failed silently; we now translate it to the asyncpg native parameter.
- **Chat handler — request param rebind** — fixes the binding of the `request` parameter in the chat handler that caused `NameError` on certain error paths.

## [v1.0.0-rc2] - 2026-05-05

### Fixed

- **Container startup**: invoke `alembic` and `uvicorn` via `python -m` instead of console scripts, preventing `sh -c` from interpreting the entrypoints incorrectly on some images. (#7)
- **Migration `26a14ac7025d`**: added `if_not_exists=True` on `op.create_table('evo_agent_processor_execution_metrics')`, making the migration safe to re-run in environments where the table has already been created by another service (shared database). (#7)

## [v1.0.0-rc1] - 2026-04-24

### Added

- First public release candidate of `evo-ai-processor-community`.

### Changed

- Refactored to remove the `account_id` parameter from internal services.
- Added multi-arch publish workflow to Docker Hub.
- Added build/publish workflow for `develop` images to staging.

### Fixed

- Resolved `UnboundLocalError` in `run_seeders.py`.
- Added `checkfirst` to `SQLAlchemy create_all` to avoid `DuplicateTableError`.
- Fixed middleware ordering and CORS / rate limiting conditions.
- `agent retrieval` migrated to async calls with refined error handling in `EvoAuthService`.
- Improved error handling in the response utility and the private messages tool.
- Added `PATCH` method to `EvoCrmClient` and support for `stage_name` in the pipeline manipulation tool.
- Removed the unused `CORS_ORIGINS` field from `settings`.
- **EVO-972**: serializes `set` in JSON responses and enriches the auth error surface. (#6)

### Security

- Removed the GCP service account key that leaked in previous commits. (#4)

## [0.1.0] - 2025-07-02

### Added

- JWT authentication via external service with FastAPI HTTPBearer integration
- Route-level protection: only sensitive endpoints require authentication
- Public endpoints (e.g. `/supported-formats`, `/health/status`) accessible without authentication
- Centralized configuration for external auth service via environment and settings
- Improved OpenAPI/Swagger experience with proper security scheme
- Error handling for unavailable or invalid authentication service
- English documentation and codebase

### Changed

- Refactored authentication logic to remove global dependencies and middleware
- Cleaned up project dependencies and removed unused packages
- Updated project structure and documentation to reflect microservice boundaries
- Improved logging and error messages for authentication and service health

### Fixed

- Fixed 401 errors on public endpoints by isolating JWT validation to protected routes only
- Fixed Swagger not sending Authorization header by using FastAPI security scheme

### Security

- All protected endpoints require valid JWT validated by external service
- No sensitive data exposed in logs or error messages

---

Older versions and future releases will be listed here.
