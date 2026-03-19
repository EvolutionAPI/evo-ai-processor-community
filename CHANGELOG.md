# Changelog

All notable changes to this microservice will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
