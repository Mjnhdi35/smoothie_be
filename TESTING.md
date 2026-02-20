# Testing Guide

## Scope

This project uses layered testing:

- Unit tests for service behavior
- Guard/controller tests for request flow and policy
- E2E smoke tests for HTTP contract
- Integration tests with real Postgres + Redis

## Test Matrix

- `AuthService`
  - register success
  - register duplicate email
  - login invalid credentials
  - login success + brute-force counter reset
  - refresh fingerprint mismatch
- `LoginRateLimitGuard`
  - request under limit
  - request over limit
- `PasswordService`
  - email normalization
  - hash + verify behavior
- `RequestContextService`
  - IP/user-agent extraction defaults
  - fingerprint derivation
- `AuthController`
  - refresh without token returns `BadRequestException`
- E2E
  - `GET /health` returns `ok` and ISO timestamp
- Integration (`Auth Integration`)
  - register + login with real DB/Redis
  - refresh token rotation
  - refresh token replay detection (reuse)
  - logout invalidates refresh session

## Commands

```bash
pnpm run test
pnpm run test:e2e
pnpm run test:integration
pnpm run test:cov
```

## Notes

- E2E tests require the runtime to allow opening a local HTTP listener.
- For integration tests with Postgres/Redis, run `docker compose up -d`.
- Ensure migrations are applied before integration tests:
  - `pnpm run db:migrate`
