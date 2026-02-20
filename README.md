# API Smoothie Auth Service

Production-grade authentication module built with NestJS 11, Express adapter, Knex, PostgreSQL 17 (or Neon), and Redis.

## Features

- Clean module separation (`auth`, `users`, `infrastructure`, `common`, `config`)
- RS256 JWT access (15m) + refresh (7d)
- Redis-backed refresh sessions (`auth:refresh:<jti>`) with rotation and reuse detection
- Brute-force protection and login rate limiting via Redis counters
- Bcrypt password hashing
- Audit log persistence (`audit_logs` table)
- Structured logging with `nestjs-pino`
- Strict validation and global exception filter (no stack leak)

## Project Structure

```text
src/
  modules/
    auth/
    users/
  infrastructure/
    database/
    redis/
  common/
    guards/
    filters/
    decorators/
  config/
  main.ts
```

## Setup

1. Install dependencies:

```bash
pnpm install
```

2. Create environment:

```bash
cp .env.example .env
```

3. Generate RSA key pairs for access/refresh tokens and put them in `.env` with `\\n`-escaped line breaks.

4. Start infrastructure:

```bash
docker compose up -d
```

5. Run migrations:

```bash
pnpm run db:migrate
```

6. Start API:

```bash
pnpm run start:dev
```

## API Endpoints

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /health`

## Example Requests

Register:

```bash
curl -X POST http://localhost:3000/auth/register \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: smoothie-client/1.0' \
  -d '{"email":"alice@example.com","password":"Str0ngPassw0rd!"}'
```

Login:

```bash
curl -X POST http://localhost:3000/auth/login \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: smoothie-client/1.0' \
  -d '{"provider":"password","email":"alice@example.com","password":"Str0ngPassw0rd!"}'
```

`provider` currently supports:

- `password` (active)
- `google` (reserved; not configured yet)

Refresh:

```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H 'Authorization: Bearer <REFRESH_TOKEN>' \
  -H 'User-Agent: smoothie-client/1.0'
```

Logout:

```bash
curl -X POST http://localhost:3000/auth/logout \
  -H 'Authorization: Bearer <REFRESH_TOKEN>' \
  -H 'User-Agent: smoothie-client/1.0' \
  -i
```

## Security Notes

- Refresh tokens are stored server-side in Redis with TTL matching token expiration.
- Refresh token rotation marks prior tokens as used and detects replay attempts.
- On replay detection, all active refresh sessions for that user are revoked.
- Login attempts are rate-limited per-IP and per-email hash.
- Passwords are never logged or stored in plaintext.

## Neon Postgres

- You can use either:
  - `DATABASE_URL` (recommended for Neon/managed Postgres)
  - or `POSTGRES_*` variables.
- Example Neon URL:
  - `postgresql://user:password@host/dbname?sslmode=require`

## CI/CD (GitHub Actions + Render)

- `CI` workflow (`.github/workflows/ci.yml`) is optimized for GitHub Free:
  - PR/main: lint + build + unit tests
- `Deploy Render` workflow (`.github/workflows/deploy-render.yml`) runs manually (`workflow_dispatch`):
  - runs Knex migrations using Neon URL
  - triggers Render deploy hook.
- `render.yaml` provides a Render Blueprint with Docker runtime and required env variable keys only (`sync: false`), so no runtime values are hardcoded in the public repo.
- Quick setup guide: `DEPLOY_SETUP.md`

Set these GitHub repository secrets:

- `NEON_DATABASE_URL`
- `RENDER_DEPLOY_HOOK_URL`

## Testing

- See `TESTING.md` for the full test matrix and execution guide.
- Quick commands:
  - `pnpm run test`
  - `pnpm run test:integration`
