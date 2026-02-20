# Docker + GitHub + Render Setup

## 1) Local Docker Build

```bash
docker build -t api-smoothie:local .
docker run --rm -p 3000:3000 --env-file .env api-smoothie:local
```

## 2) GitHub Actions (Free Tier)

CI is in `.github/workflows/ci.yml`:

- Pull Request + Push `main`: lint + build + unit tests
- No Docker image build in CI to save minutes.
- Integration tests run locally when needed:
  - `docker compose up -d`
  - `pnpm run db:migrate`
  - `pnpm run test:integration`

## 3) Render Deploy

Deploy workflow is manual only: `.github/workflows/deploy-render.yml`.

Set GitHub repo secrets:

- `NEON_DATABASE_URL`
- `RENDER_DEPLOY_HOOK_URL`

Run deploy:

1. GitHub repo -> Actions -> `Deploy Render`
2. Click `Run workflow`
3. Workflow runs DB migration then triggers Render deploy hook

## 4) Render Env Vars

Use `render.yaml` for env keys and set real values in Render Dashboard:

- `DATABASE_URL` (Neon)
- `REDIS_URL` (Upstash, `rediss://...`)
- `JWT_*`
- `CORS_ORIGIN`

Optional overrides (already have safe defaults in app):

- `TRUST_PROXY` (default: `true` on production)
- `PINO_LEVEL` (default: `info`)
- `LOGIN_RATE_LIMIT_*` (default: `5` attempts / `900` seconds)
- `JWT_ISSUER`, `JWT_AUDIENCE` (defaults: `api-smoothie`, `api-smoothie-users`)

If you do not use Upstash, you can fallback to `REDIS_HOST`, `REDIS_PORT`, `REDIS_TLS` (and optional `REDIS_USERNAME`, `REDIS_PASSWORD`).
