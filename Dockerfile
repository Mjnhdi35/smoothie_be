# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS base
WORKDIR /app

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH

RUN corepack enable && corepack prepare pnpm@10.30.1 --activate

FROM base AS build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,target=/pnpm/store \
    pnpm fetch --frozen-lockfile
RUN --mount=type=cache,target=/pnpm/store \
    pnpm install --frozen-lockfile --offline

COPY tsconfig.json tsconfig.build.json nest-cli.json ./
COPY src ./src

RUN pnpm run build && pnpm prune --prod

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

EXPOSE 3000
CMD ["node", "dist/main"]
