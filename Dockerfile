# syntax=docker/dockerfile:1.7
FROM node:22.22.0-alpine3.22 AS base
WORKDIR /app

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH

RUN apk --no-cache upgrade \
  && corepack enable \
  && corepack prepare pnpm@10.30.1 --activate

FROM base AS build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,target=/pnpm/store \
    pnpm fetch --frozen-lockfile
RUN --mount=type=cache,target=/pnpm/store \
    pnpm install --frozen-lockfile --offline

COPY tsconfig.json tsconfig.build.json nest-cli.json ./
COPY src ./src

RUN pnpm run build && pnpm prune --prod

FROM node:22.22.0-alpine3.22 AS runtime
WORKDIR /app
ENV NODE_ENV=production

RUN apk --no-cache upgrade

COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node package.json ./

EXPOSE 3000
USER node
CMD ["node", "dist/main"]
