# The narrow runtime image used by watcher, broker, adapter, and the one-shot initializer.
# It intentionally contains no participant identity, Bunker connection, or model-provider key.
# Those are mounted at runtime only where the rendered Compose contract permits them.
# Pin the base itself: a mutable tag would make this image's provenance drift with unchanged
# application source and lockfiles.
FROM node:22-bookworm-slim@sha256:f32b81066cde10a75dbac96646099533316d94bac4150c55da1636e1f0ffdc46

WORKDIR /srv/nvoy

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY lib ./lib
COPY mcp/package.json mcp/package-lock.json ./mcp/
# This image invokes only JavaScript files under mcp/tools; it does not run the MCP server.
# Avoid the package's TypeScript prepare hook, whose source tree is intentionally not copied here.
RUN npm --prefix mcp ci --omit=dev --ignore-scripts

COPY mcp/tools ./mcp/tools

# Compose always supplies numeric per-instance identities. The image must not claim an identity
# at build time, and must remain usable by each non-root runtime role.
USER 65532:65532
WORKDIR /srv/nvoy
