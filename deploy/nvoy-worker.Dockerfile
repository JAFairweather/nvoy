# A headless, keyless worker image for a single rendered Nvoy participant runtime.
#
# The deployment pins the *built image* by digest in the immutable manifest. No Nostr identity
# material is baked here: Bunker credentials never enter this image, and the model-provider
# credential arrives only as a worker-only Docker secret at runtime.
FROM node:22-bookworm-slim

ARG CODEX_VERSION=0.146.0
ARG CLAUDE_VERSION=2.1.221
WORKDIR /srv/nvoy

COPY package.json package-lock.json ./
RUN npm ci --omit=dev \
 && npm install --global --no-audit --no-fund @openai/codex@${CODEX_VERSION} @anthropic-ai/claude-code@${CLAUDE_VERSION}

COPY mcp/package.json mcp/package.json
COPY mcp/package-lock.json mcp/package-lock.json
RUN npm --prefix mcp ci --omit=dev

COPY lib lib
COPY mcp/tools mcp/tools

RUN useradd --uid 65532 --create-home --shell /usr/sbin/nologin nvoy \
 && mkdir -p /srv/nvoy/.codex \
 && chown -R nvoy:nvoy /srv/nvoy

USER 65532:65532
ENV HOME=/home/nvoy
WORKDIR /srv/nvoy
