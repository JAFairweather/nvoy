# Disposable test runner for the container boundary proof; never deployed as a participant role.
# Keep its Docker client current enough for the deployment host daemon's API floor.
FROM docker:29-cli@sha256:27a51d5ab1cd38d9eeaba7b415b8c07bc10c31e1cf1ec8d78f6413fcfab3f44f AS docker-cli
FROM node:22-bookworm-slim@sha256:f32b81066cde10a75dbac96646099533316d94bac4150c55da1636e1f0ffdc46
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /srv/nvoy
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY test/instance-runtime-container.mjs ./test/instance-runtime-container.mjs
