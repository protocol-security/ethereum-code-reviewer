FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    REVIEWER_DATA_DIR=/tmp/reviewer-data \
    REVIEWER_CACHE_DIR=/tmp/reviewer-specs \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    IS_SANDBOX=1
# IS_SANDBOX=1 lets `claude --dangerously-skip-permissions` run as root inside
# this container (the GitHub Actions Docker action runs as root); without it the
# CLI refuses the flag and every swarm agent exits 1.

# Node provides the `claude` CLI, which we drive directly as a subprocess to run
# the review swarm (finders/verifiers/synthesis). Copy the prebuilt runtime from
# the official image instead of the slow NodeSource apt setup (curl | bash + a
# second apt run). uv installs Python deps far faster than pip. git is needed for
# PR/commit clones.
COPY --from=node:20-slim /usr/local/bin/node /usr/local/bin/node
COPY --from=node:20-slim /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g @anthropic-ai/claude-code \
 && npm cache clean --force

WORKDIR /app
COPY . .
RUN uv pip install --system --no-cache . \
 && chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
