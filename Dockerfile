FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    REVIEWER_DATA_DIR=/tmp/reviewer-data \
    REVIEWER_CACHE_DIR=/tmp/reviewer-specs

# git: for start-commit clones. node + @anthropic-ai/claude-code: required by the
# claude-code-sdk Python package, which drives the `claude` CLI as a subprocess.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates gnupg \
 && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && npm install -g @anthropic-ai/claude-code \
 && apt-get purge -y --auto-remove curl gnupg \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir . \
 && chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
