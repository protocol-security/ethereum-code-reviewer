#!/usr/bin/env bash
# GitHub Action entrypoint: map action inputs (INPUT_* env) to the CLI.
set -euo pipefail

if [ -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "::error::Provide 'claude-code-oauth-token' (from \`claude setup-token\`) or 'anthropic-api-key'."
  exit 1
fi

MODE="${INPUT_MODE:-pr}"
REPO="${INPUT_REPOSITORY:-${GITHUB_REPOSITORY:-}}"

# Agent files resolve relative to cwd. Prefer the consumer's repo if it ships the
# requested agent file; otherwise fall back to this action's bundled agents (/app).
WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
if [ -n "${INPUT_AGENT_FILE:-}" ] && [ -f "$WORKSPACE/$INPUT_AGENT_FILE" ]; then
  cd "$WORKSPACE"
else
  cd /app
fi

args=(--mode "$MODE")
[ -n "${INPUT_AGENT_FILE:-}" ]   && args+=(--agent-file "$INPUT_AGENT_FILE")
[ -n "${INPUT_PROMPT:-}" ]       && args+=(--extra-prompt "$INPUT_PROMPT")
[ -n "${INPUT_HARDFORK:-}" ]     && args+=(--hardfork "$INPUT_HARDFORK")
[ -n "${INPUT_BRANCH:-}" ]       && args+=(--branch "$INPUT_BRANCH")
[ -n "${INPUT_START_COMMIT:-}" ] && args+=(--start-commit "$INPUT_START_COMMIT")
[ -n "$REPO" ]                   && args+=(--repository "$REPO")
[ "${INPUT_STRICT_SPECS:-false}" = "true" ] && args+=(--strict-specs)
[ "${INPUT_POST_COMMENT:-true}" = "true" ]  && args+=(--post-comment)

# Manual target (a PR URL/number for pr mode, or a commit SHA for commit mode).
# Empty => the CLI reviews the latest PR / latest commit. For an on-`pull_request`
# trigger, leave it empty and the CLI reads the PR from GITHUB_EVENT_PATH.
TARGET="${INPUT_TARGET:-}"
if [ -z "$TARGET" ] && [ "$MODE" = "commit" ] && [ -z "${INPUT_BRANCH:-}" ] && [ -n "${GITHUB_SHA:-}" ]; then
  # commit mode with nothing specified: default to the checked-out commit.
  TARGET="$GITHUB_SHA"
fi

if [ -n "$TARGET" ]; then
  exec python -m ethereum_code_reviewer "${args[@]}" "$TARGET"
else
  exec python -m ethereum_code_reviewer "${args[@]}"
fi
