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

case "$MODE" in
  commit)
    # Review the triggering commit (the positional target); default to the checked-out SHA.
    exec python -m ethereum_code_reviewer "${args[@]}" "${GITHUB_SHA:?commit mode needs a commit SHA (GITHUB_SHA)}"
    ;;
  *)
    # pr mode auto-reads the PR from GITHUB_EVENT_PATH; start-commit uses the flags above.
    exec python -m ethereum_code_reviewer "${args[@]}"
    ;;
esac
