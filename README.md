# Ethereum Code Reviewer (ECR)

A Claude Code SDK based security reviewer for Ethereum client code. Run it as a
**GitHub Action** in any client repo, or as a **CLI** locally. It reviews a pull
request, a single commit, or the cumulative diff of a whole hardfork, and always
pulls the **latest EIPs live** for context — no vendored spec corpus to keep in
sync.

## How it works

- Reviews are performed by Claude through the `claude-code-sdk` (which drives the
  `@anthropic-ai/claude-code` CLI) — Claude only, no other providers.
- The reviewer prompt comes from a small agent file. Two are bundled:
  `agents/execution-layer/AGENTS.md` and `agents/consensus-layer/AGENTS.md`.
- EIP/spec context is fetched at runtime: it parses
  [`eips.ethereum.org/meta`](https://eips.ethereum.org/meta) to find a fork's
  Hardfork-Meta EIP, reads its "Included EIPs" (or "Scheduled for Inclusion" for
  draft forks), and downloads those EIPs from `ethereum/EIPs`. EIPs referenced in
  the diff are fetched too. Downloaded EIPs are cached, so re-runs only fetch new
  ones. A per-run manifest reconciles expected-vs-fetched EIPs.

## Requirements

- Python ≥ 3.10.
- The `@anthropic-ai/claude-code` CLI (`npm install -g @anthropic-ai/claude-code`).
- A Claude credential: a Claude Code OAuth token from `claude setup-token`
  (recommended), or an `ANTHROPIC_API_KEY`.
- A GitHub token with read access to the reviewed repo (and write, to post comments).

## Use it as a GitHub Action

In the client repo you want reviewed, run `claude setup-token` locally and save the
output as a repository secret named `CLAUDE_CODE_OAUTH_TOKEN`. Then add a workflow
(`.github/workflows/security-review.yml`):

```yaml
name: Ethereum Security Review
on:
  pull_request:
    types: [opened, synchronize]
jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: protocol-security/ethereum-code-reviewer@v2
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
          agent-file: agents/execution-layer/AGENTS.md
          # prompt: 'Also focus on reentrancy in the new precompile.'
```

That's the whole setup — a workflow file plus one secret. See
`security-review.yml.example` for a cumulative hardfork-review example
(`mode: start-commit`).

### Action inputs

| Input | Default | Description |
|---|---|---|
| `github-token` | — (required) | Token for reading the PR/commit and posting comments |
| `claude-code-oauth-token` | — | Claude Code OAuth token from `claude setup-token` (provide this or `anthropic-api-key`) |
| `anthropic-api-key` | — | Anthropic API key (alternative auth) |
| `agent-file` | — | Path under `agents/` to an AGENT.md/AGENTS.md (bundled, or committed in your repo) |
| `prompt` | — | Extra reviewer instructions appended to the agent prompt |
| `mode` | `pr` | `pr`, `commit`, or `start-commit` |
| `repository` | current repo | `owner/repo` for `commit`/`start-commit` modes |
| `start-commit` | — | Baseline SHA for `start-commit` (cumulative review to branch head) |
| `branch` | — | Branch to review for `start-commit` |
| `hardfork` | — | Hardfork name (e.g. `fusaka`) to scope EIP context |
| `model` | `claude-opus-4-8` | Claude model id |
| `post-comment` | `true` | Post findings as a PR/commit comment |
| `strict-specs` | `false` | Fail the run if the fork's expected EIPs couldn't all be fetched |

## Use it as a CLI

```bash
npm install -g @anthropic-ai/claude-code
pip install -e .

export GITHUB_TOKEN=...                 # repo read (+ write to post comments)
export CLAUDE_CODE_OAUTH_TOKEN=...      # from `claude setup-token`  (or ANTHROPIC_API_KEY=...)
```

Review modes (agent file required for repo-scoped reviews):

```bash
# A pull request
python -m pr_security_review --mode pr https://github.com/org/repo/pull/1 \
  --agent-file agents/execution-layer/AGENTS.md

# A single commit
python -m pr_security_review --mode commit --repository org/repo <sha> \
  --agent-file agents/execution-layer/AGENTS.md

# The cumulative diff of a hardfork: from a starting commit to branch head
python -m pr_security_review --mode start-commit --repository org/repo \
  --branch master --start-commit <sha> --hardfork fusaka --strict-specs \
  --agent-file agents/execution-layer/AGENTS.md

# A single file
python -m pr_security_review --file https://github.com/org/repo/blob/main/core/vm/eips.go \
  --agent-file agents/execution-layer/AGENTS.md

# Direct text on stdin (emits JSON)
cat diff.txt | python -m pr_security_review --input-text \
  --agent-file agents/execution-layer/AGENTS.md
```

Useful flags: `--post-comment` (post to the PR), `--extra-prompt "..."` (append to
the agent prompt), `--model <id>`, `--strict-specs` (fail on a missing fork EIP).
The start-commit clone is stored under `REVIEWER_DATA_DIR` (defaults to a temp
dir); fetched EIPs are cached under `REVIEWER_CACHE_DIR`.

## Agents and custom prompts

Pick a bundled agent with `--agent-file`/`agent-file` (execution or consensus
layer). To add repo- or review-specific guidance without writing a whole agent
file, pass `--extra-prompt` (CLI) / `prompt` (Action) — it's appended to the agent
prompt. You may also commit your own `agents/.../AGENTS.md` in your repo and point
`agent-file` at it.

## Hardfork EIP context

Pass `--hardfork <name>` (e.g. `fusaka`, `pectra`, `dencun`; layer code-names like
`fulu`/`osaka` also resolve). The reviewer discovers the fork's complete EIP set
from its Meta EIP and fetches each one. Drafts (e.g. `glamsterdam`) use the
"Scheduled for Inclusion" list. With `--strict-specs`, the run fails if any
expected EIP could not be fetched.

## Development

```bash
pip install -e .[test]
pytest                                   # unit tests (network-free)
RUN_LIVE_SPEC_TESTS=1 pytest tests/test_spec_context_live.py   # live EIP-fetch oracle

docker build -t ecr .                    # build the Action image
docker run --rm --entrypoint claude ecr --version   # smoke-test the bundled CLI
```

## License

MIT License — see the LICENSE file.
