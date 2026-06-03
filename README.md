# ECR

Ethereum Code Reviewer is a Claude Code SDK based security reviewer for Ethereum pull requests, commits, files, and monitored branches.

The current implementation is intentionally Claude-only. The old multi-provider and vector database paths have been removed; review prompts now come from local `AGENT.md` / `AGENTS.md` files, and relevant specification context is selected directly from the `vectordb-docs` Markdown submodule.

## Capabilities

- Review GitHub pull requests, recent pull requests, individual files, individual commits, and direct stdin input.
- Run as a GitHub App webhook server for automatic and `/security-review` triggered PR review.
- Monitor configured repository branches continuously.
- Review either the latest branch commit or a cumulative diff from a configured starting commit to branch head.
- Scope monitored reviews to a hardfork such as `cancun`, `prague`, `electra`, or `fulu`.
- Use repository-specific agent prompt files from `./agents`.
- Include local Ethereum specification and vulnerability context from `./vectordb-docs/docs`.
- Store findings in PostgreSQL, show them in the web app, and deduplicate repeated finding rows.
- Send Telegram and email notifications.
- Listen for review jobs from an AMQP/RabbitMQ queue.

## Requirements

- Python 3.8 or higher.
- A GitHub token with read access to reviewed repositories.
- An Anthropic API key.
- The `claude-code-sdk` Python package and the `@anthropic-ai/claude-code` CLI available in the runtime environment.
- PostgreSQL for the web app, repository configuration, finding storage, and duplicate cleanup.

## Install

```bash
git submodule update --init --remote --recursive
pip install -e .
```

The `vectordb-docs` submodule is configured to track its `master` branch. Use `--remote` during setup or deployment when you want the newest docs instead of the commit pinned by this repository.

Install the Claude Code CLI separately if it is not already available:

```bash
npm install -g @anthropic-ai/claude-code
```

## Environment

The tool loads `.env` automatically when present.

```bash
cp .env.example .env
```

Minimum CLI configuration:

```bash
export GITHUB_TOKEN=your_github_token
export ANTHROPIC_API_KEY=your_anthropic_key
```

Optional model override:

```bash
export CLAUDE_MODEL=<claude-model-name>
```

If no model is configured, the current code defaults to `claude-3-5-sonnet-20241022`.

Web app, repository configuration, and persisted findings require:

```bash
export DATABASE_URL=postgresql://username:password@localhost:5432/security_findings
export GOOGLE_CLIENT_ID=your_google_client_id
export FLASK_SECRET_KEY=your_flask_secret
export AUTHORIZED_EMAILS=admin@example.com
```

## Agent Files

Each review uses a local agent prompt file under `./agents`. The repository includes:

- `agents/execution-layer/AGENTS.md`
- `agents/consensus-layer/AGENTS.md`

For ad hoc CLI reviews, pass the agent explicitly:

```bash
python -m pr_security_review https://github.com/owner/repo/pull/1 \
  --agent-file agents/execution-layer/AGENTS.md
```

For configured repositories, the selected agent file is stored on the repository record through the admin web UI or database configuration. If no `--agent-file` is passed, the reviewer resolves the agent from that repository configuration.

## Specification Context

The reviewer no longer creates embeddings or uses Voyage/OpenAI embedding APIs. Instead, it reads Markdown files from the `vectordb-docs` submodule and selects a bounded set of relevant documents for each review.

Agent path controls the default docs scope:

- `agents/execution-layer/AGENTS.md` maps to `vectordb-docs/docs/execution`.
- `agents/consensus-layer/AGENTS.md` maps to `vectordb-docs/docs/consensus`.
- Other agent paths fall back to `vectordb-docs/docs`.

When a branch has a `hardfork_name`, matching hardfork `eips` and `specs` folders are preferred, with vulnerability docs included as additional context.

## CLI

### Single PR

```bash
python -m pr_security_review https://github.com/org/repo/pull/1 \
  --agent-file agents/execution-layer/AGENTS.md
```

Post a comment only when vulnerabilities are found:

```bash
python -m pr_security_review https://github.com/org/repo/pull/1 \
  --agent-file agents/execution-layer/AGENTS.md \
  --post-comment
```

### Recent PRs

```bash
python -m pr_security_review --recent-prs owner/repo \
  --pr-count 10 \
  --agent-file agents/execution-layer/AGENTS.md
```

### Single File

```bash
python -m pr_security_review --file https://github.com/org/repo/blob/main/src/file.rs \
  --agent-file agents/execution-layer/AGENTS.md
```

### Single Commit

```bash
python -m pr_security_review --repository owner/repo --analyze-commit <sha> \
  --agent-file agents/execution-layer/AGENTS.md
```

### Direct Text Input

```bash
cat diff.txt | python -m pr_security_review --input-text \
  --agent-file agents/execution-layer/AGENTS.md
```

## Branch Monitoring

Monitoring uses local bare clones and branch worktrees. By default, data is stored under `/var/lib/reviewer/data`; override it with `REVIEWER_DATA_DIR`.

Add a repository with legacy branch-only CLI configuration:

```bash
python -m pr_security_review --monitor-add https://github.com/NethermindEth/nethermind \
  --monitor-branches master
```

List monitored repositories:

```bash
python -m pr_security_review --monitor-list
```

Check once:

```bash
python -m pr_security_review --monitor-check
```

Run continuously:

```bash
python -m pr_security_review --monitor-continuous --monitor-interval 300
```

For branch-specific review settings, use the admin web UI or a JSON config file:

```json
{
  "repositories": [
    {
      "url": "https://github.com/ethereum/go-ethereum",
      "agent_file_path": "agents/execution-layer/AGENTS.md",
      "branch_configs": [
        {
          "branch_name": "master",
          "starting_commit_sha": "abc123",
          "hardfork_name": "prague"
        }
      ],
      "telegram_channel_id": "-1001234567890",
      "notify_default_channel": true
    }
  ]
}
```

Use it with:

```bash
python -m pr_security_review --config-file ./monitoring.json --monitor-check
```

If `starting_commit_sha` is set, the review covers the cumulative diff from that commit to branch head. If it is omitted, only the latest commit is reviewed.

## GitHub App

The GitHub App mode runs a webhook server for automatic PR review and `/security-review` comment triggers.

```bash
python -m pr_security_review \
  --github-app \
  --github-app-id YOUR_APP_ID \
  --github-private-key-path path/to/private-key.pem \
  --github-webhook-secret YOUR_WEBHOOK_SECRET \
  --anthropic-api-key YOUR_ANTHROPIC_KEY \
  --model <claude-model-name>
```

Required app permissions:

- Pull requests: read and write.
- Repository contents: read.
- Repository collaborators: read.

Subscribed events:

- Pull request.
- Issue comment.

## Web App

The Dockerfile runs the web app with Gunicorn:

```bash
docker build -t ethereum-code-reviewer:latest .
docker run --rm -p 5000:5000 --env-file .env ethereum-code-reviewer:latest
```

The admin UI supports repository creation and editing with:

- GitHub repository URL.
- Branch configurations.
- Optional starting commit per branch.
- Optional hardfork name per branch.
- Required agent file selection.
- Optional repository-specific Telegram channel.

Creating a repository through the admin UI starts a background bootstrap review for the configured branches when `GITHUB_TOKEN` is available.

## Queue Listener

Use an AMQP queue for asynchronous review requests:

```bash
python -m pr_security_review \
  --listen-queue \
  --amqp-url amqp://guest:guest@localhost:5672/ \
  --queue-name security_review_requests \
  --response-queue-name security_review_responses
```

If `AMQP_URL` is set and no other mode is selected, queue listener mode is auto-detected.

## Notifications

Telegram notifications:

```bash
export TELEGRAM_BOT_TOKEN=your_telegram_bot_token
export TELEGRAM_CHAT_ID=your_telegram_chat_id
export NOTIFY_CLEAN_COMMITS=false
python -m pr_security_review --monitor-continuous
```

When Telegram is configured for monitoring, the findings web app is started so notification links can point to stored finding details. Repository-specific Telegram channel settings can be configured per repository.

Email notifications use Amazon SES:

```bash
export AWS_SES_REGION=us-east-1
export SES_FROM_EMAIL=security-findings@example.com
export BASE_URL=https://your-domain.example
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
```

## Database Management

Initialize and inspect the PostgreSQL database:

```bash
python -m pr_security_review.db_utils init
python -m pr_security_review.db_utils check
python -m pr_security_review.db_utils stats
```

List and inspect findings:

```bash
python -m pr_security_review.db_utils list --repo ethereum/go-ethereum --limit 20
python -m pr_security_review.db_utils details <uuid>
```

Clean up expired findings:

```bash
python -m pr_security_review.db_utils cleanup
```

Remove duplicate findings created by repeated persistence of the same scan:

```bash
python -m pr_security_review.db_utils dedupe --dry-run
python -m pr_security_review.db_utils dedupe --repo ethereum/go-ethereum
```

Duplicate cleanup keeps the newest matching row and treats rows as duplicates only when they share the same repository, PR number, commit SHA, vulnerability flag, summary, finding count, and are within the configured time window.

## License

MIT License - see LICENSE file for details.
