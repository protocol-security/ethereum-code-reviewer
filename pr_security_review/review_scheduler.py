"""
Background bootstrap helpers for immediate repository sync/review.
"""

from __future__ import annotations

import logging
import os


logger = logging.getLogger(__name__)


def trigger_repository_bootstrap_review(repo_name: str) -> None:
    """Sync and review a repository immediately after add/reactivation."""
    github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("INPUT_GITHUB-TOKEN")
    if not github_token:
        logger.warning("Skipping bootstrap review for %s: GITHUB_TOKEN is not configured", repo_name)
        return

    from .__main__ import run_commit_monitor_callback
    from .claude_review import SecurityReview
    from .commit_monitor import CommitMonitor
    from .telegram_notifier import TelegramNotifier

    monitor = CommitMonitor(github_token)
    review_targets = monitor.get_review_targets(force_review=True, repository_name=repo_name)
    if not review_targets:
        logger.info("No bootstrap review targets generated for %s", repo_name)
        return

    provider_kwargs = {}
    if model := os.environ.get("CLAUDE_MODEL"):
        provider_kwargs["model"] = model
    reviewer = SecurityReview(provider_kwargs=provider_kwargs, repo_name=repo_name)

    telegram_notifier = None
    telegram_bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if telegram_bot_token and telegram_chat_id:
        try:
            telegram_notifier = TelegramNotifier(
                telegram_bot_token,
                telegram_chat_id,
                github_token=github_token,
            )
        except Exception as e:
            logger.warning("Telegram bootstrap notifier disabled for %s: %s", repo_name, e)

    notify_clean_commits = os.environ.get("NOTIFY_CLEAN_COMMITS", "").lower() in ("true", "yes", "1")
    for monitored_repo, targets in review_targets:
        run_commit_monitor_callback(
            reviewer,
            monitored_repo,
            targets,
            telegram_notifier,
            notify_clean_commits=notify_clean_commits,
            monitor=monitor,
        )
