"""
Local-repository-backed monitoring for configured GitHub branches.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from github import Auth, Github
from github.GithubException import GithubException
from github.Repository import Repository

from .local_repo_manager import LocalRepositoryManager
from .review_types import BranchReviewTarget, CommitInfo


@dataclass
class MonitoredBranch:
    """Configuration for one monitored branch."""

    branch_name: str
    starting_commit_sha: Optional[str] = None
    hardfork_name: Optional[str] = None
    last_seen_head_sha: Optional[str] = None
    last_reviewed_head_sha: Optional[str] = None
    local_sync_status: str = "pending"
    last_sync_error: Optional[str] = None
    last_synced_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "branch_name": self.branch_name,
            "starting_commit_sha": self.starting_commit_sha,
            "hardfork_name": self.hardfork_name,
            "last_seen_head_sha": self.last_seen_head_sha,
            "last_reviewed_head_sha": self.last_reviewed_head_sha,
            "local_sync_status": self.local_sync_status,
            "last_sync_error": self.last_sync_error,
            "last_synced_at": self.last_synced_at,
        }


@dataclass
class MonitoredRepository:
    """Configuration for a monitored repository."""

    owner: str
    repo: str
    url: str
    branch_configs: List[MonitoredBranch]
    agent_file_path: Optional[str] = None
    telegram_channel_id: Optional[str] = None
    notify_default_channel: bool = True

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def branches(self) -> List[str]:
        return [config.branch_name for config in self.branch_configs]

    @classmethod
    def from_url(
        cls,
        url: str,
        branches: Optional[List[str]] = None,
        branch_configs: Optional[List[Dict[str, Any]]] = None,
        agent_file_path: Optional[str] = None,
        telegram_channel_id: Optional[str] = None,
        notify_default_channel: bool = True,
    ) -> "MonitoredRepository":
        parts = url.rstrip("/").split("/")
        if len(parts) < 2:
            raise ValueError(f"Invalid GitHub URL: {url}")

        owner = parts[-2]
        repo = parts[-1]
        if repo.endswith(".git"):
            repo = repo[:-4]

        normalized_configs = branch_configs
        if normalized_configs is None:
            normalized_configs = [{"branch_name": branch} for branch in (branches or [])]

        parsed_configs = [
            MonitoredBranch(
                branch_name=(config.get("branch_name") or "").strip(),
                starting_commit_sha=(config.get("starting_commit_sha") or None),
                hardfork_name=(config.get("hardfork_name") or None),
                last_seen_head_sha=config.get("last_seen_head_sha"),
                last_reviewed_head_sha=config.get("last_reviewed_head_sha"),
                local_sync_status=config.get("local_sync_status") or "pending",
                last_sync_error=config.get("last_sync_error"),
                last_synced_at=config.get("last_synced_at"),
            )
            for config in normalized_configs
            if (config.get("branch_name") or "").strip()
        ]

        return cls(
            owner=owner,
            repo=repo,
            url=url,
            branch_configs=parsed_configs,
            agent_file_path=agent_file_path,
            telegram_channel_id=telegram_channel_id,
            notify_default_channel=notify_default_channel,
        )


class CommitMonitor:
    """Monitor configured repositories via local git clones/worktrees."""

    def __init__(self, github_token: str, state_file: Optional[str] = None, config_file: Optional[str] = None):
        if not github_token or len(github_token) < 5:
            raise ValueError("Invalid GitHub token: Token is empty or too short")

        self.github = Github(auth=Auth.Token(github_token))
        self.github_token = github_token
        self.state_file = state_file or os.path.join(os.path.expanduser("~"), ".ethereum_code_reviewer", "commit_monitor_state.json")
        self.monitored_repos: List[MonitoredRepository] = []
        self.last_commits: Dict[str, Dict[str, str]] = {}
        self.local_repo_manager = LocalRepositoryManager(github_token)

        if config_file and os.path.exists(config_file):
            self._load_repositories_from_config(config_file)

    def _save_state(self) -> None:
        """Persist a lightweight compatibility snapshot for CLI helpers."""
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            data = {
                "last_commits": self.last_commits,
                "monitored_repos": [
                    {
                        "url": repo.url,
                        "branch_configs": [config.to_dict() for config in repo.branch_configs],
                    }
                    for repo in self.monitored_repos
                ],
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
            with open(self.state_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save state to {self.state_file}: {e}")

    def _update_last_commit_map(self, repo_name: str, branch_name: str, head_sha: Optional[str]) -> None:
        if repo_name not in self.last_commits:
            self.last_commits[repo_name] = {}
        if head_sha:
            self.last_commits[repo_name][branch_name] = head_sha

    def _load_repositories_from_config(self, config_file: str) -> None:
        with open(config_file, "r") as f:
            config = json.load(f)

        for repo_config in config.get("repositories", []):
            url = repo_config.get("url")
            if not url:
                continue
            monitored_repo = MonitoredRepository.from_url(
                url=url,
                branches=repo_config.get("branches", ["main", "master"]),
                branch_configs=repo_config.get("branch_configs"),
                agent_file_path=repo_config.get("agent_file_path"),
                telegram_channel_id=repo_config.get("telegram_channel_id"),
                notify_default_channel=repo_config.get("notify_default_channel", True),
            )
            self.monitored_repos.append(monitored_repo)
            for branch_config in monitored_repo.branch_configs:
                self._update_last_commit_map(monitored_repo.full_name, branch_config.branch_name, branch_config.last_seen_head_sha)

    def add_repository(self, repo_url: str, branches: List[str]) -> None:
        monitored_repo = MonitoredRepository.from_url(repo_url, branches=branches)
        existing = next((repo for repo in self.monitored_repos if repo.full_name == monitored_repo.full_name), None)
        if existing:
            known = {config.branch_name for config in existing.branch_configs}
            for branch in monitored_repo.branch_configs:
                if branch.branch_name not in known:
                    existing.branch_configs.append(branch)
        else:
            self.monitored_repos.append(monitored_repo)
        self._save_state()

    def remove_repository(self, repo_url: str) -> None:
        full_name = MonitoredRepository.from_url(repo_url, branches=[]).full_name
        self.monitored_repos = [repo for repo in self.monitored_repos if repo.full_name != full_name]
        self.last_commits.pop(full_name, None)
        self._save_state()

    def _update_branch_state(
        self,
        monitored_repo: MonitoredRepository,
        branch_config: MonitoredBranch,
        *,
        head_sha: Optional[str] = None,
        last_reviewed_head_sha: Optional[str] = None,
        local_sync_status: Optional[str] = None,
        last_sync_error: Optional[str] = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        if head_sha is not None:
            branch_config.last_seen_head_sha = head_sha
            self._update_last_commit_map(monitored_repo.full_name, branch_config.branch_name, head_sha)
        if last_reviewed_head_sha is not None:
            branch_config.last_reviewed_head_sha = last_reviewed_head_sha
        if local_sync_status is not None:
            branch_config.local_sync_status = local_sync_status
        if last_sync_error is not None or local_sync_status in {"ready", "reviewed", "syncing"}:
            branch_config.last_sync_error = last_sync_error
        branch_config.last_synced_at = now

    def mark_branch_reviewed(self, repository_name: str, branch_name: str, head_sha: str) -> None:
        monitored_repo = next((repo for repo in self.monitored_repos if repo.full_name == repository_name), None)
        if not monitored_repo:
            return
        branch_config = next((config for config in monitored_repo.branch_configs if config.branch_name == branch_name), None)
        if not branch_config:
            return
        self._update_branch_state(
            monitored_repo,
            branch_config,
            last_reviewed_head_sha=head_sha,
            local_sync_status="reviewed",
            last_sync_error=None,
        )
        self._save_state()

    def mark_branch_review_error(self, repository_name: str, branch_name: str, error_message: str) -> None:
        monitored_repo = next((repo for repo in self.monitored_repos if repo.full_name == repository_name), None)
        if not monitored_repo:
            return
        branch_config = next((config for config in monitored_repo.branch_configs if config.branch_name == branch_name), None)
        if not branch_config:
            return
        self._update_branch_state(
            monitored_repo,
            branch_config,
            local_sync_status="review_error",
            last_sync_error=error_message,
        )
        self._save_state()

    def _sync_branch_and_prepare_review(
        self,
        monitored_repo: MonitoredRepository,
        branch_config: MonitoredBranch,
        force_review: bool = False,
    ) -> Optional[BranchReviewTarget]:
        self._update_branch_state(monitored_repo, branch_config, local_sync_status="syncing", last_sync_error=None)

        try:
            bare_repo_path, worktree_path, head_sha = self.local_repo_manager.ensure_branch_checkout(
                monitored_repo.full_name,
                monitored_repo.url,
                branch_config.branch_name,
            )

            should_review = force_review or branch_config.last_seen_head_sha != head_sha or branch_config.last_reviewed_head_sha is None
            self._update_branch_state(
                monitored_repo,
                branch_config,
                head_sha=head_sha,
                local_sync_status="ready",
                last_sync_error=None,
            )
            if not should_review:
                return None

            target = self.local_repo_manager.build_review_target_for_checkout(
                repo_name=monitored_repo.full_name,
                repo_url=monitored_repo.url,
                branch_name=branch_config.branch_name,
                worktree_path=worktree_path,
                bare_repo_path=bare_repo_path,
                starting_commit_sha=branch_config.starting_commit_sha,
                hardfork_name=branch_config.hardfork_name,
            )
            if target is None:
                self._update_branch_state(
                    monitored_repo,
                    branch_config,
                    last_reviewed_head_sha=head_sha,
                    local_sync_status="reviewed",
                    last_sync_error=None,
                )
                return None
            return target
        except Exception as e:
            error_message = str(e)
            self._update_branch_state(
                monitored_repo,
                branch_config,
                local_sync_status="sync_error",
                last_sync_error=error_message,
            )
            print(f"Warning: Could not sync {monitored_repo.full_name}/{branch_config.branch_name}: {error_message}")
            return None

    def get_review_targets(
        self,
        force_review: bool = False,
        repository_name: Optional[str] = None,
    ) -> List[Tuple[MonitoredRepository, List[BranchReviewTarget]]]:
        results: List[Tuple[MonitoredRepository, List[BranchReviewTarget]]] = []

        for monitored_repo in self.monitored_repos:
            if repository_name and monitored_repo.full_name != repository_name:
                continue

            targets: List[BranchReviewTarget] = []
            for branch_config in monitored_repo.branch_configs:
                target = self._sync_branch_and_prepare_review(
                    monitored_repo=monitored_repo,
                    branch_config=branch_config,
                    force_review=force_review,
                )
                if target:
                    targets.append(target)

            if targets:
                results.append((monitored_repo, targets))

        self._save_state()
        return results

    def get_new_commits(
        self,
        force_review: bool = False,
        repository_name: Optional[str] = None
    ) -> List[Tuple[MonitoredRepository, List[BranchReviewTarget]]]:
        """Compatibility wrapper returning branch review targets instead of raw commits."""
        return self.get_review_targets(force_review=force_review, repository_name=repository_name)

    def get_commit_changes(self, repo_name: str, commit_sha: str) -> str:
        """Fallback GitHub API path for manual single-commit analysis."""
        try:
            repo: Repository = self.github.get_repo(repo_name)
            commit = repo.get_commit(commit_sha)

            changes = [
                f"Commit: {commit.sha}",
                f"Author: {commit.commit.author.name if commit.commit.author else 'Unknown'}",
                f"Date: {commit.commit.author.date if commit.commit.author else 'Unknown'}",
                f"Message: {commit.commit.message}",
                "\nFiles changed:",
            ]
            for file in commit.files:
                if file.patch:
                    changes.append(f"\nFile: {file.filename}")
                    changes.append(f"Status: {file.status}")
                    changes.append(f"Changes: +{file.additions} -{file.deletions}")
                    changes.append(f"\n{file.patch}")
            return "\n".join(changes)
        except GithubException as e:
            print(f"Error getting commit changes for {commit_sha} in {repo_name}: {e}")
            return ""

    def list_monitored_repositories(self) -> List[Dict[str, Any]]:
        return [
            {
                "repository": repo.full_name,
                "branches": repo.branches,
                "branch_configs": [config.to_dict() for config in repo.branch_configs],
                "last_commits": self.last_commits.get(repo.full_name, {}),
            }
            for repo in self.monitored_repos
        ]

    def monitor_continuously(self, check_interval: int = 300, callback=None) -> None:
        print(f"Starting continuous monitoring (checking every {check_interval} seconds)...")
        while True:
            try:
                print(f"\n[{datetime.now()}] Checking for new commits...")
                review_targets = self.get_review_targets()
                if review_targets:
                    for monitored_repo, targets in review_targets:
                        print(f"Found {len(targets)} review target(s) in {monitored_repo.full_name}")
                        if callback:
                            callback(monitored_repo, targets)
                else:
                    print("No new commits found.")
            except Exception as e:
                print(f"Error during monitoring: {e}")
            time.sleep(check_interval)
