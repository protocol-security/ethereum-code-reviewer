"""
Local git repository sync and review-target generation.
"""

from __future__ import annotations

import base64
import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from .review_types import BranchReviewTarget, CommitInfo


DEFAULT_DATA_DIR = Path(os.environ.get("REVIEWER_DATA_DIR", "/var/lib/reviewer/data"))


class LocalRepositoryManager:
    """Manage local clones/worktrees for monitored repositories."""

    def __init__(self, github_token: Optional[str], data_dir: Optional[Path | str] = None):
        self.github_token = github_token
        self.data_dir = Path(data_dir or DEFAULT_DATA_DIR)
        self.repos_dir = self.data_dir / "repos"
        self.worktrees_dir = self.data_dir / "worktrees"

    def _repo_paths(self, repo_name: str, branch_name: str) -> tuple[Path, Path]:
        owner, repo = repo_name.split("/", 1)
        branch_slug = re.sub(r"[^A-Za-z0-9._-]+", "__", branch_name.strip()) or "default"
        bare_repo_path = self.repos_dir / owner / f"{repo}.git"
        worktree_path = self.worktrees_dir / owner / repo / branch_slug
        return bare_repo_path, worktree_path

    def _git_auth_config(self, repo_url: str) -> List[str]:
        if not self.github_token:
            return []

        parsed = urlparse(repo_url)
        if not parsed.scheme or not parsed.netloc:
            return []

        credential = base64.b64encode(f"x-access-token:{self.github_token}".encode("utf-8")).decode("ascii")
        return [
            "-c",
            f"http.{parsed.scheme}://{parsed.netloc}/.extraheader=AUTHORIZATION: basic {credential}",
        ]

    def _run_git(self, args: List[str], cwd: Optional[Path] = None, repo_url: Optional[str] = None) -> str:
        cmd = ["git"]
        if repo_url:
            cmd.extend(self._git_auth_config(repo_url))
        cmd.extend(args)

        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"

        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"git {' '.join(args)} failed: {stderr}")
        return result.stdout.strip()

    def ensure_branch_checkout(self, repo_name: str, repo_url: str, branch_name: str) -> tuple[Path, Path, str]:
        """Ensure the bare clone and branch worktree exist and are updated to origin/<branch>."""
        bare_repo_path, worktree_path = self._repo_paths(repo_name, branch_name)
        bare_repo_path.parent.mkdir(parents=True, exist_ok=True)
        worktree_path.parent.mkdir(parents=True, exist_ok=True)

        if not bare_repo_path.exists():
            self._run_git(["clone", "--bare", repo_url, str(bare_repo_path)], repo_url=repo_url)

        self._run_git([
            "--git-dir", str(bare_repo_path),
            "fetch", "--prune", "origin", "+refs/heads/*:refs/remotes/origin/*"
        ], repo_url=repo_url)

        if not worktree_path.exists():
            self._run_git([
                "--git-dir", str(bare_repo_path),
                "worktree", "add", "--force", str(worktree_path), f"origin/{branch_name}"
            ])
        else:
            self._run_git(["checkout", "--force", "--detach", f"origin/{branch_name}"], cwd=worktree_path)

        self._run_git(["reset", "--hard", f"origin/{branch_name}"], cwd=worktree_path)
        self._run_git(["clean", "-fd"], cwd=worktree_path)
        head_sha = self._run_git(["rev-parse", "HEAD"], cwd=worktree_path)
        return bare_repo_path, worktree_path, head_sha

    def ensure_pr_checkout(self, repo_name: str, repo_url: str, pr_number: int) -> tuple[Path, str]:
        """Check out a pull request's head so the reviewer can read the real code.

        Fetches ``refs/pull/<n>/head`` (shallow) from the upstream repo into a
        worktree and returns ``(worktree_path, head_sha)``. The agent runs with
        this as its working directory, so it can read surrounding source, trace
        callers/callees, and verify the diff against the actual codebase rather
        than reasoning from the patch alone.
        """
        branch_name = f"pr-{pr_number}"
        bare_repo_path, worktree_path = self._repo_paths(repo_name, branch_name)
        bare_repo_path.parent.mkdir(parents=True, exist_ok=True)
        worktree_path.parent.mkdir(parents=True, exist_ok=True)

        if not bare_repo_path.exists():
            self._run_git(["init", "--bare", str(bare_repo_path)])

        ref = f"refs/remotes/origin/pr/{pr_number}"
        self._run_git([
            "--git-dir", str(bare_repo_path),
            "fetch", "--depth", "1", "--force", repo_url,
            f"+refs/pull/{pr_number}/head:{ref}",
        ], repo_url=repo_url)

        if not worktree_path.exists():
            self._run_git([
                "--git-dir", str(bare_repo_path),
                "worktree", "add", "--force", "--detach", str(worktree_path), ref,
            ])
        else:
            self._run_git(["checkout", "--force", "--detach", ref], cwd=worktree_path)

        self._run_git(["reset", "--hard", ref], cwd=worktree_path)
        self._run_git(["clean", "-fd"], cwd=worktree_path)
        head_sha = self._run_git(["rev-parse", "HEAD"], cwd=worktree_path)
        return worktree_path, head_sha

    def _build_commit_url(self, repo_name: str, sha: str) -> str:
        return f"https://github.com/{repo_name}/commit/{sha}"

    def _get_commit_info(self, repo_name: str, branch_name: str, worktree_path: Path, commitish: str) -> CommitInfo:
        raw = self._run_git(
            ["log", "-1", "--format=%H%x1f%an%x1f%aI%x1f%B", commitish],
            cwd=worktree_path
        )
        sha, author, date, message = raw.split("\x1f", 3)
        return CommitInfo(
            sha=sha.strip(),
            author=author.strip(),
            date=date.strip(),
            message=message.strip(),
            branch=branch_name,
            url=self._build_commit_url(repo_name, sha.strip()),
        )

    def _get_commit_infos_in_range(
        self,
        repo_name: str,
        branch_name: str,
        worktree_path: Path,
        revision_range: str
    ) -> List[CommitInfo]:
        raw = self._run_git(
            ["log", "--reverse", "--format=%H%x1f%an%x1f%aI%x1f%B%x1e", revision_range],
            cwd=worktree_path
        )
        commits: List[CommitInfo] = []
        for row in raw.split("\x1e"):
            row = row.strip()
            if not row:
                continue
            sha, author, date, message = row.split("\x1f", 3)
            commits.append(CommitInfo(
                sha=sha.strip(),
                author=author.strip(),
                date=date.strip(),
                message=message.strip(),
                branch=branch_name,
                url=self._build_commit_url(repo_name, sha.strip()),
            ))
        return commits

    def _build_latest_commit_review(
        self,
        repo_name: str,
        branch_name: str,
        hardfork_name: Optional[str],
        worktree_path: Path
    ) -> Optional[BranchReviewTarget]:
        commit_info = self._get_commit_info(repo_name, branch_name, worktree_path, "HEAD")
        patch = self._run_git(["show", "--find-renames", "--format=", "HEAD"], cwd=worktree_path)
        if not patch.strip():
            return None

        combined_changes = "\n".join([
            f"Repository: {repo_name}",
            f"Branch: {branch_name}",
            f"Mode: latest commit only",
            f"Head Commit: {commit_info.sha}",
            f"Hardfork: {hardfork_name or 'not specified'}",
            "",
            "# Commit Metadata",
            f"Author: {commit_info.author}",
            f"Date: {commit_info.date}",
            f"Message: {commit_info.message}",
            "",
            "# Commit Diff",
            patch,
        ])

        return BranchReviewTarget(
            repo_name=repo_name,
            repo_url=f"https://github.com/{repo_name}",
            branch_name=branch_name,
            head_sha=commit_info.sha,
            baseline_sha=None,
            hardfork_name=hardfork_name,
            combined_changes=combined_changes,
            commit_info=commit_info,
            scoped_commit_infos=[commit_info],
            bare_repo_path="",
            worktree_path=str(worktree_path),
        )

    def _build_baseline_review(
        self,
        repo_name: str,
        branch_name: str,
        starting_commit_sha: str,
        hardfork_name: Optional[str],
        worktree_path: Path
    ) -> Optional[BranchReviewTarget]:
        self._run_git(["merge-base", "--is-ancestor", starting_commit_sha, "HEAD"], cwd=worktree_path)

        revision_range = f"{starting_commit_sha}..HEAD"
        scoped_commit_infos = self._get_commit_infos_in_range(repo_name, branch_name, worktree_path, revision_range)
        if not scoped_commit_infos:
            return None

        patch = self._run_git(["diff", "--find-renames", revision_range], cwd=worktree_path)
        if not patch.strip():
            return None

        head_commit = self._get_commit_info(repo_name, branch_name, worktree_path, "HEAD")
        scoped_commit_lines = [
            f"- {commit.sha[:12]} {commit.author} {commit.date} {commit.message.splitlines()[0]}"
            for commit in scoped_commit_infos
        ]
        commit_info = CommitInfo(
            sha=head_commit.sha,
            author=head_commit.author,
            date=head_commit.date,
            branch=branch_name,
            url=head_commit.url,
            message=(
                f"Cumulative review from {starting_commit_sha[:12]} to {head_commit.sha[:12]} "
                f"covering {len(scoped_commit_infos)} commit(s)"
            ),
        )

        combined_changes = "\n".join([
            f"Repository: {repo_name}",
            f"Branch: {branch_name}",
            "Mode: cumulative baseline-to-head review",
            f"Starting Commit: {starting_commit_sha}",
            f"Head Commit: {head_commit.sha}",
            f"Hardfork: {hardfork_name or 'not specified'}",
            "",
            "# Commits In Scope",
            *scoped_commit_lines,
            "",
            "# Combined Diff",
            patch,
        ])

        return BranchReviewTarget(
            repo_name=repo_name,
            repo_url=f"https://github.com/{repo_name}",
            branch_name=branch_name,
            head_sha=head_commit.sha,
            baseline_sha=starting_commit_sha,
            hardfork_name=hardfork_name,
            combined_changes=combined_changes,
            commit_info=commit_info,
            scoped_commit_infos=scoped_commit_infos,
            bare_repo_path="",
            worktree_path=str(worktree_path),
        )

    def build_review_target_for_checkout(
        self,
        repo_name: str,
        repo_url: str,
        branch_name: str,
        worktree_path: Path,
        bare_repo_path: Path,
        starting_commit_sha: Optional[str] = None,
        hardfork_name: Optional[str] = None
    ) -> Optional[BranchReviewTarget]:
        if starting_commit_sha:
            target = self._build_baseline_review(
                repo_name=repo_name,
                branch_name=branch_name,
                starting_commit_sha=starting_commit_sha,
                hardfork_name=hardfork_name,
                worktree_path=worktree_path,
            )
        else:
            target = self._build_latest_commit_review(
                repo_name=repo_name,
                branch_name=branch_name,
                hardfork_name=hardfork_name,
                worktree_path=worktree_path,
            )

        if target is None:
            return None

        target.bare_repo_path = str(bare_repo_path)
        target.repo_url = repo_url
        return target

    def build_review_target(
        self,
        repo_name: str,
        repo_url: str,
        branch_name: str,
        starting_commit_sha: Optional[str] = None,
        hardfork_name: Optional[str] = None
    ) -> Optional[BranchReviewTarget]:
        bare_repo_path, worktree_path, _ = self.ensure_branch_checkout(repo_name, repo_url, branch_name)
        return self.build_review_target_for_checkout(
            repo_name=repo_name,
            repo_url=repo_url,
            branch_name=branch_name,
            worktree_path=worktree_path,
            bare_repo_path=bare_repo_path,
            starting_commit_sha=starting_commit_sha,
            hardfork_name=hardfork_name,
        )
