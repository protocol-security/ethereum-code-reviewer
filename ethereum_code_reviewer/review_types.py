"""
Shared dataclasses for review targets and commit metadata.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


@dataclass
class CommitInfo:
    """Information about a commit or commit-like review target."""

    sha: str
    author: str
    date: str
    message: str
    branch: str
    url: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BranchReviewTarget:
    """All data needed to review one monitored branch state."""

    repo_name: str
    repo_url: str
    branch_name: str
    head_sha: str
    baseline_sha: Optional[str]
    hardfork_name: Optional[str]
    combined_changes: str
    commit_info: CommitInfo
    scoped_commit_infos: List[CommitInfo]
    bare_repo_path: str
    worktree_path: str
