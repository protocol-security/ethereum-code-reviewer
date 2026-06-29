import argparse

import pytest

import ethereum_code_reviewer.__main__ as cli
import ethereum_code_reviewer.local_repo_manager as lrm
from ethereum_code_reviewer.review_types import BranchReviewTarget, CommitInfo


def _args(**overrides):
    base = dict(
        repository="ethereum/go-ethereum",
        start_commit="cafebabe0000",
        branch="main",
        hardfork="fusaka",
        agent_file="agents/execution-layer/AGENTS.md",
        strict_specs=True,
        extra_prompt="focus on the precompile",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class _FakeReviewer:
    github_token = "tok"

    def __init__(self):
        self.captured = {}

    def analyze_security(self, changes, **kwargs):
        self.captured = dict(kwargs)
        self.captured["changes"] = changes
        return ({"has_vulnerabilities": False, "findings": [], "summary": "ok"}, None)


def test_run_start_commit_review_forwards_target_fields(monkeypatch):
    ci = CommitInfo("deadbeefcafe", "Author", "2026-06-01", "msg", "main", "https://x")
    target = BranchReviewTarget(
        repo_name="ethereum/go-ethereum",
        repo_url="https://github.com/ethereum/go-ethereum",
        branch_name="main",
        head_sha="deadbeefcafe",
        baseline_sha="cafebabe0000",
        hardfork_name="fusaka",
        combined_changes="THE CUMULATIVE DIFF",
        commit_info=ci,
        scoped_commit_infos=[ci, ci],
        bare_repo_path="/bare",
        worktree_path="/wt",
    )
    monkeypatch.setattr(lrm.LocalRepositoryManager, "build_review_target", lambda self, **kw: target)

    reviewer = _FakeReviewer()
    returned_target, analysis, _cost = cli.run_start_commit_review(_args(), reviewer)

    assert returned_target is target
    c = reviewer.captured
    assert c["changes"] == "THE CUMULATIVE DIFF"
    assert c["baseline_sha"] == "cafebabe0000"
    assert c["head_sha"] == "deadbeefcafe"
    assert c["hardfork_name"] == "fusaka"
    assert c["working_directory"] == "/wt"
    assert c["strict_specs"] is True
    assert c["extra_prompt"] == "focus on the precompile"


def test_run_start_commit_review_requires_repository():
    with pytest.raises(ValueError):
        cli.run_start_commit_review(_args(repository=None), _FakeReviewer())


def test_run_start_commit_review_requires_start_commit():
    with pytest.raises(ValueError):
        cli.run_start_commit_review(_args(start_commit=None), _FakeReviewer())
