import subprocess

from pr_security_review.local_repo_manager import LocalRepositoryManager


def _git(cwd, *args):
    subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _git_output(cwd, *args):
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def test_build_review_target_uses_cumulative_baseline_diff(tmp_path):
    source_repo = tmp_path / "source"
    source_repo.mkdir()

    _git(source_repo, "init", "-b", "main")
    _git(source_repo, "config", "user.name", "Test User")
    _git(source_repo, "config", "user.email", "test@example.com")

    (source_repo / "example.txt").write_text("before\n", encoding="utf-8")
    _git(source_repo, "add", "example.txt")
    _git(source_repo, "commit", "-m", "baseline")
    baseline_sha = _git_output(source_repo, "rev-parse", "HEAD")

    (source_repo / "example.txt").write_text("before\nafter\n", encoding="utf-8")
    _git(source_repo, "commit", "-am", "follow-up")
    head_sha = _git_output(source_repo, "rev-parse", "HEAD")

    manager = LocalRepositoryManager(github_token=None, data_dir=tmp_path / "reviewer-data")
    target = manager.build_review_target(
        repo_name="ethereum/go-ethereum",
        repo_url=str(source_repo),
        branch_name="main",
        starting_commit_sha=baseline_sha,
        hardfork_name="cancun",
    )

    assert target is not None
    assert target.baseline_sha == baseline_sha
    assert target.head_sha == head_sha
    assert target.hardfork_name == "cancun"
    assert "Mode: cumulative baseline-to-head review" in target.combined_changes
    assert "after" in target.combined_changes
    assert len(target.scoped_commit_infos) == 1
