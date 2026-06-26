"""Engine helpers for 'latest commit' / 'latest open PR' resolution (manual modes)."""

import types

from ethereum_code_reviewer.claude_review import SecurityReview


def _reviewer_with_github(fake_github):
    r = SecurityReview.__new__(SecurityReview)  # bypass __init__ (no env/network)
    r.github = fake_github
    return r


class _FakeRepo:
    def __init__(self, default_branch="main", branch_shas=None, open_prs=None):
        self.default_branch = default_branch
        self._branch_shas = branch_shas or {}
        self._open_prs = open_prs or []

    def get_branch(self, ref):
        sha = self._branch_shas[ref]
        return types.SimpleNamespace(commit=types.SimpleNamespace(sha=sha))

    def get_pulls(self, state, sort, direction):
        assert state == "open"
        return list(self._open_prs)  # newest-first; supports [:1] slicing


class _FakeGithub:
    def __init__(self, repo):
        self._repo = repo

    def get_repo(self, name):
        return self._repo


def test_get_latest_commit_sha_uses_given_branch():
    repo = _FakeRepo(branch_shas={"unstable": "abc123", "main": "deadbeef"})
    r = _reviewer_with_github(_FakeGithub(repo))
    assert r.get_latest_commit_sha("o/r", "unstable") == "abc123"


def test_get_latest_commit_sha_falls_back_to_default_branch():
    repo = _FakeRepo(default_branch="release", branch_shas={"release": "feed0001"})
    r = _reviewer_with_github(_FakeGithub(repo))
    assert r.get_latest_commit_sha("o/r", None) == "feed0001"


def test_get_latest_open_pr_returns_newest():
    newest = types.SimpleNamespace(number=42)
    older = types.SimpleNamespace(number=7)
    repo = _FakeRepo(open_prs=[newest, older])
    r = _reviewer_with_github(_FakeGithub(repo))
    assert r.get_latest_open_pr("o/r").number == 42


def test_get_latest_open_pr_none_when_empty():
    repo = _FakeRepo(open_prs=[])
    r = _reviewer_with_github(_FakeGithub(repo))
    assert r.get_latest_open_pr("o/r") is None
