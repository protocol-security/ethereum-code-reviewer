"""Engine helpers for 'latest commit' / 'latest open PR' resolution (manual modes)."""

import types

from ethereum_code_reviewer.claude_review import SecurityReview


def _reviewer_with_github(fake_github):
    r = SecurityReview.__new__(SecurityReview)  # bypass __init__ (no env/network)
    r.github = fake_github
    return r


class _FakeRepo:
    def __init__(self, default_branch="main", branch_shas=None, open_prs=None,
                 full_name="o/r", fork=False, source=None, pulls=None):
        self.default_branch = default_branch
        self._branch_shas = branch_shas or {}
        self._open_prs = open_prs or []
        self.full_name = full_name
        self.fork = fork
        self.source = source
        self._pulls = pulls or {}

    def get_branch(self, ref):
        sha = self._branch_shas[ref]
        return types.SimpleNamespace(commit=types.SimpleNamespace(sha=sha))

    def get_pulls(self, state, sort, direction):
        assert state == "open"
        return list(self._open_prs)  # newest-first; supports [:1] slicing

    def get_pull(self, number):
        return self._pulls[number]


class _FakeGithub:
    def __init__(self, repo, repos=None):
        self._repo = repo
        self._repos = repos or {}

    def get_repo(self, name):
        return self._repos.get(name, self._repo)


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


def test_get_pr_reads_from_upstream_when_fork():
    upstream = _FakeRepo(full_name="up/r", pulls={10: types.SimpleNamespace(number=10)})
    fork = _FakeRepo(full_name="me/r", fork=True, source=upstream)
    r = _reviewer_with_github(_FakeGithub(fork))
    assert r.get_pr("me/r", 10).number == 10


def test_get_pr_uses_repo_directly_when_not_fork():
    repo = _FakeRepo(full_name="o/r", pulls={5: types.SimpleNamespace(number=5)})
    r = _reviewer_with_github(_FakeGithub(repo))
    assert r.get_pr("o/r", 5).number == 5


def test_get_latest_open_pr_reads_from_upstream_when_fork():
    newest = types.SimpleNamespace(number=99)
    upstream = _FakeRepo(full_name="up/r", open_prs=[newest])
    fork = _FakeRepo(full_name="me/r", fork=True, source=upstream, open_prs=[])
    r = _reviewer_with_github(_FakeGithub(fork))
    assert r.get_latest_open_pr("me/r").number == 99


class _FakePR:
    def __init__(self, number, title, body, files):
        self.number = number
        self.title = title
        self.body = body
        self._files = files

    def get_files(self):
        return self._files


def test_get_pr_review_input_includes_title_body_and_diff():
    pr = _FakePR(
        7, "Add foo", "This PR implements foo.\nCloses #3",
        [types.SimpleNamespace(filename="foo.py", patch="@@ -1 +1 @@\n+x = 1")],
    )
    r = SecurityReview.__new__(SecurityReview)
    out = r.get_pr_review_input(pr)
    assert "Pull Request #7: Add foo" in out
    assert "This PR implements foo." in out
    assert "File: foo.py" in out
    assert "+x = 1" in out


def test_get_pr_review_input_handles_empty_body_and_no_files():
    pr = _FakePR(8, "Empty", None, [])
    r = SecurityReview.__new__(SecurityReview)
    out = r.get_pr_review_input(pr)
    assert "(no description provided)" in out
    assert "(no file diffs available)" in out
