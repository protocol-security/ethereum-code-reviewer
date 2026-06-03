from datetime import datetime, timezone
from types import SimpleNamespace

from pr_security_review.findings_deduplication import find_duplicate_finding_uuids


def _finding(uuid, created_at, repo_name="ethereum/go-ethereum", commit_sha="00da4f5"):
    return SimpleNamespace(
        uuid=uuid,
        repo_name=repo_name,
        pr_number=None,
        commit_sha=commit_sha,
        has_vulnerabilities=True,
        summary="Potential reentrancy issue",
        findings_count=1,
        created_at=created_at,
    )


def test_find_duplicate_finding_uuids_returns_later_duplicate_rows():
    findings = [
        _finding("keep", datetime(2026, 4, 3, 10, 0, 10, tzinfo=timezone.utc)),
        _finding("delete", datetime(2026, 4, 3, 10, 0, 2, tzinfo=timezone.utc)),
    ]

    duplicate_uuids = find_duplicate_finding_uuids(findings)

    assert duplicate_uuids == ["delete"]


def test_find_duplicate_finding_uuids_keeps_distinct_rescans():
    findings = [
        _finding("recent", datetime(2026, 4, 3, 11, 0, 0, tzinfo=timezone.utc)),
        _finding("older", datetime(2026, 4, 3, 10, 0, 0, tzinfo=timezone.utc)),
    ]

    duplicate_uuids = find_duplicate_finding_uuids(findings)

    assert duplicate_uuids == []
