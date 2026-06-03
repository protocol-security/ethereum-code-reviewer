from pr_security_review.findings_deduplication import deduplicate_finding_dicts


def test_deduplicate_findings_removes_nearby_duplicate_rows():
    findings = [
        {
            "uuid": "newest",
            "repo_name": "ethereum/go-ethereum",
            "commit_sha": "00da4f5",
            "pr_number": None,
            "has_vulnerabilities": True,
            "summary": "Potential reentrancy issue",
            "findings_count": 1,
            "created_at": "2026-04-03T10:00:10+00:00",
        },
        {
            "uuid": "duplicate",
            "repo_name": "ethereum/go-ethereum",
            "commit_sha": "00da4f5",
            "pr_number": None,
            "has_vulnerabilities": True,
            "summary": "Potential reentrancy issue",
            "findings_count": 1,
            "created_at": "2026-04-03T10:00:02+00:00",
        },
    ]

    deduplicated = deduplicate_finding_dicts(findings)

    assert [finding["uuid"] for finding in deduplicated] == ["newest"]


def test_deduplicate_findings_keeps_distinct_rescans_outside_duplicate_window():
    findings = [
        {
            "uuid": "recent",
            "repo_name": "ethereum/go-ethereum",
            "commit_sha": "00da4f5",
            "pr_number": None,
            "has_vulnerabilities": True,
            "summary": "Potential reentrancy issue",
            "findings_count": 1,
            "created_at": "2026-04-03T11:00:00+00:00",
        },
        {
            "uuid": "older-rescan",
            "repo_name": "ethereum/go-ethereum",
            "commit_sha": "00da4f5",
            "pr_number": None,
            "has_vulnerabilities": True,
            "summary": "Potential reentrancy issue",
            "findings_count": 1,
            "created_at": "2026-04-03T10:00:00+00:00",
        },
    ]

    deduplicated = deduplicate_finding_dicts(findings)

    assert [finding["uuid"] for finding in deduplicated] == ["recent", "older-rescan"]
