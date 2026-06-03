"""
Helpers for identifying duplicate findings created by repeated persistence.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, Iterable, List, Optional


DUPLICATE_FINDING_WINDOW_SECONDS = 300


def finding_identity(finding: Any) -> tuple:
    """Build the comparison key used to detect duplicate findings."""
    return (
        getattr(finding, 'repo_name', None),
        getattr(finding, 'pr_number', None),
        getattr(finding, 'commit_sha', None),
        getattr(finding, 'has_vulnerabilities', None),
        getattr(finding, 'summary', None),
        getattr(finding, 'findings_count', None),
    )


def parse_created_at(created_at: Optional[str]) -> Optional[datetime.datetime]:
    """Parse an ISO timestamp if available."""
    if not created_at:
        return None

    try:
        return datetime.datetime.fromisoformat(created_at.replace('Z', '+00:00'))
    except Exception:
        return None


def deduplicate_finding_dicts(
    findings: List[Dict[str, Any]],
    duplicate_window_seconds: int = DUPLICATE_FINDING_WINDOW_SECONDS
) -> List[Dict[str, Any]]:
    """Collapse nearby duplicate findings while keeping the newest row."""
    deduplicated = []
    seen: Dict[tuple, Optional[datetime.datetime]] = {}

    for finding in findings:
        identity = (
            finding.get('repo_name'),
            finding.get('pr_number'),
            finding.get('commit_sha'),
            finding.get('has_vulnerabilities'),
            finding.get('summary'),
            finding.get('findings_count'),
        )
        created_at = parse_created_at(finding.get('created_at'))
        previous_created_at = seen.get(identity)

        if previous_created_at and created_at:
            age_delta = abs((previous_created_at - created_at).total_seconds())
            if age_delta <= duplicate_window_seconds:
                continue
        elif identity in seen:
            continue

        seen[identity] = created_at
        deduplicated.append(finding)

    return deduplicated


def find_duplicate_finding_uuids(
    findings: Iterable[Any],
    duplicate_window_seconds: int = DUPLICATE_FINDING_WINDOW_SECONDS
) -> List[str]:
    """
    Identify duplicate finding UUIDs from a newest-first ordered iterable.

    The first record for a given finding identity is kept. Additional rows are
    considered duplicates only when their creation timestamps are close enough
    to indicate they came from the same scan event.
    """
    duplicates: List[str] = []
    seen: Dict[tuple, Optional[datetime.datetime]] = {}

    for finding in findings:
        identity = finding_identity(finding)
        created_at = getattr(finding, 'created_at', None)
        previous_created_at = seen.get(identity)

        if previous_created_at and created_at:
            age_delta = abs((previous_created_at - created_at).total_seconds())
            if age_delta <= duplicate_window_seconds:
                duplicates.append(str(getattr(finding, 'uuid')))
                continue
        elif identity in seen:
            duplicates.append(str(getattr(finding, 'uuid')))
            continue

        seen[identity] = created_at

    return duplicates
