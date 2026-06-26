"""Network-gated end-to-end check of the live EIP fetcher.

Opt in with ``RUN_LIVE_SPEC_TESTS=1 pytest tests/test_spec_context_live.py``.
Uses a *finalized* fork (Dencun) as a stable oracle: its Meta EIP (7569) and its
"Included EIPs" set don't change, so ``expected == fetched`` must hold exactly.
"""

import os

import pytest

import pr_security_review.spec_context as sc


@pytest.mark.skipif(
    not os.environ.get("RUN_LIVE_SPEC_TESTS"),
    reason="set RUN_LIVE_SPEC_TESTS=1 to run live network tests",
)
def test_live_finalized_fork_complete(tmp_path, monkeypatch):
    monkeypatch.setenv("REVIEWER_CACHE_DIR", str(tmp_path))
    sc.fork_meta_index.cache_clear()

    result = sc.build_review_context(
        "agents/execution-layer/AGENTS.md", "", hardfork_name="dencun", strict=True
    )
    m = result.manifest
    assert m["meta_eip"] == 7569
    assert m["expected_eips"], "Dencun meta EIP should list included EIPs"
    assert m["missing_eips"] == []
    assert m["fetched_eips"] == m["expected_eips"]
