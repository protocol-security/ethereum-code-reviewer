"""Report rendering + diff-range parsing for the review output."""

import types

from ethereum_code_reviewer.report import build_review_report
from ethereum_code_reviewer.claude_review import parse_changed_file_ranges, _oneline, _paint_signals


def test_parse_changed_file_ranges_reads_hunks():
    diff = (
        "## Changed Files\n\n"
        "File: beacon/state.rs\n"
        "@@ -100,8 +101,8 @@ fn process()\n"
        " ctx\n"
        "@@ -200 +210,3 @@\n"
        "+x\n"
        "File: README.md\n"
        "@@ -1 +1 @@\n"
        "+hi\n"
    )
    assert parse_changed_file_ranges(diff) == [
        {"file": "beacon/state.rs", "ranges": [(101, 108), (210, 212)]},
        {"file": "README.md", "ranges": [(1, 1)]},
    ]


def test_parse_changed_file_ranges_skips_files_without_hunks():
    assert parse_changed_file_ranges("File: only_header.rs\n(no diff)\n") == []


def _analysis(**log):
    base = {
        "has_vulnerabilities": False,
        "confidence_score": 100,
        "summary": "Looks correct against the fork spec.",
        "findings": [],
        "_reasoning_log": {"repo_name": "sigp/lighthouse", **log},
    }
    return base


def test_report_clean_verdict_includes_summary_and_files():
    analysis = _analysis(
        analysed_files=[{"file": "a.rs", "ranges": [(10, 20)]}],
        spec_manifest={"hardfork": "fusaka", "meta_eip": 7607, "fetched_eips": [7594], "missing_eips": []},
        docs_scope="hardfork:fusaka",
    )
    out = build_review_report(analysis, types.SimpleNamespace(model="claude-opus-4-8"), title="PR #1")
    assert "✅ **No vulnerabilities detected**" in out
    assert "Looks correct against the fork spec." in out  # summary kept even when clean
    assert "`a.rs` — L10–20" in out
    assert "EIP-7594" in out
    assert "claude-opus-4-8" in out


def test_report_summary_detail_hides_reasoning_text_but_keeps_tools():
    analysis = _analysis(
        transcript=[{"type": "A", "text": "thinking out loud", "tools": [{"name": "Read", "input": {"file_path": "x.rs"}}]}],
    )
    summary = build_review_report(analysis, None, detail="summary")
    full = build_review_report(analysis, None, detail="full")
    assert "📄 Read `x.rs`" in summary       # tool calls always shown
    assert "thinking out loud" not in summary  # reasoning text only in full
    assert "thinking out loud" in full


def test_report_renders_findings_with_severity_badge():
    analysis = {
        "has_vulnerabilities": True, "confidence_score": 90,
        "summary": "One issue.",
        "findings": [{"severity": "HIGH", "description": "panic on None", "confidence": 90,
                      "recommendation": "return Err"}],
        "_reasoning_log": {"raw_output": '{"has_vulnerabilities": true}'},
    }
    out = build_review_report(analysis, None)
    assert "⚠️ **1 potential issue(s) found**" in out
    assert "🔴 HIGH — panic on None" in out
    assert "<details><summary>Raw JSON review</summary>" in out


def test_oneline_collapses_whitespace():
    assert _oneline("a\n  b   c", 100) == "a ⏎ b c"
    assert _oneline("x" * 50, 10) == "x" * 10 + " …"


def test_signal_painting_respects_no_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert "\x1b[1;31m" in _paint_signals("a consensus mismatch here")
    monkeypatch.setenv("NO_COLOR", "1")
    assert _paint_signals("a consensus mismatch here") == "a consensus mismatch here"
