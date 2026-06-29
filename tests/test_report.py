"""Report rendering + diff-range parsing for the review output."""

import types

from ethereum_code_reviewer.report import build_review_report, emit_review_report
from ethereum_code_reviewer.claude_review import parse_changed_file_ranges, _oneline, _paint_signals


def _has_emoji(text):
    # Any non-ASCII pictographic char (en-dash and accents are fine; emojis aren't).
    return any(ord(ch) >= 0x2600 for ch in text)


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
        "summary": "Looks correct against the fork spec.",
        "findings": [],
        "_reasoning_log": {"repo_name": "sigp/lighthouse", **log},
    }
    return base


def test_report_no_confidence_and_fork_aware_header():
    analysis = _analysis()
    header = {
        "title": "PR #9516: Fix peerless lookup",
        "url": "https://github.com/sigp/lighthouse/pull/9516",
        "repo": "sigp/lighthouse",
        "fork_of": "protocol-security/lighthouse-ecr-testing",
        "branch": "unstable",
    }
    out = build_review_report(analysis, None, header=header)
    assert "[PR #9516: Fix peerless lookup](https://github.com/sigp/lighthouse/pull/9516)" in out
    assert "[sigp/lighthouse](https://github.com/sigp/lighthouse)" in out
    assert "protocol-security/lighthouse-ecr-testing" in out  # shown as fork origin
    assert "confidence" not in out.lower()  # confidence fully removed
    assert not _has_emoji(out)  # no emojis anywhere


def test_report_non_fork_repo_has_no_fork_note():
    out = build_review_report(_analysis(), None, header={"repo": "sigp/lighthouse"})
    assert "[sigp/lighthouse](https://github.com/sigp/lighthouse)" in out
    assert "fork:" not in out


def test_report_renders_analysis_and_spec_compliance_sections():
    analysis = _analysis()
    analysis["analysis"] = "Traced `is_awaiting_event()` to both call sites in `mod.rs`."
    analysis["spec_compliance"] = "Not spec-relevant; does not touch EIP-7594 behavior."
    out = build_review_report(analysis, None)
    assert "## Analysis" in out
    assert "Traced `is_awaiting_event()` to both call sites" in out
    assert "## Spec compliance" in out
    assert "EIP-7594" in out


def test_report_omits_empty_analysis_sections():
    out = build_review_report(_analysis(), None)  # no analysis/spec_compliance
    assert "## Analysis" not in out
    assert "## Spec compliance" not in out


def test_stream_suppresses_json_answer_and_empty_thinking(capsys):
    from ethereum_code_reviewer.claude_review import _print_stream_block
    _print_stream_block("thinking", "   ")                       # empty -> skip
    _print_stream_block("text", '{"has_vulnerabilities": false}')  # JSON answer -> skip
    _print_stream_block("text", "I traced the call sites.")        # real reasoning -> shown
    err = capsys.readouterr().err
    assert "has_vulnerabilities" not in err
    assert "thinking:" not in err
    assert "I traced the call sites." in err


def test_report_clean_verdict_includes_summary_and_files():
    analysis = _analysis(
        analysed_files=[{"file": "a.rs", "ranges": [(10, 20)]}],
        spec_manifest={"hardfork": "fusaka", "meta_eip": 7607, "fetched_eips": [7594], "missing_eips": []},
        docs_scope="hardfork:fusaka",
    )
    out = build_review_report(analysis, types.SimpleNamespace(model="claude-opus-4-8"), title="PR #1")
    assert "**Verdict:** No vulnerabilities detected" in out
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
    assert "Read `x.rs`" in summary           # tool calls always shown
    assert "thinking out loud" not in summary  # reasoning text only in full
    assert "thinking out loud" in full


def test_report_renders_findings_with_severity_badge():
    analysis = {
        "has_vulnerabilities": True,
        "summary": "One issue.",
        "findings": [{"severity": "HIGH", "title": "panic on None",
                      "description": "It unwraps.", "recommendation": "return Err"}],
        "_reasoning_log": {},
    }
    out = build_review_report(analysis, None)
    assert "**Verdict:** 1 potential issue(s) found" in out
    assert "### HIGH — panic on None" in out
    assert "<summary>Raw JSON review</summary>" in out
    assert not _has_emoji(out)


def test_finding_location_links_to_upstream_and_diff_fence():
    analysis = {
        "has_vulnerabilities": True, "summary": "x",
        "findings": [{
            "severity": "HIGH", "title": "wrong gas constant",
            "location": "crates/precompile/src/bls12_381_const.rs:24",
            "description": "The constant is hex.", "impact": "chain split",
            "recommendation": "use decimal",
            "code_example": "-const X: u64 = 0x23800;\n+const X: u64 = 23800;",
            "references": "EIP-2537",
        }],
        "_reasoning_log": {},
    }
    header = {"repo": "sigp/lighthouse", "commit": "abc123"}
    out = build_review_report(analysis, None, header=header)
    # location is a clickable blob link at the reviewed commit, anchored to the line
    assert "[`crates/precompile/src/bls12_381_const.rs:24`]" in out
    assert "https://github.com/sigp/lighthouse/blob/abc123/crates/precompile/src/bls12_381_const.rs#L24" in out
    # patch rendered as a diff
    assert "```diff" in out
    # long description is NOT the heading
    assert "### HIGH — wrong gas constant" in out


def test_files_analysed_link_to_upstream_lines():
    analysis = _analysis(analysed_files=[{"file": "a/b.rs", "ranges": [(10, 20)]}])
    out = build_review_report(analysis, None, header={"repo": "o/r", "commit": "deadbeef"})
    assert "[`a/b.rs`](https://github.com/o/r/blob/deadbeef/a/b.rs)" in out
    assert "[L10–20](https://github.com/o/r/blob/deadbeef/a/b.rs#L10-L20)" in out


def test_long_finding_title_is_truncated_not_dumped_in_heading():
    long_desc = "MAP_FP2_TO_G2_BASE_GAS_FEE is 0x23800 instead of 23800. " * 5
    analysis = {
        "has_vulnerabilities": True, "summary": "x",
        "findings": [{"severity": "HIGH", "description": long_desc}],
        "_reasoning_log": {},
    }
    out = build_review_report(analysis, None)
    heading = next(ln for ln in out.splitlines() if ln.startswith("### HIGH"))
    assert len(heading) <= 110  # short, not the whole multi-sentence body


def test_raw_json_is_clean_and_fence_safe():
    import json
    # Model echoed its JSON wrapped in its own fences — must NOT leak into ours.
    analysis = {
        "has_vulnerabilities": False, "summary": "ok", "findings": [],
        "_reasoning_log": {"raw_output": "```json\n{\"x\": 1}\n```", "transcript": []},
    }
    out = build_review_report(analysis, None)
    # exactly one opening json fence — no nested/colliding fences
    assert out.count("```json") == 1
    # the embedded JSON is valid and excludes internal/confidence keys
    block = out.split("```json", 1)[1].split("```", 1)[0].strip()
    parsed = json.loads(block)
    assert "_reasoning_log" not in parsed
    assert "confidence_score" not in parsed
    assert parsed["has_vulnerabilities"] is False


def test_oneline_collapses_whitespace():
    assert _oneline("a\n  b   c", 100) == "a ⏎ b c"
    assert _oneline("x" * 50, 10) == "x" * 10 + " …"


def test_signal_painting_respects_no_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert "\x1b[1;31m" in _paint_signals("a consensus mismatch here")
    monkeypatch.setenv("NO_COLOR", "1")
    assert _paint_signals("a consensus mismatch here") == "a consensus mismatch here"


def test_emit_writes_markdown_to_summary_not_log(monkeypatch, tmp_path, capsys):
    # In CI, the rendered Markdown goes to the job summary; the step log only
    # gets a one-line pointer (GitHub logs don't render Markdown).
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    emit_review_report("# 🛡️ Report\n\n## Summary\n\nok")
    stdout = capsys.readouterr().out
    assert "Summary tab" in stdout
    assert "# 🛡️ Report" not in stdout            # raw markdown stays out of the log
    assert "# 🛡️ Report" in summary.read_text()    # ...and lands in the summary


def test_emit_falls_back_to_stdout_without_summary(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    emit_review_report("# 🛡️ Report\n\nok")
    assert "# 🛡️ Report" in capsys.readouterr().out  # local runs still see it
