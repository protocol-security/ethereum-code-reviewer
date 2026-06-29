"""Stream-json parsing + swarm helpers for the CLI-driven audit."""

import asyncio
import json

from ethereum_code_reviewer.claude_review import (
    SecurityReview, _dedupe_candidates, _json_object, FINDER_SPECS,
)


def _reviewer():
    r = SecurityReview.__new__(SecurityReview)  # bypass __init__ (no env/CLI)
    r.stream_live = False
    return r


def test_consume_stream_event_assistant_blocks():
    r = _reviewer()
    transcript = []
    event = {
        "type": "assistant",
        "message": {"content": [
            {"type": "thinking", "thinking": "tracing the call"},
            {"type": "text", "text": "Reading the file"},
            {"type": "tool_use", "name": "Read", "input": {"file_path": "x.go"}},
        ]},
    }
    assert r._consume_stream_event(event, transcript, "crash-sweep") == ""
    rec = transcript[-1]
    assert rec["type"] == "assistant"
    assert rec["text"] == "Reading the file"
    assert rec["thinking"] == "tracing the call"
    assert rec["tools"] == [{"name": "Read", "input": {"file_path": "x.go"}}]


def test_consume_stream_event_result_returns_text():
    r = _reviewer()
    transcript = []
    event = {"type": "result", "subtype": "success", "result": '{"candidates":[]}'}
    assert r._consume_stream_event(event, transcript, None) == '{"candidates":[]}'
    assert transcript[-1] == {"type": "result", "subtype": "success"}


def test_consume_ignores_system_and_unknown():
    r = _reviewer()
    transcript = []
    assert r._consume_stream_event({"type": "system", "subtype": "init"}, transcript, None) == ""
    assert transcript == []


def test_json_object_extracts_from_fenced_or_plain():
    assert _json_object('{"candidates": []}') == {"candidates": []}
    assert _json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert _json_object("not json at all") is None
    assert _json_object('[1,2,3]') is None  # arrays aren't accepted as the object


def test_dedupe_candidates_by_location_and_title():
    cands = [
        {"location": "a.go:10", "title": "panic"},
        {"location": "A.GO:10", "title": "Panic"},  # same, case-insensitive
        {"location": "b.go:20", "title": "race"},
    ]
    out = _dedupe_candidates(cands)
    assert len(out) == 2
    assert {c["location"] for c in out} == {"a.go:10", "b.go:20"}


def test_finder_specs_cover_the_three_classes():
    labels = {f["label"] for f in FINDER_SPECS}
    assert labels == {"crash-sweep", "logic", "spec"}
    for f in FINDER_SPECS:
        assert f["focus"].strip()


def test_pipeline_finders_to_verify_to_synthesis():
    """Mock the CLI substrate and check the swarm wiring end to end."""
    r = _reviewer()
    r.model = "test-model"

    async def fake_cli(*, system_prompt, prompt, working_directory=None, label=None):
        if label == "crash-sweep":
            text = json.dumps({"candidates": [
                {"severity": "HIGH", "title": "panic in simulate", "location": "x/simulate.go:412",
                 "description": "reachable panic"},
            ]})
        elif label == "logic":
            text = json.dumps({"candidates": [
                {"severity": "HIGH", "title": "double finalise", "location": "x/statedb.go:900",
                 "description": "return discarded"},
                {"severity": "LOW", "title": "noise", "location": "x/z.go:1", "description": "bogus"},
            ]})
        elif label == "spec":
            text = json.dumps({"candidates": []})
        elif label and label.startswith("verify#"):
            # Confirm the two HIGH candidates (distinct locations); reject "noise".
            confirm = "panic" in prompt or "double finalise" in prompt
            loc = "x/simulate.go:412" if "panic" in prompt else "x/statedb.go:900"
            text = json.dumps({
                "confirmed": confirm, "reason": "checked",
                "severity": "HIGH", "title": f"confirmed {loc}", "location": loc,
                "description": "d", "recommendation": "fix", "detailed_explanation": "e",
                "impact": "crash", "detailed_recommendation": "do x", "code_example": "", "references": "",
            })
        elif label == "synthesis":
            text = json.dumps({"summary": "Two real crashes.", "analysis": "traced both",
                               "spec_compliance": "Not spec-relevant"})
        else:
            text = "{}"
        return text, [{"type": "result", "subtype": "success"}]

    r._run_cli_agent = fake_cli
    result = asyncio.run(r._run_audit_pipeline(
        system_prompt="sys", context_block="ctx", context_brief="brief", working_directory=None,
    ))

    assert result["has_vulnerabilities"] is True
    assert result["summary"] == "Two real crashes."
    assert result["spec_compliance"] == "Not spec-relevant"
    # 3 candidates found, all verified, 2 confirmed (the LOW "noise" rejected)
    assert result["_stats"] == {"candidates": 3, "verified": 3, "confirmed": 2}
    assert len(result["findings"]) == 2
    # verdict-internal fields are stripped from the surfaced findings
    assert all("confirmed" not in f and "reason" not in f for f in result["findings"])


def test_pipeline_no_candidates_is_clean():
    r = _reviewer()
    r.model = "test-model"

    async def fake_cli(*, system_prompt, prompt, working_directory=None, label=None):
        if label == "synthesis":
            return json.dumps({"summary": "", "analysis": "", "spec_compliance": ""}), []
        return json.dumps({"candidates": []}), []

    r._run_cli_agent = fake_cli
    result = asyncio.run(r._run_audit_pipeline(
        system_prompt="sys", context_block="ctx", context_brief="brief", working_directory=None,
    ))
    assert result["has_vulnerabilities"] is False
    assert result["findings"] == []
    assert "No vulnerabilities identified" in result["summary"]  # default when synth is empty
