from ethereum_code_reviewer.claude_review import CostInfo, build_storage_metadata


def test_build_storage_metadata_includes_reasoning_log():
    cost_info = CostInfo(
        total_cost=0.0,
        input_tokens=0,
        output_tokens=0,
        model="claude-test",
        provider="claude-code-sdk",
        metadata={"reasoning_log": {"raw_output": "{\"has_vulnerabilities\":false}"}},
    )

    metadata = build_storage_metadata(cost_info, {"source": "unit-test"})

    assert metadata["source"] == "unit-test"
    assert metadata["reasoning_log"]["raw_output"] == "{\"has_vulnerabilities\":false}"
