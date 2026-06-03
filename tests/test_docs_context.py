from pr_security_review.docs_context import build_review_context, map_agent_path_to_docs_dir


def test_execution_agent_maps_to_execution_docs():
    docs_dir = map_agent_path_to_docs_dir("agents/execution-layer/AGENTS.md")

    assert docs_dir.as_posix().endswith("/vectordb-docs/docs/execution")


def test_consensus_agent_maps_to_consensus_docs():
    docs_dir = map_agent_path_to_docs_dir("agents/consensus-layer/AGENTS.md")

    assert docs_dir.as_posix().endswith("/vectordb-docs/docs/consensus")


def test_other_agent_path_falls_back_to_full_docs():
    docs_dir = map_agent_path_to_docs_dir("agents/misc/AGENT.md")

    assert docs_dir.as_posix().endswith("/vectordb-docs/docs")


def test_build_review_context_prefers_hardfork_specific_docs():
    context = build_review_context(
        "agents/execution-layer/AGENTS.md",
        "Validate blob transaction handling against eip-4844",
        hardfork_name="cancun",
    )

    assert context.text
    assert context.scope_description == "hardfork:cancun"
    assert any("/execution/eips/cancun/" in path or "/execution/specs/cancun/" in path for path in context.selected_docs)
