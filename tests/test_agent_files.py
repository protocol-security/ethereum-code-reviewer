from pr_security_review.agent_files import discover_agent_files, load_agent_instructions


def test_discover_agent_files_finds_sample_agents():
    agent_files = discover_agent_files()

    assert "agents/consensus-layer/AGENTS.md" in agent_files
    assert "agents/execution-layer/AGENTS.md" in agent_files


def test_load_agent_instructions_reads_agent_markdown():
    instructions = load_agent_instructions("agents/execution-layer/AGENTS.md")

    assert "Execution Layer Review Agent" in instructions
