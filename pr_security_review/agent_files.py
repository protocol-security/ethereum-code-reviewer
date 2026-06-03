"""
Filesystem-backed agent prompt discovery and loading.
"""

from __future__ import annotations

from pathlib import Path
from typing import List


REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_ROOT = REPO_ROOT / "agents"
VALID_AGENT_FILENAMES = {"AGENT.md", "AGENTS.md"}


def discover_agent_files() -> List[str]:
    """Return all valid agent prompt files relative to the repo root."""
    if not AGENTS_ROOT.exists():
        return []

    discovered = []
    for path in AGENTS_ROOT.rglob("*.md"):
        if path.name not in VALID_AGENT_FILENAMES:
            continue
        discovered.append(path.relative_to(REPO_ROOT).as_posix())

    return sorted(discovered)


def resolve_agent_file(relative_path: str) -> Path:
    """Resolve and validate a repository-configured agent file path."""
    if not relative_path:
        raise ValueError("Agent file path is required")

    candidate = (REPO_ROOT / relative_path).resolve()

    try:
        candidate.relative_to(AGENTS_ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"Agent file must live under {AGENTS_ROOT.relative_to(REPO_ROOT).as_posix()}") from exc

    if candidate.name not in VALID_AGENT_FILENAMES:
        raise ValueError("Agent file must be named AGENT.md or AGENTS.md")

    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(f"Agent file not found: {relative_path}")

    return candidate


def load_agent_instructions(relative_path: str) -> str:
    """Load the selected agent instructions from disk."""
    agent_file = resolve_agent_file(relative_path)
    return agent_file.read_text(encoding="utf-8")
