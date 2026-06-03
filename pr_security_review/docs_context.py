"""
Local `vectordb-docs` context selection for reviews.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_ROOT = REPO_ROOT / "vectordb-docs" / "docs"
TOKEN_RE = re.compile(r"[a-zA-Z0-9_./-]+")


@dataclass(frozen=True)
class ReviewContextResult:
    """Selected docs and formatted review context."""

    text: str
    selected_docs: List[str]
    scope_description: str


def map_agent_path_to_docs_dir(agent_file_path: str) -> Path:
    normalized = agent_file_path.lower()
    if normalized.startswith("agents/execution-layer/"):
        return DOCS_ROOT / "execution"
    if normalized.startswith("agents/consensus-layer/"):
        return DOCS_ROOT / "consensus"
    return DOCS_ROOT


def _tokenize(text: str) -> List[str]:
    return [token.lower() for token in TOKEN_RE.findall(text) if len(token) >= 3]


def _normalize_hardfork_name(hardfork_name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", hardfork_name.lower()).strip("_")


@lru_cache(maxsize=16)
def _load_docs_index(docs_dir: str) -> List[Dict[str, str]]:
    root = Path(docs_dir)
    if not root.exists():
        return []

    indexed = []
    for path in sorted(root.rglob("*.md")):
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = path.read_text(encoding="utf-8", errors="ignore")

        indexed.append({
            "path": path.relative_to(REPO_ROOT).as_posix(),
            "content": content,
        })

    return indexed


def _score_document(query_tokens: Sequence[str], doc_path: str, doc_content: str, preferred_prefixes: Sequence[str]) -> int:
    path_text = doc_path.lower()
    content_text = doc_content.lower()

    score = 0
    for prefix in preferred_prefixes:
        if path_text.startswith(prefix.lower()):
            score += 50

    for token in query_tokens:
        if token in path_text:
            score += 6
        if token in content_text:
            score += min(content_text.count(token), 5)
    return score


def _preferred_hardfork_prefixes(docs_dir: Path, hardfork_name: str) -> tuple[List[str], str]:
    normalized_hardfork = _normalize_hardfork_name(hardfork_name)
    preferred_paths: List[Path] = []

    for subdir_name in ("eips", "specs"):
        subdir_root = docs_dir / subdir_name
        if not subdir_root.exists():
            continue
        for candidate in subdir_root.iterdir():
            if candidate.is_dir() and _normalize_hardfork_name(candidate.name) == normalized_hardfork:
                preferred_paths.append(candidate)

    vulnerabilities_dir = docs_dir / "vulnerabilities"
    if vulnerabilities_dir.exists():
        preferred_paths.append(vulnerabilities_dir)

    if preferred_paths:
        return [path.relative_to(REPO_ROOT).as_posix() for path in preferred_paths], f"hardfork:{hardfork_name}"

    return [], "layer-fallback"


def build_review_context(
    agent_file_path: str,
    query_text: str,
    hardfork_name: str | None = None,
    max_docs: int = 6,
    max_chars: int = 45000,
) -> ReviewContextResult:
    """Select a bounded set of relevant docs and format them for review input."""
    docs_dir = map_agent_path_to_docs_dir(agent_file_path)
    docs = _load_docs_index(str(docs_dir))
    if not docs:
        return ReviewContextResult(text="", selected_docs=[], scope_description="no-docs")

    preferred_prefixes: List[str] = []
    scope_description = "layer-wide"
    query = query_text
    if hardfork_name:
        preferred_prefixes, scope_description = _preferred_hardfork_prefixes(docs_dir, hardfork_name)
        query = f"{hardfork_name}\n{query_text}"

    query_tokens = _tokenize(query)
    scored_docs = []
    for doc in docs:
        score = _score_document(query_tokens, doc["path"], doc["content"], preferred_prefixes)
        if score <= 0:
            continue
        scored_docs.append((score, doc))

    if not scored_docs:
        return ReviewContextResult(text="", selected_docs=[], scope_description=scope_description)

    scored_docs.sort(key=lambda item: (-item[0], item[1]["path"]))

    included = []
    selected_docs = []
    used_chars = 0
    for _, doc in scored_docs[:max_docs]:
        remaining = max_chars - used_chars
        if remaining <= 0:
            break

        snippet = doc["content"][:remaining]
        included.append(f"## {doc['path']}\n\n{snippet}")
        selected_docs.append(doc["path"])
        used_chars += len(snippet)

    if not included:
        return ReviewContextResult(text="", selected_docs=[], scope_description=scope_description)

    return ReviewContextResult(
        text="# Additional Context From vectordb-docs\n\n" + "\n\n".join(included),
        selected_docs=selected_docs,
        scope_description=scope_description,
    )
