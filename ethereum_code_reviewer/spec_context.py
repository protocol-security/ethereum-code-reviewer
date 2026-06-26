"""
Live EIP context fetcher for reviews.

Replaces the vendored ``vectordb-docs`` corpus with runtime fetches from the
canonical Ethereum sources, so reviews always use the latest EIP text with no
hand-maintained fork tables.

How the fork EIP set is discovered (zero maintenance):

1. ``https://eips.ethereum.org/meta`` lists the "Hardfork Meta" EIP for every
   fork, including drafts (Fusaka, Glamsterdam, BPO3, ...). We parse it into a
   ``{fork_name: meta_eip_number}`` map at runtime, so new forks appear
   automatically.
2. For the requested ``--hardfork`` we fetch that Meta EIP and parse its
   "Included EIPs" (final forks) or "EIPs Scheduled for Inclusion" (drafts)
   section — the authoritative, complete set across execution and consensus.
3. Each EIP is fetched from ``ethereum/EIPs``. EIPs referenced directly in the
   diff are always fetched too.

Every call reconciles expected-vs-fetched into ``ReviewContextResult.manifest``
so "did we get all of <fork>?" has a concrete answer; ``strict=True`` raises
``SpecFetchError`` when an expected EIP is missing.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests


META_INDEX_URL = "https://eips.ethereum.org/meta"
EIPS_RAW = "https://raw.githubusercontent.com/ethereum/EIPs/master/EIPS/eip-{n}.md"

HTTP_TIMEOUT = 10
DEFAULT_MAX_DOCS = 30
DEFAULT_MAX_CHARS = 45000
DEFAULT_PER_FILE_CHARS = 16000

EIP_RE = re.compile(r"\bEIP[-\s]?(\d{1,5})\b", re.IGNORECASE)
INCLUDED_EIP_LINK_RE = re.compile(r"\[EIP-(\d{1,5})\]", re.IGNORECASE)
_META_ROW_RE = re.compile(
    r'<td class="eipnum"><a href="/EIPS/eip-(\d+)">\d+</a></td>\s*'
    r'<td class="title">([^<]+)</td>',
    re.S,
)
_META_TITLE_RE = re.compile(r"Hardfork Meta(?:\s+Backfill)?\s*[:\-]\s*(.+)", re.IGNORECASE)
# Meta-EIP section that lists the fork's EIPs (final vs draft wording). Must NOT
# match "Considered/Proposed/Declined for Inclusion".
_INCLUDED_HEADING_RE = re.compile(r"included eips|scheduled for inclusion", re.IGNORECASE)

# Optional convenience: map execution/consensus code-names to the marketing fork
# name used by the meta index. Not load-bearing for EIP correctness (the index is
# the source of truth); it only lets users pass e.g. ``--hardfork fulu``.
FORK_ALIASES: Dict[str, str] = {
    "fulu": "fusaka",
    "osaka": "fusaka",
    "electra": "pectra",
    "prague": "pectra",
    "deneb": "dencun",
    "cancun": "dencun",
}


class SpecFetchError(RuntimeError):
    """Raised in strict mode when expected EIPs could not be fetched."""


@dataclass(frozen=True)
class ReviewContextResult:
    """Selected docs, formatted review context, and a fetch manifest."""

    text: str
    selected_docs: List[str]
    scope_description: str
    manifest: Dict[str, object] = field(default_factory=dict)


def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def _cache_dir() -> Path:
    base = os.environ.get("REVIEWER_CACHE_DIR") or os.path.join(tempfile.gettempdir(), "ethereum_code_reviewer_specs")
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _warn(message: str) -> None:
    print(f"[spec_context] {message}", file=sys.stderr)


def _get(url: str) -> Optional[str]:
    try:
        response = requests.get(url, timeout=HTTP_TIMEOUT)
    except requests.RequestException as exc:
        _warn(f"fetch {url} failed: {exc}")
        return None
    if response.status_code != 200:
        _warn(f"fetch {url} -> HTTP {response.status_code}")
        return None
    return response.text


def _fetch_eip(number: int) -> Optional[str]:
    """Fetch an EIP markdown (cached; EIP text is effectively immutable)."""
    cache_file = _cache_dir() / f"eip-{number}.md"
    if cache_file.exists():
        try:
            return cache_file.read_text(encoding="utf-8")
        except OSError:
            pass
    text = _get(EIPS_RAW.format(n=number))
    if text is not None:
        try:
            cache_file.write_text(text, encoding="utf-8")
        except OSError:
            pass
    return text


@lru_cache(maxsize=1)
def fork_meta_index() -> Dict[str, int]:
    """Return ``{normalized_fork_name: meta_eip_number}`` from the live meta index."""
    html = _get(META_INDEX_URL)
    if html is None:
        return {}
    index: Dict[str, int] = {}
    for number, title in _META_ROW_RE.findall(html):
        match = _META_TITLE_RE.match(title.strip())
        if not match:
            continue
        name = match.group(1).strip()
        if " to " in name.lower():  # skip "Berlin to Shapella" backfill meta
            continue
        index[_normalize(name)] = int(number)
    return index


def resolve_meta_eip(hardfork_name: str) -> Optional[int]:
    """Resolve a fork name to its Meta EIP number via the live index (+aliases)."""
    index = fork_meta_index()
    key = _normalize(hardfork_name)
    if key in index:
        return index[key]
    alias = FORK_ALIASES.get(key)
    if alias and _normalize(alias) in index:
        return index[_normalize(alias)]
    return None


def extract_eip_numbers(text: str) -> List[int]:
    """Return EIP numbers referenced in ``text``, deduped, first-seen order."""
    seen: Set[int] = set()
    ordered: List[int] = []
    for match in EIP_RE.finditer(text or ""):
        number = int(match.group(1))
        if number not in seen:
            seen.add(number)
            ordered.append(number)
    return ordered


def parse_included_eips(meta_markdown: str) -> Set[int]:
    """Parse the included/scheduled EIP set from a fork Meta EIP body.

    Targets the "Included EIPs" (final) or "EIPs Scheduled for Inclusion" (draft)
    heading and reads until the next heading of the same or higher level, so
    deeper "#### Core/Other EIPs" subsections are kept while sibling
    "Considered/Proposed/Declined for Inclusion" sections are excluded.
    """
    if not meta_markdown:
        return set()

    lines = meta_markdown.splitlines()
    target_index = None
    target_level = 0
    for index, line in enumerate(lines):
        heading = re.match(r"^(#{1,6})\s+(.*)", line)
        if heading and _INCLUDED_HEADING_RE.search(heading.group(2)):
            target_index = index
            target_level = len(heading.group(1))
            break
    if target_index is None:
        return set()

    section: List[str] = []
    for line in lines[target_index + 1:]:
        heading = re.match(r"^(#{1,6})\s", line)
        if heading and len(heading.group(1)) <= target_level:
            break
        section.append(line)

    body = "\n".join(section)
    numbers = {int(match.group(1)) for match in INCLUDED_EIP_LINK_RE.finditer(body)}
    if not numbers:
        numbers = {int(match.group(1)) for match in EIP_RE.finditer(body)}
    return numbers


def expected_eips_for_fork(hardfork_name: str) -> Tuple[Optional[int], Set[int]]:
    """Return (meta EIP number, expected EIP set) for a fork, or (None, set())."""
    meta_eip = resolve_meta_eip(hardfork_name)
    if meta_eip is None:
        return None, set()
    meta = _fetch_eip(meta_eip)
    if meta is None:
        return meta_eip, set()
    return meta_eip, parse_included_eips(meta)


def _truncate(content: str, limit: int) -> str:
    if len(content) <= limit:
        return content
    return content[:limit] + "\n\n... [truncated]"


def build_review_context(
    agent_file_path: str,
    query_text: str,
    hardfork_name: Optional[str] = None,
    strict: bool = False,
    max_docs: int = DEFAULT_MAX_DOCS,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> ReviewContextResult:
    """Fetch the latest relevant EIPs and format them for review input."""
    diff_eips = extract_eip_numbers(query_text)
    expected: Set[int] = set()
    meta_eip: Optional[int] = None
    failures: List[str] = []

    if hardfork_name:
        meta_eip, expected = expected_eips_for_fork(hardfork_name)
        if meta_eip is None:
            failures.append(f"unknown-hardfork:{hardfork_name}")
        elif not expected:
            failures.append(f"meta-eip-{meta_eip}-parse")

    # Most-relevant first: diff-referenced EIPs, then the rest of the fork set.
    ordered_eips: List[int] = list(diff_eips)
    for number in sorted(expected):
        if number not in ordered_eips:
            ordered_eips.append(number)

    fetched: List[Tuple[str, int, str]] = []  # (source_id, number, content)
    fetched_eips: Set[int] = set()
    cache_root = _cache_dir()
    cache_hits = 0
    downloaded = 0
    for number in ordered_eips:
        was_cached = (cache_root / f"eip-{number}.md").exists()
        markdown = _fetch_eip(number)
        if markdown is None:
            failures.append(f"eip-{number}")
            continue
        fetched_eips.add(number)
        cache_hits += int(was_cached)
        downloaded += int(not was_cached)
        fetched.append((f"EIPS/eip-{number}.md", number, markdown))

    missing_eips = sorted(expected - fetched_eips)
    manifest: Dict[str, object] = {
        "hardfork": hardfork_name,
        "meta_eip": meta_eip,
        "expected_eips": sorted(expected),
        "fetched_eips": sorted(fetched_eips),
        "missing_eips": missing_eips,
        "cache_hits": cache_hits,
        "downloaded": downloaded,
        "failures": failures,
    }
    _warn(
        "manifest: hardfork={hf} meta_eip={meta} expected={exp} fetched={fet} "
        "(cached={hit} new={dl}) missing={miss} failures={fail}".format(
            hf=hardfork_name,
            meta=meta_eip,
            exp=len(expected),
            fet=len(fetched_eips),
            hit=cache_hits,
            dl=downloaded,
            miss=missing_eips,
            fail=failures,
        )
    )

    if strict:
        problems = []
        if hardfork_name and meta_eip is None:
            problems.append(f"unknown hardfork '{hardfork_name}' (not in {META_INDEX_URL})")
        if meta_eip is not None and not expected:
            problems.append(f"could not parse EIPs from meta EIP-{meta_eip}")
        if missing_eips:
            problems.append(f"missing EIPs {missing_eips}")
        if problems:
            raise SpecFetchError("; ".join(problems))

    if not fetched:
        return ReviewContextResult("", [], "spec-fetch-unavailable", manifest)

    included: List[str] = []
    selected_docs: List[str] = []
    used_chars = 0
    for source_id, number, content in fetched[:max_docs]:
        remaining = max_chars - used_chars
        if remaining <= 0:
            break
        snippet = _truncate(content, min(DEFAULT_PER_FILE_CHARS, remaining))
        included.append(f"## EIP-{number}\n\n{snippet}")
        selected_docs.append(source_id)
        used_chars += len(snippet)

    if hardfork_name and meta_eip is not None:
        scope = f"hardfork:{hardfork_name}"
    elif diff_eips:
        scope = "eip-refs"
    else:
        scope = "no-specs"

    return ReviewContextResult(
        text="# EIP Context (fetched live)\n\n" + "\n\n".join(included),
        selected_docs=selected_docs,
        scope_description=scope,
        manifest=manifest,
    )
