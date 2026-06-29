"""
Claude Agent SDK-backed security review implementation.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from github import Github, Auth
from github.PullRequest import PullRequest

from .agent_files import load_agent_instructions
from .commit_monitor import CommitMonitor
from .spec_context import ReviewContextResult, build_review_context
from .review_types import CommitInfo

# We drive the `claude` CLI (the same binary the Agent SDK wraps) directly as a
# subprocess so we can run a *swarm* of independent agents — several finders in
# parallel, a verifier per candidate, then synthesis — each its own process.
CLAUDE_CLI = os.environ.get("CLAUDE_CLI_PATH") or shutil.which("claude") or "claude"


REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_CLAUDE_MODEL = "claude-opus-4-8"

# Running headless Claude: block tools that wait for a human or spawn sub-agents,
# so the agent can't park and exit without a final answer.
DISALLOWED_TOOLS = [
    "ScheduleWakeup", "AskUserQuestion", "EnterPlanMode", "ExitPlanMode",
    "EnterWorktree", "ExitWorktree", "Monitor", "PushNotification",
    "CronCreate", "CronDelete", "CronList", "RemoteTrigger", "Task", "Workflow",
]

# --- Live stream rendering (mirrors KAT's stream-json view) ---------------
# A scannable, colorized live view of the agent as it works: thinking,
# reasoning, tool calls (one color per tool), result. Reproduction/consensus
# signal words are painted red so the eye catches them. No emojis.
_SIGNAL_RE = re.compile(
    r"(panic|invalid opcode|invalid|fatal|divergen[a-z]*|state.?root|mismatch|"
    r"consensus|slash|segfault|goroutine|stack trace|fork.?choice|timeout|"
    r"overflow|underflow|reentran[a-z]*|out.?of.?bounds)",
    re.IGNORECASE,
)
_TOOL_COLORS = {
    "Bash": "1;32", "Write": "1;33", "Edit": "1;33", "NotebookEdit": "1;33",
    "Read": "1;34", "Grep": "1;36", "Glob": "1;36",
    "WebFetch": "1;35", "WebSearch": "1;35",
}
_TOOL_FIELDS = ("command", "file_path", "path", "url", "pattern", "query")


def _use_color() -> bool:
    return os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return text if not _use_color() else f"\x1b[{code}m{text}\x1b[0m"


def _oneline(text: str, limit: int) -> str:
    text = re.sub(r"[\t\r ]*\n[\t\r ]*", " ⏎ ", text or "")
    text = re.sub(r"[ \t]{2,}", " ", text).strip()
    return text[:limit] + " …" if len(text) > limit else text


def _paint_signals(text: str) -> str:
    if not _use_color():
        return text
    return _SIGNAL_RE.sub(lambda m: _c("1;31", m.group(0)), text)


def _tool_summary(tool_input: Dict[str, Any]) -> str:
    for key in _TOOL_FIELDS:
        if tool_input.get(key):
            return str(tool_input[key])
    return json.dumps(tool_input, default=str)


def _print_stream_block(kind: str, payload: Any, label: Optional[str] = None) -> None:
    """Print one streamed event to stderr (flushed, colorized for live CI)."""
    tag = _c("35", f"[{label}] ") if label else ""
    if kind == "thinking":
        if not (payload or "").strip():
            return  # skip empty/redacted thinking blocks
        # Thinking is the reasoning the user wants to watch — give it room and
        # keep its paragraph breaks (indented) rather than clipping to one line.
        body = "\n".join("  " + ln for ln in payload.strip().splitlines())
        line = tag + _c("2", "thinking:\n" + body)
    elif kind == "text":
        # Don't echo the final JSON answer — it's noise in the log (and may carry
        # fields we don't surface, like a volunteered confidence score). It is
        # rendered, cleaned, in the report.
        stripped = (payload or "").strip()
        if not stripped or _looks_like_json_review(stripped) or stripped.startswith("{"):
            return
        line = tag + _c("36", "reasoning: ") + _paint_signals(_oneline(payload, 300))
    elif kind == "tool":
        name = payload.get("name", "tool")
        color = _TOOL_COLORS.get(name, "1;37")
        line = tag + _c(color, name) + "  " + _c("2", _oneline(_tool_summary(payload.get("input") or {}), 240))
    elif kind == "result":
        # Don't echo the result body — it just repeats the last assistant text.
        subtype = payload
        ok = subtype in (None, "success")
        line = tag + _c("1;32" if ok else "1;31",
                        "done" if ok else f"ended: {subtype}")
    else:
        return
    print("  " + line, file=sys.stderr, flush=True)


@dataclass
class CostInfo:
    """Cost information for an LLM request."""

    total_cost: float
    input_tokens: int
    output_tokens: int
    model: str
    provider: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"${self.total_cost:.6f} ({self.input_tokens} input + {self.output_tokens} output tokens, {self.model})"


def _extract_json_from_response(response_text: str) -> str:
    """Extract the outermost JSON object from an SDK response."""
    if not response_text:
        raise ValueError("Empty response text")

    response_text = response_text.strip()

    if response_text.startswith("```json"):
        response_text = response_text[7:]
    elif response_text.startswith("```"):
        response_text = response_text[3:]

    if response_text.endswith("```"):
        response_text = response_text[:-3]

    response_text = response_text.strip()

    try:
        json.loads(response_text)
        return response_text
    except json.JSONDecodeError:
        pass

    start_idx = response_text.find("{")
    if start_idx == -1:
        return response_text

    depth = 0
    in_string = False
    escape_next = False

    for index in range(start_idx, len(response_text)):
        char = response_text[index]

        if escape_next:
            escape_next = False
            continue

        if char == "\\" and in_string:
            escape_next = True
            continue

        if char == '"' and not escape_next:
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return response_text[start_idx:index + 1]

    return response_text[start_idx:]


_FILE_HEADER_RE = re.compile(r"^File:\s+(.+)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_changed_file_ranges(code_changes: str) -> List[Dict[str, Any]]:
    """Parse the review input into a list of changed files with line ranges.

    Reads the ``File: <name>`` blocks produced by ``get_pr_changes`` and the
    unified-diff ``@@ -a,b +c,d @@`` hunk headers, returning the new-side line
    ranges per file. Used to show reviewers exactly which lines were in scope.
    """
    files: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for line in (code_changes or "").splitlines():
        header = _FILE_HEADER_RE.match(line)
        if header:
            current = {"file": header.group(1).strip(), "ranges": []}
            files.append(current)
            continue
        hunk = _HUNK_RE.match(line)
        if hunk and current is not None:
            start = int(hunk.group(1))
            count = int(hunk.group(2)) if hunk.group(2) else 1
            end = start + max(count, 1) - 1
            current["ranges"].append((start, end))
    return [f for f in files if f["ranges"]]


def _looks_like_json_review(response_text: str) -> bool:
    """Best-effort check that the response carries a parseable JSON object."""
    if not response_text or not response_text.strip():
        return False
    try:
        json.loads(_extract_json_from_response(response_text))
        return True
    except (ValueError, json.JSONDecodeError):
        return False


def _validate_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize the review result into the existing app contract."""
    if "has_vulnerabilities" not in response:
        raise ValueError("Response missing 'has_vulnerabilities'")

    response.setdefault("findings", [])
    response.setdefault("summary", "")
    response.setdefault("analysis", "")
    response.setdefault("spec_compliance", "")

    if not response["has_vulnerabilities"]:
        response["findings"] = []

    return response


def build_storage_metadata(cost_info: Optional[CostInfo], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build finding metadata for persistence."""
    metadata = dict(extra or {})
    if cost_info:
        metadata["cost_info"] = str(cost_info)
        if cost_info.metadata.get("reasoning_log"):
            metadata["reasoning_log"] = cost_info.metadata["reasoning_log"]
    return metadata


def _json_object(text: str) -> Optional[Dict[str, Any]]:
    """Parse a JSON object out of an agent's final text, or None."""
    try:
        obj = json.loads(_extract_json_from_response(text))
        return obj if isinstance(obj, dict) else None
    except (ValueError, json.JSONDecodeError):
        return None


# The swarm's finders. Each is an independent agent with a single, narrow mandate,
# run in parallel. Splitting the work this way stops any one agent from tunnelling
# on a pet theory and skipping the obvious stuff (a panic finder WILL report every
# reachable panic; it has no other job).
FINDER_SPECS: List[Dict[str, str]] = [
    {
        "label": "crash-sweep",
        "focus": (
            "Find every way the CHANGED code can crash or abort at runtime. FIRST run "
            "grep over the changed files for: `panic(`, `todo!`, `unimplemented!`, "
            "`unreachable!`, `TODO`, `FIXME`, `XXX`, `.unwrap(`, `.expect(`. For EACH "
            "hit in non-test, runtime-reachable code (an RPC/API handler, validation, "
            "encoding/decoding, block processing) emit a candidate — a shipped panic/"
            "stub on a reachable path is a guaranteed crash/DoS. Do NOT excuse it as "
            "'scaffolding', 'WIP', 'incomplete', or 'intentional'. Also flag reachable "
            "nil/None dereferences and unchecked indexing/slicing."
        ),
    },
    {
        "label": "logic",
        "focus": (
            "Find logic and concurrency bugs in the CHANGED code: duplication / "
            "discarded-return bugs (the same call made twice, a result computed then "
            "thrown away and recomputed), the wrong constant/address/length/variant "
            "used (copy-paste from a sibling), off-by-one, ignored errors, integer "
            "overflow/truncation, and data races / missing locks (compare a changed "
            "method to its siblings — does it take the lock the others take?)."
        ),
    },
    {
        "label": "spec",
        "focus": (
            "Find spec/EIP-conformance defects in the CHANGED code: incorrect gas "
            "costs or constants, missing or wrong required behavior, wrong fork-gating, "
            "and deviations from the relevant EIP. Confirm any gas value or constant "
            "against the actual EIP text (use the spec context, or fetch the EIP) "
            "before flagging it; do not assert a consensus split you cannot ground in "
            "the spec."
        ),
    },
]

# A finder lists candidates exhaustively; depth comes later in the verifier.
_CANDIDATE_SCHEMA = (
    '{"candidates":[{"severity":"HIGH|MEDIUM|LOW","title":"<concise headline>",'
    '"location":"<path:line>","description":"<1-2 sentences>"}]}'
)
# The verifier independently confirms or rejects one candidate.
_VERDICT_SCHEMA = (
    '{"confirmed":true_or_false,"reason":"<why confirmed or rejected>",'
    '"severity":"HIGH|MEDIUM|LOW","title":"<headline>","location":"<path:line>",'
    '"description":"<1-2 sentence summary>","recommendation":"<1 sentence fix>",'
    '"detailed_explanation":"<the mechanism, in depth>","impact":"<what can happen>",'
    '"detailed_recommendation":"<how to fix, in depth>",'
    '"code_example":"<optional unified-diff patch>","references":"<optional EIP/spec>"}'
)
# Synthesis writes only the prose; the findings list comes from verified verdicts.
_SYNTHESIS_SCHEMA = (
    '{"summary":"<2-4 sentence verdict>","analysis":"<Markdown: what the change does '
    'and how it was reviewed>","spec_compliance":"<EIP conformance note, or '
    '\'Not spec-relevant\'>"}'
)


# Shared policy every swarm member sees (scope, verification discipline, formatting).
_REVIEW_POLICY = """REVIEW POLICY
You are reviewing THIS pull request's changes for concrete security vulnerabilities
AND spec/EIP-conformance defects. Center on the changed code; a genuine issue in the
code the change touches or sits among is good to surface too — don't chase unrelated
problems far from the PR.

VERIFICATION:
- A CODE DEFECT confirmable from the source alone (a reachable panic/TODO-stub, a
  double call, a missing lock, a wrong constant) — confirm it in the code and report
  it. Do NOT withhold an obviously-real code bug, and do NOT excuse a shipped panic/
  stub as "scaffolding", "WIP", or "intentional".
- A SPEC/IMPACT claim ("chain split", "consensus divergence", a gas/constant mismatch)
  requires confirming the governing EIP. Fetch/read the EIP; if you cannot confirm the
  requirement, downgrade to the impact you can prove or omit it. Never assert a
  consensus split you have not grounded in the spec.
Never surface a hedged, unconfirmed guess. Base every claim on the actual code you read.

FORMATTING: write prose in GitHub-flavored Markdown; wrap code identifiers (functions,
types, variants, fields, paths) in backticks; reference files and line numbers."""


def _dedupe_candidates(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop duplicate candidates surfaced by more than one finder."""
    seen = set()
    unique = []
    for c in candidates:
        key = (
            (c.get("location") or "").strip().lower(),
            (c.get("title") or c.get("description") or "").strip().lower()[:80],
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)
    return unique


class SecurityReview:
    """Claude-only security review entrypoint."""

    def __init__(
        self,
        provider_kwargs: Optional[Dict[str, Any]] = None,
        repo_name: Optional[str] = None,
        agent_file_path: Optional[str] = None,
    ):
        provider_kwargs = provider_kwargs or {}
        self.model = provider_kwargs.get("model") or os.environ.get("CLAUDE_MODEL") or DEFAULT_CLAUDE_MODEL
        self.default_repo_name = repo_name
        self.override_agent_file_path = agent_file_path
        # Stream the agent's thinking/tool calls live to the log as it works.
        # On by default (visibility is the point in CI); set STREAM_REVIEW=0 to mute.
        self.stream_live = provider_kwargs.get(
            "stream_live", os.environ.get("STREAM_REVIEW", "1") not in {"0", "false", "no"}
        )

        self.github_token = os.environ.get("INPUT_GITHUB-TOKEN") or os.environ.get("GITHUB_TOKEN")
        self.github = Github(auth=Auth.Token(self.github_token)) if self.github_token else None

    def _resolve_review_config(
        self,
        repo_name: Optional[str] = None,
        agent_file_path: Optional[str] = None,
    ) -> Tuple[str, str]:
        resolved_repo_name = repo_name or self.default_repo_name
        resolved_agent_file = agent_file_path or self.override_agent_file_path

        if resolved_agent_file:
            return resolved_repo_name or "", resolved_agent_file

        raise ValueError(
            "No agent file configured for this review. Pass --agent-file "
            "(a path under ./agents to an AGENT.md/AGENTS.md), e.g. "
            "agents/execution-layer/AGENTS.md."
        )

    def _resolve_pr_repo(self, repo_name: str):
        """Return the repo PRs should be read from.

        When the action runs on a fork, pull requests live on the upstream
        (source) repository, not the fork. GitHub returns 404 for
        ``fork.get_pull(n)`` in that case, so redirect to the upstream repo.
        """
        if not self.github:
            raise ValueError("GitHub client not initialized")
        repo = self.github.get_repo(repo_name)
        if getattr(repo, "fork", False):
            upstream = getattr(repo, "source", None) or getattr(repo, "parent", None)
            if upstream is not None:
                print(
                    f"\n{repo_name} is a fork; reading PRs from upstream "
                    f"{upstream.full_name}"
                )
                return upstream
        return repo

    def get_pr(self, repo_name: str, pr_number: int) -> PullRequest:
        return self._resolve_pr_repo(repo_name).get_pull(pr_number)

    def get_pr_changes(self, pr: PullRequest) -> str:
        changes = []
        for file in pr.get_files():
            if file.patch:
                changes.append(f"File: {file.filename}\n{file.patch}\n")
        return "\n".join(changes)

    def get_pr_review_input(self, pr: PullRequest) -> str:
        """Compose the full review material for a PR.

        Includes the PR title and body (the author's description of intent,
        markdown) followed by the changed files. The body often states what the
        change is meant to do, which the reviewer needs to judge whether the
        diff actually does it.
        """
        sections = [f"# Pull Request #{pr.number}: {pr.title or '(no title)'}"]
        body = (pr.body or "").strip()
        sections.append(
            f"## PR Description\n\n{body}" if body else "## PR Description\n\n(no description provided)"
        )
        changes = self.get_pr_changes(pr)
        sections.append(
            f"## Changed Files\n\n{changes}" if changes else "## Changed Files\n\n(no file diffs available)"
        )
        return "\n\n".join(sections)

    def get_recent_prs(self, repo_name: str, count: int = 10) -> List[PullRequest]:
        if not self.github:
            raise ValueError("GitHub client not initialized")
        repo = self.github.get_repo(repo_name)
        prs = repo.get_pulls(state="all", sort="created", direction="desc")
        return list(prs[:count])

    def get_latest_open_pr(self, repo_name: str) -> Optional[PullRequest]:
        repo = self._resolve_pr_repo(repo_name)
        prs = list(repo.get_pulls(state="open", sort="created", direction="desc")[:1])
        return prs[0] if prs else None

    def get_latest_commit_sha(self, repo_name: str, branch: Optional[str] = None) -> str:
        if not self.github:
            raise ValueError("GitHub client not initialized")
        repo = self.github.get_repo(repo_name)
        ref = branch or repo.default_branch
        return repo.get_branch(ref).commit.sha

    def get_file_content(self, repo_name: str, branch: str, file_path: str) -> str:
        if not self.github:
            raise ValueError("GitHub client not initialized")
        repo = self.github.get_repo(repo_name)
        file_content = repo.get_contents(file_path, ref=branch)
        if isinstance(file_content, list):
            raise ValueError(f"Path '{file_path}' refers to a directory, not a file")
        decoded_content = file_content.decoded_content.decode("utf-8")
        return f"File: {file_path}\n\n{decoded_content}"

    def _consume_stream_event(
        self, event: Dict[str, Any], transcript: List[Dict[str, Any]], label: Optional[str]
    ) -> str:
        """Process one `--output-format stream-json` event. Returns result text if any."""
        etype = event.get("type")
        if etype == "assistant":
            blocks = (event.get("message") or {}).get("content") or []
            text_parts: List[str] = []
            tools: List[Dict[str, Any]] = []
            thinking: List[str] = []
            for block in blocks:
                bt = block.get("type")
                if bt == "thinking":
                    thinking.append(block.get("thinking", ""))
                    if self.stream_live:
                        _print_stream_block("thinking", block.get("thinking", ""), label)
                elif bt == "text":
                    text_parts.append(block.get("text", ""))
                    if self.stream_live:
                        _print_stream_block("text", block.get("text", ""), label)
                elif bt == "tool_use":
                    call = {"name": block.get("name", "tool"), "input": block.get("input") or {}}
                    tools.append(call)
                    if self.stream_live:
                        _print_stream_block("tool", call, label)
            rec: Dict[str, Any] = {"type": "assistant"}
            if text_parts:
                rec["text"] = "".join(text_parts)
            if thinking:
                rec["thinking"] = "\n".join(thinking)
            if tools:
                rec["tools"] = tools
            transcript.append(rec)
            return ""
        if etype == "result":
            subtype = event.get("subtype")
            transcript.append({"type": "result", "subtype": subtype})
            if self.stream_live:
                _print_stream_block("result", subtype, label)
            return event.get("result") or ""
        return ""

    async def _run_cli_agent(
        self,
        *,
        system_prompt: str,
        prompt: str,
        working_directory: Optional[str] = None,
        label: Optional[str] = None,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Run one `claude` CLI agent to completion, streaming stream-json.

        Each call is its own subprocess — one member of the swarm. Returns the
        agent's final result text and a transcript of its thinking/tools.
        """
        cmd = [
            CLAUDE_CLI, "-p",
            "--output-format", "stream-json",
            "--verbose",
            "--model", self.model,
            "--append-system-prompt", system_prompt,
            "--dangerously-skip-permissions",
            "--disallowedTools", ",".join(DISALLOWED_TOOLS),
        ]
        # Bound per-agent spend when configured (the CLI no longer takes --max-turns).
        budget = os.environ.get("REVIEW_AGENT_BUDGET_USD")
        if budget:
            cmd += ["--max-budget-usd", budget]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=working_directory or str(REPO_ROOT),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Large prompts (the diff + EIP context) go via stdin to avoid ARG_MAX.
        proc.stdin.write(prompt.encode("utf-8"))
        await proc.stdin.drain()
        proc.stdin.close()

        transcript: List[Dict[str, Any]] = [{"type": "prompt", "label": label}]
        final_text = ""
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            text = self._consume_stream_event(event, transcript, label)
            if text:
                final_text = text

        await proc.wait()
        if not final_text:
            # No terminal result (e.g. turn limit) — fall back to assistant text.
            final_text = " ".join(
                r.get("text", "") for r in transcript
                if r.get("type") == "assistant" and r.get("text")
            ).strip()
        if not final_text and proc.returncode not in (0, None):
            err = (await proc.stderr.read()).decode("utf-8", "replace").strip()
            transcript.append({"type": "error", "returncode": proc.returncode, "stderr": err[:2000]})
            print(f"::warning::[{label or 'agent'}] claude CLI exited {proc.returncode}: {err[:500]}")
        return final_text.strip(), transcript

    def analyze_security(
        self,
        code_changes: str,
        repo_name: Optional[str] = None,
        agent_file_path: Optional[str] = None,
        branch_name: Optional[str] = None,
        hardfork_name: Optional[str] = None,
        baseline_sha: Optional[str] = None,
        head_sha: Optional[str] = None,
        working_directory: Optional[str] = None,
        strict_specs: bool = False,
        extra_prompt: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], CostInfo]:
        resolved_repo_name, resolved_agent_file = self._resolve_review_config(
            repo_name=repo_name,
            agent_file_path=agent_file_path,
        )
        agent_instructions = load_agent_instructions(resolved_agent_file)
        if extra_prompt:
            agent_instructions = f"{agent_instructions}\n\n# Additional reviewer instructions\n{extra_prompt}"
        docs_context: ReviewContextResult = build_review_context(
            resolved_agent_file,
            code_changes,
            hardfork_name=hardfork_name,
            strict=strict_specs,
        )

        context_header = (
            f"Repository: {resolved_repo_name or 'unknown'}\n"
            f"Branch: {branch_name or 'unknown'}\n"
            f"Configured hardfork: {hardfork_name or 'not specified'}\n"
            f"Head commit: {head_sha or 'not specified'}\n"
            f"Working directory: {working_directory or 'not provided'}"
        )
        checkout_note = (
            "The FULL repository is checked out at the working directory above. Open and "
            "read the changed files and the surrounding code (Read/Grep/Glob/Bash) and "
            "trace control flow through the real source — do not review from the diff alone."
            if working_directory else
            "The repository is NOT checked out; review from the diff and the EIP specs below. "
            "Do not search the filesystem for source files — they are not present."
        )
        policy = _REVIEW_POLICY
        docs = docs_context.text or ""
        context_block = (
            f"{context_header}\n\n{checkout_note}\n\n{policy}\n\n{docs}\n\n# Code Changes\n\n{code_changes}"
        )
        # Verifier/synthesis read files directly, so they get the policy + context
        # without the full diff (which would just bloat every call).
        context_brief = f"{context_header}\n\n{checkout_note}\n\n{policy}\n\n{docs}"

        result = asyncio.run(self._run_audit_pipeline(
            system_prompt=agent_instructions,
            context_block=context_block,
            context_brief=context_brief,
            working_directory=working_directory,
        ))
        transcript = result.pop("_transcript", [])
        swarm_stats = result.pop("_stats", {})

        reasoning_log = {
            "repo_name": resolved_repo_name,
            "branch_name": branch_name,
            "agent_file_path": resolved_agent_file,
            "hardfork_name": hardfork_name,
            "baseline_sha": baseline_sha,
            "head_sha": head_sha,
            "working_directory": working_directory,
            "transcript": transcript,
            "swarm_stats": swarm_stats,
            "analysed_files": parse_changed_file_ranges(code_changes),
            "selected_docs": docs_context.selected_docs,
            "docs_scope": docs_context.scope_description,
            "spec_manifest": docs_context.manifest,
        }
        if docs_context.text:
            reasoning_log["docs_context"] = docs_context.text

        result["_reasoning_log"] = reasoning_log

        return result, CostInfo(
            total_cost=0.0,
            input_tokens=0,
            output_tokens=0,
            model=self.model,
            provider="claude-cli-swarm",
            metadata={"reasoning_log": reasoning_log},
        )

    async def _run_audit_pipeline(
        self,
        *,
        system_prompt: str,
        context_block: str,
        context_brief: str,
        working_directory: Optional[str],
    ) -> Dict[str, Any]:
        """Swarm: parallel finders -> per-candidate verifier -> synthesis."""
        transcript: List[Dict[str, Any]] = []

        def note(msg: str) -> None:
            if self.stream_live:
                print("  " + _c("1;35", "swarm: ") + msg, file=sys.stderr, flush=True)

        # 1) Finders run in parallel, each with a single narrow mandate.
        async def run_finder(spec: Dict[str, str]) -> List[Dict[str, Any]]:
            prompt = (
                f"{context_block}\n\n## YOUR TASK — {spec['label']} finder\n{spec['focus']}\n\n"
                f"Enumerate EVERY candidate of this kind across the changed files. Be "
                f"exhaustive; do not verify in depth yet — a later pass verifies each. "
                f"Output ONLY this JSON (no prose, no code fences):\n{_CANDIDATE_SCHEMA}\n"
                f'If there are none, output {{"candidates":[]}}.'
            )
            text, tr = await self._run_cli_agent(
                system_prompt=system_prompt, prompt=prompt,
                working_directory=working_directory, label=spec["label"],
            )
            transcript.extend(tr)
            obj = _json_object(text) or {}
            out = []
            for c in (obj.get("candidates") or []):
                if isinstance(c, dict):
                    c["finder"] = spec["label"]
                    out.append(c)
            return out

        finder_results = await asyncio.gather(
            *[run_finder(s) for s in FINDER_SPECS], return_exceptions=True
        )
        candidates: List[Dict[str, Any]] = []
        for r in finder_results:
            if isinstance(r, list):
                candidates.extend(r)
        candidates = _dedupe_candidates(candidates)
        note(f"{len(candidates)} candidate(s) from {len(FINDER_SPECS)} finders")

        # 2) Verify each candidate independently (parallel, bounded).
        MAX_VERIFY = 24
        to_verify = candidates[:MAX_VERIFY]
        if len(candidates) > MAX_VERIFY:
            print(f"::warning::swarm: {len(candidates)} candidates; verifying first {MAX_VERIFY}")
        sem = asyncio.Semaphore(4)

        async def verify(cand: Dict[str, Any], index: int) -> Optional[Dict[str, Any]]:
            async with sem:
                prompt = (
                    f"{context_brief}\n\n## YOUR TASK — verifier\n"
                    f"A prior finder flagged this CANDIDATE:\n{json.dumps(cand, ensure_ascii=False)}\n\n"
                    f"Independently VERIFY it against the ACTUAL code — read the files and trace "
                    f"the path. Confirm ONLY if it is a real, reachable defect. For any chain-split/"
                    f"consensus/gas claim, confirm the governing EIP or downgrade to the impact you "
                    f"can prove; reject what you cannot confirm. Output ONLY this JSON:\n{_VERDICT_SCHEMA}"
                )
                text, tr = await self._run_cli_agent(
                    system_prompt=system_prompt, prompt=prompt,
                    working_directory=working_directory, label=f"verify#{index + 1}",
                )
                transcript.extend(tr)
                return _json_object(text)

        verdicts = await asyncio.gather(
            *[verify(c, i) for i, c in enumerate(to_verify)], return_exceptions=True
        )
        confirmed: List[Dict[str, Any]] = []
        for v in verdicts:
            if isinstance(v, dict) and v.get("confirmed"):
                v.pop("confirmed", None)
                v.pop("reason", None)
                confirmed.append(v)
        confirmed = _dedupe_candidates(confirmed)
        note(f"{len(confirmed)} confirmed finding(s)")

        # 3) Synthesis writes the prose; findings come straight from the verdicts.
        findings_brief = [
            {k: f.get(k) for k in ("severity", "title", "location", "description")}
            for f in confirmed
        ]
        synth_prompt = (
            f"{context_brief}\n\n## YOUR TASK — synthesis\n"
            f"These findings were independently verified and confirmed:\n"
            f"{json.dumps(findings_brief, ensure_ascii=False)}\n\n"
            f"Write the review's prose for a maintainer (Markdown, backtick code identifiers). "
            f"Output ONLY this JSON:\n{_SYNTHESIS_SCHEMA}"
        )
        synth_text, synth_tr = await self._run_cli_agent(
            system_prompt=system_prompt, prompt=synth_prompt,
            working_directory=working_directory, label="synthesis",
        )
        transcript.extend(synth_tr)
        synth = _json_object(synth_text) or {}

        default_summary = (
            f"{len(confirmed)} issue(s) found and verified." if confirmed
            else "No vulnerabilities identified in the changed code."
        )
        return {
            "has_vulnerabilities": bool(confirmed),
            "summary": (synth.get("summary") or "").strip() or default_summary,
            "analysis": (synth.get("analysis") or "").strip(),
            "spec_compliance": (synth.get("spec_compliance") or "").strip(),
            "findings": confirmed,
            "_transcript": transcript,
            "_stats": {
                "candidates": len(candidates),
                "verified": len(to_verify),
                "confirmed": len(confirmed),
            },
        }

    def analyze_commit(
        self,
        repo_name: str,
        commit_sha: str,
        branch: str = None,
        hardfork_name: Optional[str] = None,
        strict_specs: bool = False,
        extra_prompt: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], CostInfo]:
        if not self.github:
            raise ValueError("GitHub client not initialized")

        monitor = CommitMonitor(self.github_token)
        commit_changes = monitor.get_commit_changes(repo_name, commit_sha)
        if not commit_changes:
            raise ValueError(f"Could not retrieve commit {commit_sha} from {repo_name}")

        return self.analyze_security(
            commit_changes,
            repo_name=repo_name,
            branch_name=branch,
            head_sha=commit_sha,
            hardfork_name=hardfork_name,
            strict_specs=strict_specs,
            extra_prompt=extra_prompt,
        )

    def create_report_comment(
        self,
        pr: PullRequest,
        analysis: Dict[str, Any],
        cost_info: CostInfo = None,
        header: Optional[Dict[str, Any]] = None,
        detail: str = "summary",
    ) -> None:
        # GitHub renders Markdown in comments, so post the same polished report
        # used for the job summary (PR link, fork-aware repo, code blocks, etc.).
        from .report import build_review_report

        pr.create_issue_comment(
            build_review_report(analysis, cost_info, header=header, detail=detail)
        )

    def create_commit_issue(self, repo_name: str, commit_info: CommitInfo, analysis: Dict[str, Any], cost_info: CostInfo = None) -> None:
        if not self.github:
            raise ValueError("GitHub client not initialized")

        repo = self.github.get_repo(repo_name)
        title = f"Security Alert: Potential vulnerabilities in commit {commit_info.sha[:7]}"
        body = f"""## Security Review for Commit

**Commit:** [{commit_info.sha[:7]}]({commit_info.url})
**Branch:** {commit_info.branch}
**Author:** {commit_info.author}
**Date:** {commit_info.date}
**Message:** {commit_info.message}

**Detected Security Issues:** {'Yes' if analysis['has_vulnerabilities'] else 'No'}

### Summary
{analysis['summary']}
"""

        if analysis["findings"]:
            body += "\n### Detailed Findings\n"
            for finding in analysis["findings"]:
                body += f"""
#### {finding['severity']} Severity Issue
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}
"""

        labels = ["security"]
        if analysis["has_vulnerabilities"]:
            labels.append("vulnerability")

        repo.create_issue(title=title, body=body, labels=labels)
