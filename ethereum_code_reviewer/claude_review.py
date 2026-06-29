"""
Claude Agent SDK-backed security review implementation.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
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

try:
    from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
except ImportError:
    ClaudeSDKClient = None
    ClaudeAgentOptions = None


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


def _print_stream_block(kind: str, payload: Any) -> None:
    """Print one streamed event to stderr (flushed, colorized for live CI)."""
    if kind == "thinking":
        if not (payload or "").strip():
            return  # skip empty/redacted thinking blocks
        # Thinking is the reasoning the user wants to watch — give it room and
        # keep its paragraph breaks (indented) rather than clipping to one line.
        body = "\n".join("  " + ln for ln in payload.strip().splitlines())
        line = _c("2", "  thinking:\n" + body)
    elif kind == "text":
        # Don't echo the final JSON answer — it's noise in the log (and may carry
        # fields we don't surface, like a volunteered confidence score). It is
        # rendered, cleaned, in the report.
        stripped = (payload or "").strip()
        if not stripped or _looks_like_json_review(stripped) or stripped.startswith("{"):
            return
        line = _c("36", "  reasoning: ") + _paint_signals(_oneline(payload, 300))
    elif kind == "tool":
        name = payload.get("name", "tool")
        color = _TOOL_COLORS.get(name, "1;37")
        line = _c(color, f"  {name}") + "  " + _c("2", _oneline(_tool_summary(payload.get("input") or {}), 240))
    elif kind == "result":
        # Don't echo the result body — it just repeats the last assistant text.
        subtype = payload
        ok = subtype in (None, "success")
        line = _c("1;32" if ok else "1;31",
                  "  review complete" if ok else f"  ended: {subtype}")
    else:
        return
    print(line, file=sys.stderr, flush=True)


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
        self.max_turns = provider_kwargs.get(
            "max_turns", int(os.environ.get("REVIEW_MAX_TURNS", "40"))
        )
        self.max_thinking_tokens = provider_kwargs.get("max_thinking_tokens", 12000)
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

    async def _run_claude_review(
        self,
        system_prompt: str,
        user_prompt: str,
        working_directory: Optional[str] = None,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        if ClaudeSDKClient is None or ClaudeAgentOptions is None:
            raise RuntimeError(
                "claude-agent-sdk is not installed. Install the Python package and the @anthropic-ai/claude-code CLI."
            )

        transcript: List[Dict[str, Any]] = [{"type": "user_prompt", "text": user_prompt}]

        async with ClaudeSDKClient(
            options=ClaudeAgentOptions(
                system_prompt=system_prompt,
                model=self.model,
                max_turns=self.max_turns,
                max_thinking_tokens=self.max_thinking_tokens,
                # Surface the model's reasoning: "summarized" returns visible
                # thinking text. Without this, thinking blocks come back omitted
                # (empty) and the live "thinking:" lines are blank.
                thinking={
                    "type": "enabled",
                    "budget_tokens": self.max_thinking_tokens,
                    "display": "summarized",
                },
                cwd=working_directory or str(REPO_ROOT),
                disallowed_tools=DISALLOWED_TOOLS,
            )
        ) as client:

            async def collect_response() -> str:
                """Drain one query's messages, recording the transcript.

                Returns the final result text (the SDK's terminal result, or the
                concatenated assistant text if no explicit result was emitted —
                e.g. when the turn limit is hit mid-exploration).
                """
                result = ""
                fragments: List[str] = []
                async for message in client.receive_response():
                    serialized = {"type": type(message).__name__}

                    if hasattr(message, "content"):
                        text_blocks: List[str] = []
                        tool_calls: List[Dict[str, Any]] = []
                        thinking: List[str] = []
                        for block in message.content:
                            # Print each block live, in order, as it streams in.
                            if hasattr(block, "thinking"):
                                thinking.append(block.thinking)
                                if self.stream_live:
                                    _print_stream_block("thinking", block.thinking)
                            elif hasattr(block, "text"):
                                text_blocks.append(block.text)
                                if self.stream_live:
                                    _print_stream_block("text", block.text)
                            elif hasattr(block, "name") and hasattr(block, "input"):
                                call = {"name": block.name, "input": block.input}
                                tool_calls.append(call)
                                if self.stream_live:
                                    _print_stream_block("tool", call)
                        if text_blocks:
                            serialized["text"] = "".join(text_blocks)
                            fragments.append(serialized["text"])
                        if thinking:
                            serialized["thinking"] = "\n".join(thinking)
                        if tool_calls:
                            serialized["tools"] = tool_calls

                    if hasattr(message, "result"):
                        serialized["result"] = message.result
                        result = message.result or result
                        if self.stream_live:
                            _print_stream_block("result", getattr(message, "subtype", None))

                    if hasattr(message, "subtype"):
                        serialized["subtype"] = message.subtype
                    if hasattr(message, "session_id"):
                        serialized["session_id"] = message.session_id
                    if hasattr(message, "total_cost_usd"):
                        serialized["total_cost_usd"] = message.total_cost_usd
                    if hasattr(message, "duration_ms"):
                        serialized["duration_ms"] = message.duration_ms

                    transcript.append(serialized)

                if not result and fragments:
                    result = "".join(fragments)
                return result

            await client.query(user_prompt)
            final_result = await collect_response()

            # The model sometimes ends a turn on prose (a preamble like "I'll
            # examine the code…") without ever emitting the JSON review — often
            # because it spent its turns exploring. Ask once more for JSON only.
            if not _looks_like_json_review(final_result):
                transcript.append({"type": "retry", "reason": "no_json_in_response"})
                await client.query(
                    "Stop. Do not use any tools. Output ONLY the JSON review object "
                    "described earlier — no prose, no markdown fences — starting with "
                    "'{' and nothing else."
                )
                retry_result = await collect_response()
                if _looks_like_json_review(retry_result) or not final_result:
                    final_result = retry_result

        return (final_result or "").strip(), transcript

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

        user_prompt = f"""Review the following changed code for concrete security vulnerabilities.

Repository: {resolved_repo_name or "unknown"}
Branch: {branch_name or "unknown"}
Selected agent file: {resolved_agent_file}
Review working directory: {working_directory or "not provided"}
Configured hardfork: {hardfork_name or "not specified"}
Starting commit: {baseline_sha or "latest commit only"}
Head commit: {head_sha or "not specified"}

{(
    "The FULL repository is checked out at the review working directory above. "
    "Do NOT review from the diff alone. Open and read the changed files in full, "
    "read the surrounding code, and trace each changed function to its callers and "
    "callees (use Read/Grep/Glob) so you understand the real control flow and "
    "invariants. Verify the change against the actual codebase and the EIP specs "
    "below before reaching a verdict."
  ) if working_directory else (
    "The repository is NOT checked out; review from the diff and the EIP specs below. "
    "Do not waste turns searching the filesystem for source files — they are not present."
  )}

You must validate whether the changed implementation matches the relevant EIPs/specification for the configured hardfork when one is provided. Flag deviations, missing required behavior, or security-sensitive mismatches with the hardfork spec.

Base every claim on the actual code you read, not the diff alone. Your verdict
must be backed by reasoning a maintainer can follow and check.

Write all prose fields in GitHub-flavored Markdown. ALWAYS wrap code identifiers
— function names, type names, variants, fields, paths, e.g. `is_awaiting_event()`,
`DataRequest::WaitingForBlock` — in backticks so they render as inline code. Use
short paragraphs and bullet lists; reference files and line numbers you inspected.

Return ONLY a JSON object with this shape:
{{
  "has_vulnerabilities": <true/false>,
  "summary": "<2-4 sentence verdict: what the change does and why it is or isn't safe>",
  "analysis": "<the core of the review, in Markdown. Explain: (1) what the changed code actually does, (2) the control flow you traced through the real source — the functions, call sites, and invariants you checked and what they guarantee, (3) the security reasoning that leads to your verdict (why each potential failure mode is or isn't reachable). Cite the files/lines you read.>",
  "spec_compliance": "<how the change relates to the relevant EIP(s)/hardfork spec: cite EIP numbers and the specific requirement, and state whether the implementation matches it. Write 'Not spec-relevant' if the change does not touch consensus/spec-governed behavior.>",
  "findings": [
    {{
      "severity": "HIGH|MEDIUM|LOW",
      "description": "<specific vulnerability with exact location>",
      "recommendation": "<precise fix>",
      "detailed_explanation": "<what the issue is>",
      "impact_explanation": "<what can happen>",
      "detailed_recommendation": "<how to fix it>",
      "code_example": "<example patch or code excerpt>",
      "additional_resources": "<optional references>"
    }}
  ]
}}

{docs_context.text if docs_context.text else ""}

# Code Changes

{code_changes}
"""

        raw_output, transcript = asyncio.run(
            self._run_claude_review(
                agent_instructions,
                user_prompt,
                working_directory=working_directory,
            )
        )
        try:
            cleaned_json = _extract_json_from_response(raw_output)
            result = json.loads(cleaned_json)
            result = _validate_response(result)
        except (ValueError, json.JSONDecodeError) as exc:
            # The Claude Code SDK returned something that isn't the expected JSON
            # (often an auth/startup error, a refusal, or prose). Surface it so the
            # failure is diagnosable instead of a bare "Expecting value" traceback.
            snippet = (raw_output or "").strip()
            print(
                "[claude_review] Could not parse a JSON review from the model.\n"
                f"  model: {self.model}\n"
                f"  raw response length: {len(raw_output or '')} chars\n"
                f"  raw response (first 2000 chars): {snippet[:2000] or '<empty>'}",
                file=sys.stderr,
            )
            raise ValueError(
                "Claude did not return a parseable JSON review "
                f"({exc}). See the raw response logged above — an empty/short "
                "response usually means a Claude auth or model error."
            ) from exc

        reasoning_log = {
            "repo_name": resolved_repo_name,
            "branch_name": branch_name,
            "agent_file_path": resolved_agent_file,
            "hardfork_name": hardfork_name,
            "baseline_sha": baseline_sha,
            "head_sha": head_sha,
            "working_directory": working_directory,
            "raw_output": raw_output,
            "transcript": transcript,
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
            provider="claude-agent-sdk",
            metadata={"reasoning_log": reasoning_log},
        )

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
