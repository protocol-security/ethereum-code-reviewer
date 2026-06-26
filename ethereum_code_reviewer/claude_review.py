"""
Claude Agent SDK-backed security review implementation.
"""

from __future__ import annotations

import asyncio
import json
import os
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


def _validate_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize the review result into the existing app contract."""
    if "has_vulnerabilities" not in response:
        raise ValueError("Response missing 'has_vulnerabilities'")

    response.setdefault("findings", [])
    response.setdefault("summary", "")
    response.setdefault("confidence_score", 0)

    if not response["has_vulnerabilities"]:
        response["confidence_score"] = 100
        response["findings"] = []
        return response

    if response["findings"]:
        response["confidence_score"] = max(
            finding.get("confidence", 50) for finding in response["findings"]
        )

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
        self.max_turns = provider_kwargs.get("max_turns", 4)
        self.max_thinking_tokens = provider_kwargs.get("max_thinking_tokens", 8000)
        self.default_repo_name = repo_name
        self.override_agent_file_path = agent_file_path

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

    def get_pr_changes(self, pr: PullRequest) -> str:
        changes = []
        for file in pr.get_files():
            if file.patch:
                changes.append(f"File: {file.filename}\n{file.patch}\n")
        return "\n".join(changes)

    def get_recent_prs(self, repo_name: str, count: int = 10) -> List[PullRequest]:
        if not self.github:
            raise ValueError("GitHub client not initialized")
        repo = self.github.get_repo(repo_name)
        prs = repo.get_pulls(state="all", sort="created", direction="desc")
        return list(prs[:count])

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
        final_result = ""
        text_fragments: List[str] = []

        async with ClaudeSDKClient(
            options=ClaudeAgentOptions(
                system_prompt=system_prompt,
                model=self.model,
                max_turns=self.max_turns,
                max_thinking_tokens=self.max_thinking_tokens,
                cwd=working_directory or str(REPO_ROOT),
            )
        ) as client:
            await client.query(user_prompt)

            async for message in client.receive_response():
                serialized = {"type": type(message).__name__}

                if hasattr(message, "content"):
                    text_blocks = []
                    for block in message.content:
                        if hasattr(block, "text"):
                            text_blocks.append(block.text)
                    if text_blocks:
                        serialized["text"] = "".join(text_blocks)
                        text_fragments.append(serialized["text"])

                if hasattr(message, "result"):
                    serialized["result"] = message.result
                    final_result = message.result or final_result

                if hasattr(message, "subtype"):
                    serialized["subtype"] = message.subtype
                if hasattr(message, "session_id"):
                    serialized["session_id"] = message.session_id
                if hasattr(message, "total_cost_usd"):
                    serialized["total_cost_usd"] = message.total_cost_usd
                if hasattr(message, "duration_ms"):
                    serialized["duration_ms"] = message.duration_ms

                transcript.append(serialized)

                if not final_result and text_fragments:
                    final_result = "".join(text_fragments)

        if not final_result and text_fragments:
            final_result = "".join(text_fragments)

        return final_result.strip(), transcript

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

You must validate whether the changed implementation matches the relevant EIPs/specification for the configured hardfork when one is provided. Flag deviations, missing required behavior, or security-sensitive mismatches with the hardfork spec.

Return ONLY a JSON object with this shape:
{{
  "confidence_score": <0-100>,
  "has_vulnerabilities": <true/false>,
  "findings": [
    {{
      "severity": "HIGH|MEDIUM|LOW",
      "description": "<specific vulnerability with exact location>",
      "recommendation": "<precise fix>",
      "confidence": <0-100>,
      "detailed_explanation": "<what the issue is>",
      "impact_explanation": "<what can happen>",
      "detailed_recommendation": "<how to fix it>",
      "code_example": "<example patch or code excerpt>",
      "additional_resources": "<optional references>"
    }}
  ],
  "summary": "<brief summary mentioning only concrete vulnerabilities>"
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
        cleaned_json = _extract_json_from_response(raw_output)
        result = json.loads(cleaned_json)
        result = _validate_response(result)

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

    def analyze_commit(self, repo_name: str, commit_sha: str, branch: str = None) -> Tuple[Dict[str, Any], CostInfo]:
        if not self.github:
            raise ValueError("GitHub client not initialized")

        monitor = CommitMonitor(self.github_token)
        commit_changes = monitor.get_commit_changes(repo_name, commit_sha)
        if not commit_changes:
            raise ValueError(f"Could not retrieve commit {commit_sha} from {repo_name}")

        return self.analyze_security(commit_changes, repo_name=repo_name, branch_name=branch, head_sha=commit_sha)

    def create_report_comment(self, pr: PullRequest, analysis: Dict[str, Any], cost_info: CostInfo = None) -> None:
        report = f"""## Security Review

**Confidence Score:** {analysis['confidence_score']}%
**Detected Security Issues:** {'Yes' if analysis['has_vulnerabilities'] else 'No'}

### Summary
{analysis['summary']}

"""

        if analysis["findings"]:
            report += "\n### Detailed Findings\n"
            for finding in analysis["findings"]:
                report += f"""
#### {finding['severity']} Severity Issue
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}
- **Confidence:** {finding['confidence']}%
"""

        pr.create_issue_comment(report)

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

**Confidence Score:** {analysis['confidence_score']}%
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
- **Confidence:** {finding['confidence']}%
"""

        labels = ["security"]
        if analysis["has_vulnerabilities"]:
            labels.append("vulnerability")

        repo.create_issue(title=title, body=body, labels=labels)
