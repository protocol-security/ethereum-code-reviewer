"""Human-facing review report rendering.

Turns the structured analysis (and its attached ``_reasoning_log``) into a
polished Markdown report so a reviewer can see, at a glance: the verdict, which
files and lines were in scope, the spec context that was loaded, the agent's
thought process, and the findings — plus the raw JSON for the record.

The same Markdown is printed to the Action log and written to the GitHub job
summary (``$GITHUB_STEP_SUMMARY``).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_BADGE = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}

# How much of the agent's activity to render. "summary" keeps it tight;
# "full" includes every reasoning turn and tool call.
DETAIL_LEVELS = ("summary", "full")


def _format_ranges(ranges: List[Tuple[int, int]]) -> str:
    parts = [f"L{s}" if s == e else f"L{s}–{e}" for s, e in ranges]
    return ", ".join(parts)


def _files_section(analysed_files: List[Dict[str, Any]]) -> List[str]:
    if not analysed_files:
        return ["## 🔍 Files analysed", "", "_No changed files with line ranges were detected._", ""]
    lines = ["## 🔍 Files analysed", ""]
    for entry in analysed_files:
        ranges = [tuple(r) for r in entry.get("ranges", [])]
        suffix = f" — {_format_ranges(ranges)}" if ranges else ""
        lines.append(f"- `{entry['file']}`{suffix}")
    lines.append("")
    return lines


def _tool_summary(tool: Dict[str, Any]) -> str:
    name = tool.get("name", "tool")
    args = tool.get("input", {}) or {}
    if name == "Read" and args.get("file_path"):
        loc = args["file_path"]
        offset, limit = args.get("offset"), args.get("limit")
        if offset and limit:
            loc += f" (L{offset}–{int(offset) + int(limit) - 1})"
        elif offset:
            loc += f" (from L{offset})"
        return f"📄 Read `{loc}`"
    if name in {"Grep", "Glob"} and (args.get("pattern") or args.get("query")):
        return f"🔎 {name} `{args.get('pattern') or args.get('query')}`"
    if name == "Bash" and args.get("command"):
        cmd = str(args["command"]).splitlines()[0]
        return f"💻 Bash `{cmd[:80]}`"
    return f"🔧 {name}"


def _process_section(transcript: List[Dict[str, Any]], detail: str) -> List[str]:
    steps: List[str] = []
    for entry in transcript:
        for tool in entry.get("tools", []) or []:
            steps.append(_tool_summary(tool))
        if detail == "full":
            thinking = (entry.get("thinking") or "").strip()
            if thinking:
                steps.append(f"💭 {thinking}")
            text = (entry.get("text") or "").strip()
            if text:
                steps.append(f"🗣️ {text}")
    if not steps:
        return []
    lines = ["## 🧠 Review process", ""]
    lines.extend(f"{i}. {step}" for i, step in enumerate(steps, 1))
    lines.append("")
    return lines


def _findings_section(findings: List[Dict[str, Any]]) -> List[str]:
    if not findings:
        return []
    lines = ["## 🚨 Findings", ""]
    for finding in findings:
        severity = finding.get("severity", "?")
        badge = SEVERITY_BADGE.get(severity, "⚪")
        lines.append(f"### {badge} {severity} — {finding.get('description', '(no description)')}")
        if finding.get("confidence") is not None:
            lines.append(f"*Confidence: {finding['confidence']}%*")
        lines.append("")
        if finding.get("detailed_explanation"):
            lines += ["**What it is**", "", finding["detailed_explanation"], ""]
        if finding.get("impact_explanation"):
            lines += ["**Impact**", "", finding["impact_explanation"], ""]
        recommendation = finding.get("detailed_recommendation") or finding.get("recommendation")
        if recommendation:
            lines += ["**Recommendation**", "", recommendation, ""]
        if finding.get("code_example"):
            lines += ["```", finding["code_example"], "```", ""]
        if finding.get("additional_resources"):
            lines += [f"_References: {finding['additional_resources']}_", ""]
    return lines


def _spec_section(log: Dict[str, Any]) -> List[str]:
    manifest = log.get("spec_manifest") or {}
    if not manifest:
        return []
    fetched = manifest.get("fetched_eips") or []
    parts = [f"**Scope:** `{log.get('docs_scope', 'n/a')}`"]
    if manifest.get("hardfork"):
        meta = manifest.get("meta_eip")
        parts.append(f"**Hardfork:** {manifest['hardfork']}" + (f" (meta EIP-{meta})" if meta else ""))
    if fetched:
        parts.append("**EIPs loaded:** " + ", ".join(f"EIP-{n}" for n in fetched))
    missing = manifest.get("missing_eips") or []
    if missing:
        parts.append("**⚠️ Missing EIPs:** " + ", ".join(f"EIP-{n}" for n in missing))
    return ["## 📚 Spec context", "", "  \n".join(parts), ""]


def build_review_report(
    analysis: Dict[str, Any],
    cost_info: Optional[Any] = None,
    *,
    title: Optional[str] = None,
    detail: str = "summary",
) -> str:
    """Render the analysis into a Markdown report."""
    detail = detail if detail in DETAIL_LEVELS else "summary"
    log: Dict[str, Any] = analysis.get("_reasoning_log") or {}

    has_vulns = analysis.get("has_vulnerabilities")
    findings = analysis.get("findings") or []
    if has_vulns:
        verdict = f"⚠️ **{len(findings)} potential issue(s) found** ({analysis.get('confidence_score', 0)}% confidence)"
    else:
        verdict = "✅ **No vulnerabilities detected**"

    lines: List[str] = ["# 🛡️ Ethereum Code Review", ""]
    if title:
        lines += [f"### {title}", ""]

    meta_bits = [verdict]
    if log.get("repo_name"):
        meta_bits.append(f"**Repository:** {log['repo_name']}")
    if log.get("branch_name"):
        meta_bits.append(f"**Branch:** {log['branch_name']}")
    model = getattr(cost_info, "model", None)
    if model:
        meta_bits.append(f"**Model:** {model}")
    lines += ["  \n".join(meta_bits), ""]

    summary = (analysis.get("summary") or "").strip()
    lines += ["## 📋 Summary", "", summary or "_No summary provided._", ""]

    lines += _files_section(log.get("analysed_files") or [])
    lines += _spec_section(log)
    lines += _process_section(log.get("transcript") or [], detail)
    lines += _findings_section(findings)

    raw = (log.get("raw_output") or "").strip()
    if raw:
        lines += [
            "<details><summary>Raw JSON review</summary>", "",
            "```json", raw, "```", "", "</details>", "",
        ]

    return "\n".join(lines).rstrip() + "\n"


def emit_review_report(report: str) -> None:
    """Print the report to stdout and append it to the GitHub job summary."""
    print(report)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as handle:
                handle.write(report + "\n")
        except OSError as exc:  # don't fail the review over a summary write
            print(f"::warning::Could not write job summary: {exc}")
