"""
Main module for PR security review.
"""

import os
import sys
import json
import re
import argparse
import dotenv
import tempfile
from typing import Dict, Optional, Tuple
from .claude_review import SecurityReview, CostInfo
from .local_repo_manager import LocalRepositoryManager
from .spec_context import latest_mainnet_hardfork
from .report import build_review_report, emit_review_report, DETAIL_LEVELS

def parse_pr_url(url: str) -> Tuple[str, int]:
    """
    Parse a GitHub PR URL to extract repository name and PR number.
    
    Args:
        url: GitHub PR URL (e.g., https://github.com/owner/repo/pull/123)
        
    Returns:
        Tuple containing repository full name and PR number
    """
    pattern = r"github\.com/([^/]+/[^/]+)/pull/(\d+)"
    match = re.search(pattern, url)
    if not match:
        raise ValueError("Invalid GitHub PR URL format")
    return match.group(1), int(match.group(2))

def parse_file_url(url: str) -> Tuple[str, str, str]:
    """
    Parse a GitHub file URL to extract repository name, branch, and file path.
    
    Args:
        url: GitHub file URL (e.g., https://github.com/owner/repo/blob/branch/path/to/file.rs)
        
    Returns:
        Tuple containing repository full name, branch name, and file path
    """
    pattern = r"github\.com/([^/]+/[^/]+)/blob/([^/]+)/(.*)"
    match = re.search(pattern, url)
    if not match:
        raise ValueError("Invalid GitHub file URL format")
    return match.group(1), match.group(2), match.group(3)

def run_start_commit_review(args, reviewer: SecurityReview):
    """Build and analyze a cumulative start-commit -> branch-head review target.

    Returns (target, analysis, cost_info). Kept module-level so it is testable
    without driving full argparse.
    """
    if not args.repository:
        raise ValueError("--mode start-commit requires --repository owner/repo")
    if not args.start_commit:
        raise ValueError("--mode start-commit requires --start-commit <sha>")

    repo_url = f"https://github.com/{args.repository}"
    data_dir = os.environ.get("REVIEWER_DATA_DIR") or tempfile.mkdtemp(prefix="reviewer-data-")
    manager = LocalRepositoryManager(reviewer.github_token, data_dir=data_dir)
    target = manager.build_review_target(
        repo_name=args.repository,
        repo_url=repo_url,
        branch_name=args.branch,
        starting_commit_sha=args.start_commit,
        hardfork_name=args.hardfork,
    )
    if target is None:
        raise ValueError(
            f"No changes to review between {args.start_commit} and {args.branch} head"
        )
    analysis, cost_info = reviewer.analyze_security(
        target.combined_changes,
        repo_name=args.repository,
        agent_file_path=args.agent_file,
        branch_name=target.branch_name,
        hardfork_name=target.hardfork_name,
        baseline_sha=target.baseline_sha,
        head_sha=target.head_sha,
        working_directory=target.worktree_path,
        strict_specs=args.strict_specs,
        extra_prompt=args.extra_prompt,
    )
    return target, analysis, cost_info

def main():
    """Main entry point for the security review action."""
    def require_anthropic_key() -> None:
        credential = (
            os.environ.get('CLAUDE_CODE_OAUTH_TOKEN')
            or os.environ.get('ANTHROPIC_API_KEY')
            or os.environ.get('INPUT_ANTHROPIC-API-KEY')
        )
        if not credential:
            raise ValueError(
                "Claude credentials required. Set CLAUDE_CODE_OAUTH_TOKEN "
                "(from `claude setup-token`) or ANTHROPIC_API_KEY."
            )

    def build_provider_kwargs(model: Optional[str]) -> Dict[str, str]:
        resolved_model = model or os.environ.get('CLAUDE_MODEL') or os.environ.get('INPUT_CLAUDE-MODEL')
        return {'model': resolved_model} if resolved_model else {}

    def emit_report(analysis: Dict[str, object], cost_info: Optional[CostInfo],
                    title: Optional[str] = None) -> None:
        """Render the polished report to the Action log and the job summary."""
        emit_review_report(
            build_review_report(analysis, cost_info, title=title, detail=args.detail)
        )

    try:
        dotenv.load_dotenv()

        env_path = os.path.join(os.getcwd(), '.env')
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.strip() and not line.startswith('#') and line.startswith('GITHUB_TOKEN='):
                        token_value = line.split('=', 1)[1].strip()
                        if token_value not in {'your_github_token_here', 'your_actual_token_here'}:
                            os.environ['GITHUB_TOKEN'] = token_value

        parser = argparse.ArgumentParser(description='Analyze PRs, commits, files, or cumulative hardfork ranges for security vulnerabilities')
        parser.add_argument('target', nargs='?', help='PR URL (--mode pr) or commit SHA (--mode commit)')
        parser.add_argument('--mode', choices=['pr', 'commit', 'start-commit'], default='pr',
                            help='Review scope: a PR (default), a single commit, or the cumulative diff from --start-commit to branch head')
        parser.add_argument('--repository', help='owner/repo (required for --mode commit and start-commit)')
        parser.add_argument('--start-commit', help='Baseline commit SHA for --mode start-commit (cumulative review to branch head)')
        parser.add_argument('--branch', default='main', help='Branch to review for --mode start-commit (default: main)')
        parser.add_argument('--hardfork', help='Hardfork name (e.g. fusaka) to scope EIP context')
        parser.add_argument('--file', help='GitHub file URL to analyze (e.g., https://github.com/owner/repo/blob/branch/path/to/file.rs)')
        parser.add_argument('--agent-file', help='Relative path under ./agents to AGENT.md or AGENTS.md when overriding repository config')
        parser.add_argument('--extra-prompt', help='Extra reviewer instructions appended to the agent file prompt')
        parser.add_argument('--strict-specs', action='store_true', help="Fail if the hardfork's expected EIPs could not all be fetched")
        parser.add_argument('--github-token', help='GitHub token', default=os.environ.get('GITHUB_TOKEN'))
        parser.add_argument('--anthropic-api-key', help='Anthropic API key', default=os.environ.get('ANTHROPIC_API_KEY'))
        parser.add_argument('--model', help='Claude model to use (defaults to CLAUDE_MODEL)')
        parser.add_argument('--post-comment', help='Post analysis as a comment on the PR', action='store_true')
        parser.add_argument('--detail', choices=DETAIL_LEVELS,
                            default=os.environ.get('INPUT_DETAIL') or 'summary',
                            help='How much of the agent\'s activity to render in the report (default: summary)')
        parser.add_argument('--input-text', help='Analyze text input directly and output JSON result', action='store_true')

        args = parser.parse_args()

        if args.github_token:
            os.environ['GITHUB_TOKEN'] = args.github_token
            os.environ['INPUT_GITHUB-TOKEN'] = args.github_token
        if args.anthropic_api_key:
            os.environ['ANTHROPIC_API_KEY'] = args.anthropic_api_key
            os.environ['INPUT_ANTHROPIC-API-KEY'] = args.anthropic_api_key
        if args.model:
            os.environ['CLAUDE_MODEL'] = args.model
            os.environ['INPUT_CLAUDE-MODEL'] = args.model

        if args.input_text:
            require_anthropic_key()
            print("Enter the code to analyze (press Ctrl+D when done):", file=sys.stderr)
            text_input = sys.stdin.read()
            if not text_input.strip():
                raise ValueError("No input provided")
            reviewer = SecurityReview(
                provider_kwargs=build_provider_kwargs(args.model),
                agent_file_path=args.agent_file
            )
            analysis, cost_info = reviewer.analyze_security(
                text_input, agent_file_path=args.agent_file, extra_prompt=args.extra_prompt
            )
            output = {
                "confidence_score": analysis['confidence_score'],
                "has_vulnerabilities": analysis['has_vulnerabilities'],
                "summary": analysis['summary'],
                "findings": analysis['findings'],
            }
            if cost_info and cost_info.total_cost > 0:
                output["cost_info"] = {
                    "total_cost": cost_info.total_cost,
                    "input_tokens": cost_info.input_tokens,
                    "output_tokens": cost_info.output_tokens,
                    "model": cost_info.model,
                    "provider": cost_info.provider,
                }
            print(json.dumps(output, indent=2))
            return

        event_path = os.environ.get('GITHUB_EVENT_PATH')
        reviewer = SecurityReview(
            provider_kwargs=build_provider_kwargs(args.model),
            agent_file_path=args.agent_file
        )

        # Treat blank / "none" / "null" (common workflow-input sentinels) as
        # "no hardfork requested" so the mainnet default below applies.
        if args.hardfork and args.hardfork.strip().lower() in {"", "none", "null"}:
            args.hardfork = None

        # When no hardfork is requested, scope the review to whatever is live on
        # mainnet today (e.g. Fusaka) rather than leaving it unscoped or picking
        # an upcoming fork. File/text-only modes don't use hardfork context.
        if not args.hardfork and not args.file and not args.input_text:
            default_fork = latest_mainnet_hardfork()
            if default_fork:
                args.hardfork = default_fork
                print(f"\nNo hardfork specified; defaulting to latest mainnet fork: {default_fork}")
            else:
                print("\nNo hardfork specified and latest mainnet fork could not be determined; "
                      "proceeding without hardfork spec context.")

        if event_path and args.mode == 'pr' and not args.target:
            require_anthropic_key()
            with open(event_path, 'r') as f:
                event = json.load(f)
            if 'pull_request' not in event:
                raise ValueError(
                    "GITHUB_EVENT_PATH is not a pull_request event. For manual runs pass a "
                    "PR URL/number as the target, or leave it empty with --repository to review the latest open PR."
                )
            repo_name = event['repository']['full_name']
            pr = reviewer.get_pr(repo_name, event['pull_request']['number'])
            changes = reviewer.get_pr_review_input(pr)
            analysis, cost_info = reviewer.analyze_security(
                changes, repo_name=repo_name, agent_file_path=args.agent_file,
                hardfork_name=args.hardfork, strict_specs=args.strict_specs, extra_prompt=args.extra_prompt,
            )
            emit_report(analysis, cost_info, title=f"PR #{pr.number}: {pr.title or ''}".strip())
            if analysis['has_vulnerabilities']:
                reviewer.create_report_comment(pr, analysis, cost_info)
                print(f"::warning::Security vulnerabilities detected with {analysis['confidence_score']}% confidence")
            else:
                print("::notice::No security vulnerabilities detected")
            return

        require_anthropic_key()

        def emit_status(analysis: Dict[str, object]) -> None:
            if analysis['has_vulnerabilities']:
                print(f"::warning::Security vulnerabilities detected with {analysis['confidence_score']}% confidence")
            else:
                print("::notice::No security vulnerabilities detected")

        if args.file:
            repo_name, branch, file_path = parse_file_url(args.file)
            print(f"\nAnalyzing file: {file_path}")
            print(f"Repository: {repo_name}")
            print(f"Branch: {branch}")
            changes = reviewer.get_file_content(repo_name, branch, file_path)
            analysis, cost_info = reviewer.analyze_security(
                changes, repo_name=repo_name, agent_file_path=args.agent_file,
                strict_specs=args.strict_specs, extra_prompt=args.extra_prompt,
            )
            emit_report(analysis, cost_info, title=f"File: {file_path}")
            emit_status(analysis)
            return

        if args.mode == 'commit':
            if not args.repository:
                raise ValueError("--mode commit requires --repository owner/repo")
            commit_sha = args.target
            if not commit_sha:
                commit_sha = reviewer.get_latest_commit_sha(args.repository, args.branch)
                print(f"\nNo commit given; using latest commit on "
                      f"{args.branch or 'the default branch'}: {commit_sha[:7]}")
            print(f"\nAnalyzing commit {commit_sha[:7]} in {args.repository}")
            analysis, cost_info = reviewer.analyze_commit(
                args.repository, commit_sha, branch=args.branch,
                hardfork_name=args.hardfork, strict_specs=args.strict_specs, extra_prompt=args.extra_prompt,
            )
            emit_report(analysis, cost_info, title=f"Commit {commit_sha[:7]} in {args.repository}")
            emit_status(analysis)
            return

        if args.mode == 'start-commit':
            target, analysis, cost_info = run_start_commit_review(args, reviewer)
            print(f"\nReviewed {args.repository}@{args.branch}: "
                  f"{args.start_commit[:7]}..{target.head_sha[:7]} ({len(target.scoped_commit_infos)} commit(s))")
            emit_report(analysis, cost_info,
                        title=f"{args.repository}@{args.branch}: {args.start_commit[:7]}..{target.head_sha[:7]}")
            emit_status(analysis)
            return

        # default: --mode pr
        if args.target:
            if args.target.isdigit():
                if not args.repository:
                    raise ValueError("A PR number needs --repository owner/repo (or pass a full PR URL)")
                repo_name, pr_number = args.repository, int(args.target)
            else:
                repo_name, pr_number = parse_pr_url(args.target)
            pr = reviewer.get_pr(repo_name, pr_number)
        else:
            if not args.repository:
                raise ValueError("Provide a PR URL/number, or --repository to review the latest open PR")
            repo_name = args.repository
            pr = reviewer.get_latest_open_pr(repo_name)
            if pr is None:
                raise ValueError(f"No open pull requests found in {repo_name}")
            print(f"\nNo PR given; using the latest open PR #{pr.number}")
        print(f"\nAnalyzing PR #{pr.number}")
        print(f"Repository: {repo_name}")
        changes = reviewer.get_pr_review_input(pr)
        analysis, cost_info = reviewer.analyze_security(
            changes, repo_name=repo_name, agent_file_path=args.agent_file,
            hardfork_name=args.hardfork, strict_specs=args.strict_specs, extra_prompt=args.extra_prompt,
        )
        emit_report(analysis, cost_info, title=f"PR #{pr.number}: {pr.title or ''}".strip())
        if args.post_comment and analysis['has_vulnerabilities']:
            reviewer.create_report_comment(pr, analysis, cost_info)
        emit_status(analysis)
        return

    except ValueError as e:
        print(f"::error::{str(e)}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("::error::Operation cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"::error::Action failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
