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

    def print_analysis(analysis: Dict[str, object], cost_info: Optional[CostInfo]) -> None:
        if analysis['confidence_score'] == 0:
            print("\n⚠️ Analysis failed or returned unexpected results.")
            return
        if analysis['has_vulnerabilities']:
            print("\n🛡️ Security Review Report")
            print("Vulnerabilities Detected: Yes")
            print(f"\nSummary:\n{analysis['summary']}")
            if cost_info and cost_info.total_cost > 0:
                print(f"\nCost Information: {cost_info}")
            if analysis['findings']:
                print("\nDetailed Findings:")
                for finding in analysis['findings']:
                    print(f"\n{finding['severity']} Severity Issue")
                    print(f"Description: {finding['description']}")
                    print(f"Recommendation: {finding['recommendation']}")
                    print(f"Confidence: {finding['confidence']}%")
        else:
            print("\n✅ No security vulnerabilities detected in the changed code.")

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

        if event_path:
            require_anthropic_key()
            with open(event_path, 'r') as f:
                event = json.load(f)
            repo_name = event['repository']['full_name']
            repo = reviewer.github.get_repo(repo_name)
            pr = repo.get_pull(event['pull_request']['number'])
            changes = reviewer.get_pr_changes(pr)
            analysis, cost_info = reviewer.analyze_security(
                changes, repo_name=repo_name, agent_file_path=args.agent_file,
                hardfork_name=args.hardfork, strict_specs=args.strict_specs, extra_prompt=args.extra_prompt,
            )
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
            print_analysis(analysis, cost_info)
            emit_status(analysis)
            return

        if args.mode == 'commit':
            if not (args.repository and args.target):
                raise ValueError("--mode commit requires --repository owner/repo and a commit SHA argument")
            print(f"\nAnalyzing commit {args.target[:7]} in {args.repository}")
            analysis, cost_info = reviewer.analyze_commit(args.repository, args.target, branch=args.branch)
            print_analysis(analysis, cost_info)
            emit_status(analysis)
            return

        if args.mode == 'start-commit':
            target, analysis, cost_info = run_start_commit_review(args, reviewer)
            print(f"\nReviewed {args.repository}@{args.branch}: "
                  f"{args.start_commit[:7]}..{target.head_sha[:7]} ({len(target.scoped_commit_infos)} commit(s))")
            print_analysis(analysis, cost_info)
            emit_status(analysis)
            return

        # default: --mode pr
        if not args.target:
            raise ValueError("Provide a PR URL (--mode pr), a commit SHA (--mode commit), --file, or --input-text")
        repo_name, pr_number = parse_pr_url(args.target)
        print(f"\nAnalyzing PR #{pr_number}")
        print(f"Repository: {repo_name}")
        repo = reviewer.github.get_repo(repo_name)
        pr = repo.get_pull(pr_number)
        changes = reviewer.get_pr_changes(pr)
        analysis, cost_info = reviewer.analyze_security(
            changes, repo_name=repo_name, agent_file_path=args.agent_file,
            hardfork_name=args.hardfork, strict_specs=args.strict_specs, extra_prompt=args.extra_prompt,
        )
        if args.post_comment and analysis['has_vulnerabilities']:
            reviewer.create_report_comment(pr, analysis, cost_info)
        else:
            print_analysis(analysis, cost_info)
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
