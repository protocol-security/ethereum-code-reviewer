"""
Main module for PR security review.
"""

import os
import sys
import json
import re
import argparse
import hmac
import hashlib
import dotenv
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional, Tuple, Type
from github import Github, Auth
from github.GithubIntegration import GithubIntegration
from .claude_review import SecurityReview, CostInfo, build_storage_metadata
from .commit_monitor import CommitMonitor, MonitoredRepository
from .review_types import BranchReviewTarget, CommitInfo
from .telegram_notifier import TelegramNotifier
from .web_app import SecurityFinderApp
from .queue_listener import QueueListener

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

class GithubWebhookHandler(BaseHTTPRequestHandler):
    """Handler for GitHub webhook events."""
    
    def verify_signature(self, payload_body):
        """Verify that the webhook is from GitHub using the webhook secret."""
        if 'X-Hub-Signature-256' not in self.headers:
            return False
            
        received_sig = self.headers['X-Hub-Signature-256']
        expected_sig = 'sha256=' + hmac.new(
            os.environ.get('GITHUB_WEBHOOK_SECRET', '').encode(),
            payload_body,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(received_sig, expected_sig)
    
    def do_POST(self):
        """Handle POST requests from GitHub webhooks."""
        content_length = int(self.headers.get('Content-Length', 0))
        payload_body = self.rfile.read(content_length)
        
        # Log detailed request information
        print("\n" + "="*60)
        print(f"GitHub Webhook POST Request Received")
        print(f"Time: {self.log_date_time_string()}")
        print(f"Client IP: {self.client_address[0]}")
        print(f"Content-Length: {content_length}")
        
        # Log relevant headers
        github_headers = {
            'X-GitHub-Event': self.headers.get('X-GitHub-Event'),
            'X-GitHub-Delivery': self.headers.get('X-GitHub-Delivery'),
            'X-Hub-Signature-256': self.headers.get('X-Hub-Signature-256', '<not present>'),
            'User-Agent': self.headers.get('User-Agent'),
            'Content-Type': self.headers.get('Content-Type')
        }
        
        print("GitHub Headers:")
        for header, value in github_headers.items():
            if value:
                # Mask signature for security
                if header == 'X-Hub-Signature-256' and value != '<not present>':
                    masked_sig = value[:12] + '...' + value[-8:] if len(value) > 20 else value
                    print(f"  {header}: {masked_sig}")
                else:
                    print(f"  {header}: {value}")
        
        # Log payload size and first part of payload
        print(f"\nPayload size: {len(payload_body)} bytes")
        
        try:
            # Parse and log event payload (with sensitive data masked)
            event = json.loads(payload_body.decode())
            event_type = self.headers.get('X-GitHub-Event')
            
            print(f"Event Type: {event_type}")
            print(f"Event Action: {event.get('action', 'N/A')}")
            
            # Log key event details without sensitive information
            if 'repository' in event:
                repo_info = event['repository']
                print(f"Repository: {repo_info.get('full_name', 'N/A')}")
                print(f"Repository Owner: {repo_info.get('owner', {}).get('login', 'N/A')}")
            
            if 'pull_request' in event:
                pr_info = event['pull_request']
                print(f"PR Number: {pr_info.get('number', 'N/A')}")
                print(f"PR Title: {pr_info.get('title', 'N/A')}")
                print(f"PR Author: {pr_info.get('user', {}).get('login', 'N/A')}")
            
            if 'issue' in event and event.get('issue', {}).get('pull_request'):
                issue_info = event['issue']
                print(f"Issue/PR Number: {issue_info.get('number', 'N/A')}")
                print(f"Issue Title: {issue_info.get('title', 'N/A')}")
            
            if 'comment' in event:
                comment_info = event['comment']
                print(f"Comment Author: {comment_info.get('user', {}).get('login', 'N/A')}")
                comment_body = comment_info.get('body', '')
                # Truncate long comments for logging
                if len(comment_body) > 200:
                    comment_preview = comment_body[:200] + '...'
                else:
                    comment_preview = comment_body
                print(f"Comment Body: {comment_preview}")
            
            if 'installation' in event:
                print(f"Installation ID: {event['installation'].get('id', 'N/A')}")
            
            # Log the full JSON structure (keys only) for debugging
            def get_json_structure(obj, max_depth=2, current_depth=0):
                if current_depth >= max_depth:
                    return "..."
                if isinstance(obj, dict):
                    return {k: get_json_structure(v, max_depth, current_depth + 1) for k, v in obj.items()}
                elif isinstance(obj, list) and obj:
                    return [get_json_structure(obj[0], max_depth, current_depth + 1)] if obj else []
                else:
                    return type(obj).__name__
            
            print(f"\nJSON Structure (first 2 levels):")
            structure = get_json_structure(event)
            print(json.dumps(structure, indent=2))
            
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON payload: {e}")
            print(f"Raw payload (first 500 chars): {payload_body[:500].decode('utf-8', errors='replace')}")
            self.send_response(400)
            self.end_headers()
            return
        except Exception as e:
            print(f"Error processing payload: {e}")
            event = None
            event_type = self.headers.get('X-GitHub-Event')
        
        print("="*60 + "\n")
        
        # Verify webhook signature
        if not self.verify_signature(payload_body):
            print("❌ Webhook signature verification failed")
            self.send_response(401)
            self.end_headers()
            return
        
        print("✅ Webhook signature verified")
        
        if event_type == 'issue_comment':
            print(f"Processing issue_comment event with action: {event.get('action')}")
            # Check if it's a PR comment with the trigger command
            if (event['action'] == 'created' and 
                '/security-review' in event.get('comment', {}).get('body', '') and
                event.get('issue', {}).get('pull_request') is not None):  # Ensure it's a PR comment
                print("🎯 Detected PR comment with /security-review trigger")
                try:
                    # Initialize GitHub App client
                    private_key = os.environ.get('GITHUB_PRIVATE_KEY')
                    if private_key.startswith('-----BEGIN'):
                        # Already in PEM format, don't encode
                        integration = GithubIntegration(
                            os.environ.get('GITHUB_APP_ID'),
                            private_key
                        )
                    else:
                        # Not in PEM format, encode it
                        integration = GithubIntegration(
                            os.environ.get('GITHUB_APP_ID'),
                            private_key.encode()
                        )
                    
                    # Get an access token for the repository
                    installation_id = event['installation']['id']
                    access_token = integration.get_access_token(installation_id).token
                    github_client = Github(auth=Auth.Token(access_token))
                    
                    # Get repository and check if commenter has write access
                    repo = github_client.get_repo(event['repository']['full_name'])
                    commenter = event['comment']['user']['login']
                    collaborator = repo.get_collaborator_permission(commenter)
                    
                    if collaborator not in ['admin', 'write']:
                        print(f"User {commenter} does not have required permissions")
                        self.send_response(403)
                        self.end_headers()
                        return
                    
                    # Get PR number from the issue
                    pr_number = event['issue']['number']
                    
                    # Get repository and PR
                    repo = github_client.get_repo(event['repository']['full_name'])
                    pr = repo.get_pull(pr_number)  # This will work since issues/PRs share numbers
                    
                    provider_kwargs = {}
                    if model := os.environ.get('CLAUDE_MODEL') or os.environ.get('INPUT_CLAUDE-MODEL'):
                        provider_kwargs['model'] = model
                    reviewer = SecurityReview(
                        provider_kwargs=provider_kwargs,
                        repo_name=event['repository']['full_name']
                    )
                    
                    # Get PR changes and analyze
                    changes = reviewer.get_pr_changes(pr)
                    analysis, cost_info = reviewer.analyze_security(
                        changes,
                        repo_name=event['repository']['full_name']
                    )
                    
                    # Post comment with results only if vulnerabilities found
                    if analysis['has_vulnerabilities']:
                        reviewer.create_report_comment(pr, analysis, cost_info)
                    
                    self.send_response(200)
                    self.end_headers()
                    return
                    
                except Exception as e:
                    print(f"Error processing PR: {str(e)}")
                    self.send_response(500)
                    self.end_headers()
                    return
                
        elif event_type == 'pull_request':
            # Process newly opened PRs or when changes are pushed
            if event['action'] in ['opened', 'synchronize']:
                try:
                    # Initialize GitHub App client
                    private_key = os.environ.get('GITHUB_PRIVATE_KEY')
                    if private_key.startswith('-----BEGIN'):
                        # Already in PEM format, don't encode
                        integration = GithubIntegration(
                            os.environ.get('GITHUB_APP_ID'),
                            private_key
                        )
                    else:
                        # Not in PEM format, encode it
                        integration = GithubIntegration(
                            os.environ.get('GITHUB_APP_ID'),
                            private_key.encode()
                        )
                    
                    # Get an access token for the repository
                    installation_id = event['installation']['id']
                    access_token = integration.get_access_token(installation_id).token
                    github_client = Github(auth=Auth.Token(access_token))
                    
                    # Get repository and PR
                    repo = github_client.get_repo(event['repository']['full_name'])
                    pr = repo.get_pull(event['pull_request']['number'])
                    
                    provider_kwargs = {}
                    if model := os.environ.get('CLAUDE_MODEL') or os.environ.get('INPUT_CLAUDE-MODEL'):
                        provider_kwargs['model'] = model
                    reviewer = SecurityReview(
                        provider_kwargs=provider_kwargs,
                        repo_name=event['repository']['full_name']
                    )
                    
                    # Get PR changes and analyze
                    changes = reviewer.get_pr_changes(pr)
                    analysis, cost_info = reviewer.analyze_security(
                        changes,
                        repo_name=event['repository']['full_name']
                    )
                    
                    # Post comment with results only if vulnerabilities found
                    if analysis['has_vulnerabilities']:
                        reviewer.create_report_comment(pr, analysis, cost_info)
                    
                    self.send_response(200)
                    self.end_headers()
                    return
                    
                except Exception as e:
                    print(f"Error processing PR: {str(e)}")
                    self.send_response(500)
                    self.end_headers()
                    return
            
        # Acknowledge other events
        self.send_response(200)
        self.end_headers()

def read_private_key(key_path: str) -> str:
    """Read private key from a file."""
    try:
        with open(key_path, 'r') as f:
            return f.read().strip()
    except Exception as e:
        print(f"Error reading private key file: {str(e)}")
        sys.exit(1)

def run_github_app(port: int = 3000, app_id: str = None, private_key: str = None, webhook_secret: str = None,
                  private_key_path: str = None, anthropic_key: str = None, model: str = None):
    """Run the GitHub App webhook server."""
    # Set environment variables from arguments if provided
    if app_id:
        os.environ['GITHUB_APP_ID'] = app_id
    if private_key:
        os.environ['GITHUB_PRIVATE_KEY'] = private_key
    if webhook_secret:
        os.environ['GITHUB_WEBHOOK_SECRET'] = webhook_secret
    if private_key_path:
        os.environ['GITHUB_PRIVATE_KEY'] = read_private_key(private_key_path)
    if anthropic_key:
        os.environ['ANTHROPIC_API_KEY'] = anthropic_key
        os.environ['INPUT_ANTHROPIC-API-KEY'] = anthropic_key
    if model:
        os.environ['CLAUDE_MODEL'] = model
        os.environ['INPUT_CLAUDE-MODEL'] = model

    # Handle case where GITHUB_PRIVATE_KEY_PATH is set but GITHUB_PRIVATE_KEY is not
    if not os.environ.get('GITHUB_PRIVATE_KEY') and os.environ.get('GITHUB_PRIVATE_KEY_PATH'):
        private_key_path = os.environ.get('GITHUB_PRIVATE_KEY_PATH')
        print(f"Reading private key from: {private_key_path}")
        os.environ['GITHUB_PRIVATE_KEY'] = read_private_key(private_key_path)

    # Check required environment variables
    required_env_vars = [
        'GITHUB_APP_ID',
        'GITHUB_PRIVATE_KEY',
        'GITHUB_WEBHOOK_SECRET'
    ]
    
    missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        sys.exit(1)
        
    server = HTTPServer(('', port), GithubWebhookHandler)
    print(f"GitHub App webhook server running on port {port}")
    server.serve_forever()

def run_commit_monitor_callback(
    reviewer: SecurityReview,
    monitored_repo: MonitoredRepository,
    review_targets: List[BranchReviewTarget],
    telegram_notifier: Optional[TelegramNotifier] = None,
    notify_clean_commits: bool = False,
    monitor: Optional[CommitMonitor] = None,
) -> None:
    """
    Callback function for commit monitoring to analyze new commits.
    
    Args:
        reviewer: SecurityReview instance to use for analysis
        monitored_repo: Repository being monitored
        review_targets: List of branch review targets
        telegram_notifier: Optional Telegram notifier for sending alerts
        notify_clean_commits: Whether to send notifications for clean commits (no vulnerabilities)
        monitor: Optional monitor instance for persisting runtime review state
    """
    print(f"\nAnalyzing {len(review_targets)} pending review target(s) in {monitored_repo.full_name}")
    
    # Show telegram configuration if present
    if monitored_repo.telegram_channel_id:
        print(f"  Telegram channel: {monitored_repo.telegram_channel_id}")
        print(f"  Also notify default channel: {monitored_repo.notify_default_channel}")
    
    # Import database manager if available
    database_available = False
    db_manager = None
    if os.environ.get('DATABASE_URL'):
        try:
            from .database import get_database_manager
            db_manager = get_database_manager()
            database_available = True
        except Exception as e:
            print(f"  ⚠️ Database not available: {e}")
    
    for target in review_targets:
        commit_info = target.commit_info
        print(f"\nAnalyzing branch {target.branch_name} at {target.head_sha[:7]}")
        print(f"  Author: {commit_info.author}")
        print(f"  Message: {commit_info.message[:80]}{'...' if len(commit_info.message) > 80 else ''}")
        
        try:
            analysis, cost_info = reviewer.analyze_security(
                target.combined_changes,
                repo_name=monitored_repo.full_name,
                branch_name=target.branch_name,
                hardfork_name=target.hardfork_name,
                baseline_sha=target.baseline_sha,
                head_sha=target.head_sha,
                working_directory=target.worktree_path,
            )
            
            # Generate HTML content for the finding (same format as manual scans)
            html_content = f"""<h1>Security Review for {monitored_repo.full_name}</h1>
<p><strong>Commit:</strong> <a href="{commit_info.url}">{commit_info.sha[:7]}</a></p>
<p><strong>Author:</strong> {commit_info.author}</p>
<p><strong>Date:</strong> {commit_info.date}</p>
<p><strong>Branch:</strong> {commit_info.branch}</p>
<p><strong>Message:</strong> {commit_info.message}</p>
<p><strong>Review Head:</strong> {target.head_sha}</p>
<p><strong>Starting Commit:</strong> {target.baseline_sha or 'latest commit only'}</p>
<p><strong>Hardfork:</strong> {target.hardfork_name or 'not specified'}</p>
<h2>Analysis Results</h2>
<p><strong>Confidence Score:</strong> {analysis['confidence_score']}%</p>
<p><strong>Has Vulnerabilities:</strong> {'Yes' if analysis['has_vulnerabilities'] else 'No'}</p>
<h3>Summary</h3>
<p>{analysis['summary']}</p>
"""
            
            if analysis.get('findings'):
                html_content += "<h3>Detailed Findings</h3>"
                for finding in analysis['findings']:
                    html_content += f"""
<h4>{finding['severity']} Severity Issue</h4>
<ul>
<li><strong>Description:</strong> {finding['description']}</li>
<li><strong>Recommendation:</strong> {finding['recommendation']}</li>
<li><strong>Confidence:</strong> {finding['confidence']}%</li>
</ul>
"""
            
            # Store in database if available (regardless of vulnerability status)
            finding_url = None
            if database_available and db_manager:
                try:
                    finding_uuid = db_manager.store_finding(
                        html_content=html_content,
                        repo_name=monitored_repo.full_name,
                        commit_info=commit_info,
                        analysis=analysis,
                        metadata=build_storage_metadata(cost_info, {
                            'source': 'continuous_monitoring',
                            'starting_commit_sha': target.baseline_sha,
                            'review_head_sha': target.head_sha,
                            'hardfork_name': target.hardfork_name,
                            'local_repo_path': target.worktree_path,
                        })
                    )
                    from .findings_server import get_finding_url
                    finding_url = get_finding_url(finding_uuid)
                    print(f"  💾 Stored finding {finding_uuid} in database")
                except Exception as db_error:
                    print(f"  ⚠️ Failed to store finding in database: {db_error}")
            
            if analysis['has_vulnerabilities']:
                print(f"  ⚠️ Security issues detected (confidence: {analysis['confidence_score']}%)")
                
                if telegram_notifier:
                    # Send to Telegram with cost information and repository-specific channel configuration
                    if telegram_notifier.send_security_finding(
                        monitored_repo.full_name, 
                        commit_info, 
                        analysis, 
                        cost_info,
                        repo_telegram_channel_id=monitored_repo.telegram_channel_id,
                        notify_default_channel=monitored_repo.notify_default_channel,
                        finding_url=finding_url
                    ):
                        channels_notified = []
                        if monitored_repo.telegram_channel_id:
                            channels_notified.append(f"repo channel ({monitored_repo.telegram_channel_id})")
                        if monitored_repo.notify_default_channel:
                            channels_notified.append("default channel")
                        if not channels_notified:
                            channels_notified.append("default channel")
                        
                        print(f"  📱 Sent security alert to Telegram: {', '.join(channels_notified)} for commit {commit_info.sha[:7]}")
                    else:
                        print(f"  ❌ Failed to send Telegram alert for commit {commit_info.sha[:7]}")
                else:
                    # Create a GitHub issue
                    reviewer.create_commit_issue(monitored_repo.full_name, commit_info, analysis, cost_info)
                    print(f"  📝 Created security issue for commit {commit_info.sha[:7]}")
            else:
                print(f"  ✅ No security issues detected")
                
                # Send notification for clean commits if enabled
                if notify_clean_commits and telegram_notifier:
                    if telegram_notifier.send_clean_commit(monitored_repo.full_name, commit_info, analysis, cost_info):
                        print(f"  📱 Sent clean commit notification to Telegram for commit {commit_info.sha[:7]}")
                    else:
                        print(f"  ❌ Failed to send clean commit notification for commit {commit_info.sha[:7]}")

            if monitor:
                monitor.mark_branch_reviewed(monitored_repo.full_name, target.branch_name, target.head_sha)
                
        except Exception as e:
            error_message = str(e)
            print(f"  ❌ Error analyzing commit {commit_info.sha[:7]}: {error_message}")
            if monitor:
                monitor.mark_branch_review_error(monitored_repo.full_name, target.branch_name, error_message)

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

        parser = argparse.ArgumentParser(description='Analyze PRs, commits, or files for security vulnerabilities')
        parser.add_argument('--github-app', action='store_true', help='Run as a GitHub App webhook server', default=os.environ.get('GITHUB_APP', '').lower() in ('true', 'yes', '1'))
        parser.add_argument('--port', type=int, default=3000, help='Port for GitHub App webhook server')
        parser.add_argument('--github-app-id', help='GitHub App ID')
        parser.add_argument('--github-private-key', help='GitHub App private key')
        parser.add_argument('--github-private-key-path', help='Path to GitHub App private key file')
        parser.add_argument('--github-webhook-secret', help='GitHub App webhook secret')
        parser.add_argument('--file', help='GitHub file URL to analyze (e.g., https://github.com/owner/repo/blob/branch/path/to/file.rs)')
        parser.add_argument('--recent-prs', help='Repository to analyze recent PRs from (e.g., owner/repo)')
        parser.add_argument('--pr-count', type=int, default=10, help='Number of recent PRs to analyze')
        parser.add_argument('--agent-file', help='Relative path under ./agents to AGENT.md or AGENTS.md when overriding repository config')
        parser.add_argument('pr_url', nargs='?', help='GitHub PR URL (e.g., https://github.com/owner/repo/pull/123)')
        parser.add_argument('--github-token', help='GitHub token', default=os.environ.get('GITHUB_TOKEN'))
        parser.add_argument('--anthropic-api-key', help='Anthropic API key', default=os.environ.get('ANTHROPIC_API_KEY'))
        parser.add_argument('--model', help='Claude model to use (defaults to CLAUDE_MODEL)')
        parser.add_argument('--post-comment', help='Post analysis as a comment on the PR', action='store_true')
        parser.add_argument('--input-text', help='Analyze text input directly and output JSON result', action='store_true')

        queue_group = parser.add_argument_group('queue listener')
        queue_group.add_argument('--listen-queue', action='store_true',
                               help='Listen to RabbitMQ/AMQP queue for analysis requests', default=os.environ.get('LISTEN_QUEUE', '').lower() in ('true', 'yes', '1'))
        queue_group.add_argument('--amqp-url', help='AMQP connection URL (or set AMQP_URL env var)',
                               default=os.environ.get('AMQP_URL'))
        queue_group.add_argument('--queue-name', help='Queue name to listen to (or set QUEUE_NAME env var)',
                               default=os.environ.get('QUEUE_NAME', 'security_analysis'))
        queue_group.add_argument('--response-queue-name', help='Queue name for responses (defaults to {queue_name}_response)',
                               default=os.environ.get('RESPONSE_QUEUE_NAME'))

        monitor_group = parser.add_argument_group('commit monitoring')
        monitor_group.add_argument('--config-file', help='Path to configuration file for commit monitoring (optional)', default=None)
        monitor_group.add_argument('--monitor-add', metavar='URL', help='Add a repository to monitor (e.g., https://github.com/owner/repo)')
        monitor_group.add_argument('--monitor-branches', nargs='+', default=['main', 'master'], help='Branches to monitor')
        monitor_group.add_argument('--monitor-remove', metavar='URL', help='Remove a repository from monitoring')
        monitor_group.add_argument('--monitor-list', action='store_true', help='List all monitored repositories')
        monitor_group.add_argument('--monitor-check', action='store_true', help='Check for new commits once')
        monitor_group.add_argument('--monitor-continuous', action='store_true', help='Continuously monitor for new commits', default=os.environ.get('MONITOR_CONTINUOUS', '').lower() in ('true', 'yes', '1'))
        monitor_group.add_argument('--monitor-interval', type=int, default=300, help='Check interval in seconds for continuous monitoring')
        monitor_group.add_argument('--analyze-commit', metavar='SHA', help='Analyze a specific commit (requires --repository)')
        monitor_group.add_argument('--repository', help='Repository for commit analysis (e.g., owner/repo)')
        monitor_group.add_argument('--telegram-bot-token', help='Telegram bot token for notifications', default=os.environ.get('TELEGRAM_BOT_TOKEN'))
        monitor_group.add_argument('--telegram-chat-id', help='Telegram chat ID for notifications', default=os.environ.get('TELEGRAM_CHAT_ID'))
        monitor_group.add_argument('--notify-clean-commits', action='store_true', help='Send Telegram notifications for clean commits (no vulnerabilities)', default=os.environ.get('NOTIFY_CLEAN_COMMITS', '').lower() in ('true', 'yes', '1'))

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

        if not args.listen_queue and args.amqp_url and not any([
            args.input_text, args.github_app, args.file, args.recent_prs, args.pr_url,
            args.monitor_add, args.monitor_remove, args.monitor_list,
            args.monitor_check, args.monitor_continuous, args.analyze_commit
        ]):
            print("ℹ️  Auto-detected queue listener mode (AMQP_URL is set)")
            args.listen_queue = True

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
            analysis, cost_info = reviewer.analyze_security(text_input, agent_file_path=args.agent_file)
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

        if args.listen_queue:
            require_anthropic_key()
            if not args.amqp_url:
                raise ValueError("AMQP URL required for queue listener (use --amqp-url or set AMQP_URL env var)")

            reviewer = SecurityReview(provider_kwargs=build_provider_kwargs(args.model))
            print("\n🐰 Initializing RabbitMQ Queue Listener...")
            print(f"  AMQP URL: {args.amqp_url.split('@')[1] if '@' in args.amqp_url else args.amqp_url}")
            print(f"  Queue name: {args.queue_name}")
            print(f"  Response queue: {args.response_queue_name or f'{args.queue_name}_response'}")

            listener = QueueListener(
                amqp_url=args.amqp_url,
                queue_name=args.queue_name,
                response_queue_name=args.response_queue_name
            )
            listener.set_security_reviewer(reviewer)
            print("\n🚀 Starting queue listener with auto-reconnect...")
            listener.run_with_reconnect(max_retries=10, retry_delay=5)
            return

        if any([args.monitor_add, args.monitor_remove, args.monitor_list, args.monitor_check, args.monitor_continuous, args.analyze_commit]):
            if not args.github_token:
                raise ValueError("GitHub token required for commit monitoring")

            monitor = CommitMonitor(args.github_token, config_file=args.config_file)

            if args.monitor_add:
                print(f"Adding repository to monitoring: {args.monitor_add}")
                print(f"Branches: {', '.join(args.monitor_branches)}")
                monitor.add_repository(args.monitor_add, args.monitor_branches)
                print("✅ Repository added to monitoring")
                return

            if args.monitor_remove:
                print(f"Removing repository from monitoring: {args.monitor_remove}")
                monitor.remove_repository(args.monitor_remove)
                print("✅ Repository removed from monitoring")
                return

            if args.monitor_list:
                monitored = monitor.list_monitored_repositories()
                if monitored:
                    print("\n📋 Monitored Repositories:")
                    for repo_info in monitored:
                        print(f"\n  Repository: {repo_info['repository']}")
                        print(f"  Branches: {', '.join(repo_info['branches'])}")
                        if repo_info['last_commits']:
                            print("  Last known commits:")
                            for branch, sha in repo_info['last_commits'].items():
                                print(f"    - {branch}: {sha[:7]}")
                else:
                    print("\nNo repositories are currently being monitored.")
                return

            require_anthropic_key()
            reviewer = SecurityReview(provider_kwargs=build_provider_kwargs(args.model))

            if args.analyze_commit:
                if not args.repository:
                    raise ValueError("--repository required when using --analyze-commit")
                print(f"\nAnalyzing commit {args.analyze_commit[:7]} in {args.repository}")
                analysis, cost_info = reviewer.analyze_commit(args.repository, args.analyze_commit)
                print_analysis(analysis, cost_info)
                return

            telegram_notifier = None
            if args.telegram_bot_token and args.telegram_chat_id:
                try:
                    import threading
                    import subprocess

                    host = os.environ.get('WEB_APP_HOST', '0.0.0.0')
                    web_port = int(os.environ.get('WEB_APP_PORT', 5000))
                    workers = int(os.environ.get('WEB_APP_WORKERS', 1))
                    print(f"🌐 Starting Security Findings Web Application with Gunicorn at http://{host}:{web_port}")
                    print(f"👷 Workers: {workers}")

                    def start_gunicorn():
                        cmd = [
                            sys.executable, '-m', 'gunicorn',
                            '--config', 'gunicorn.conf.py',
                            'pr_security_review.web_app:create_app()'
                        ]
                        try:
                            subprocess.run(cmd, check=True, env=os.environ.copy())
                        except subprocess.CalledProcessError as e:
                            print(f"❌ Gunicorn failed to start: {e}")
                        except KeyboardInterrupt:
                            print("🔄 Gunicorn shutting down...")

                    web_app_thread = threading.Thread(target=start_gunicorn, daemon=True)
                    web_app_thread.start()
                    print(f"✅ Gunicorn web server started at http://{host}:{web_port}")

                    telegram_notifier = TelegramNotifier(
                        args.telegram_bot_token,
                        args.telegram_chat_id,
                        github_token=args.github_token
                    )
                    print("✅ Telegram notifications enabled")
                    if args.monitor_continuous:
                        telegram_notifier.start_polling()
                        print("✅ Telegram bot is now listening for commands (e.g. /lastcommits)")
                except Exception as e:
                    print(f"⚠️ Telegram notifications disabled: {e}")
            else:
                print("ℹ️ Telegram notifications not configured (will create GitHub issues instead)")

            if args.monitor_check:
                print("\nChecking for new commits...")
                new_commits = monitor.get_new_commits()
                if new_commits:
                    for monitored_repo, review_targets in new_commits:
                        run_commit_monitor_callback(
                            reviewer,
                            monitored_repo,
                            review_targets,
                            telegram_notifier,
                            monitor=monitor,
                        )
                else:
                    print("No new commits found.")
                return

            notify_clean = args.notify_clean_commits
            callback = lambda repo, review_targets: run_commit_monitor_callback(
                reviewer,
                repo,
                review_targets,
                telegram_notifier,
                notify_clean_commits=notify_clean,
                monitor=monitor,
            )
            try:
                print("\n🤖 Monitoring repositories for new commits...")
                if telegram_notifier and getattr(telegram_notifier, '_polling_active', False):
                    print("📱 Telegram bot active and listening for commands (e.g. /lastcommits)")
                monitor.monitor_continuously(
                    check_interval=args.monitor_interval,
                    callback=callback
                )
            except KeyboardInterrupt:
                print("\n\nStopping continuous monitoring...")
                if telegram_notifier and hasattr(telegram_notifier, 'stop_polling'):
                    telegram_notifier.stop_polling()
                    print("Telegram bot polling stopped")
            return

        if args.github_app:
            require_anthropic_key()
            run_github_app(
                port=args.port,
                app_id=args.github_app_id,
                private_key=args.github_private_key,
                webhook_secret=args.github_webhook_secret,
                private_key_path=args.github_private_key_path,
                anthropic_key=args.anthropic_api_key,
                model=args.model
            )
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
            analysis, cost_info = reviewer.analyze_security(changes, repo_name=repo_name, agent_file_path=args.agent_file)
            if analysis['has_vulnerabilities']:
                reviewer.create_report_comment(pr, analysis, cost_info)
                print(f"::warning::Security vulnerabilities detected with {analysis['confidence_score']}% confidence")
            else:
                print("::notice::No security vulnerabilities detected")
            return

        require_anthropic_key()

        if args.file:
            repo_name, branch, file_path = parse_file_url(args.file)
            print(f"\nAnalyzing file: {file_path}")
            print(f"Repository: {repo_name}")
            print(f"Branch: {branch}")
            changes = reviewer.get_file_content(repo_name, branch, file_path)
            pr = None
            analysis, cost_info = reviewer.analyze_security(changes, repo_name=repo_name, agent_file_path=args.agent_file)
            print_analysis(analysis, cost_info)
        elif args.recent_prs:
            repo_name = args.recent_prs
            print(f"\nAnalyzing last {args.pr_count} PRs from repository: {repo_name}")
            recent_prs = reviewer.get_recent_prs(repo_name, args.pr_count)
            if not recent_prs:
                print(f"No PRs found in repository {repo_name}")
                return

            all_results = []
            total_input_tokens = 0
            total_output_tokens = 0
            total_cost_amount = 0.0
            last_model = "unknown"
            last_provider = "unknown"

            print(f"Found {len(recent_prs)} PRs to analyze:")
            for pr in recent_prs:
                print(f"  - PR #{pr.number}: {pr.title}")

            for i, pr in enumerate(recent_prs, 1):
                print(f"\n[{i}/{len(recent_prs)}] Analyzing PR #{pr.number}: {pr.title}")
                try:
                    changes = reviewer.get_pr_changes(pr)
                    if not changes.strip():
                        print(f"  No code changes found in PR #{pr.number}, skipping...")
                        continue
                    analysis, cost_info = reviewer.analyze_security(
                        changes,
                        repo_name=repo_name,
                        agent_file_path=args.agent_file
                    )
                    if cost_info:
                        total_input_tokens += cost_info.input_tokens
                        total_output_tokens += cost_info.output_tokens
                        total_cost_amount += cost_info.total_cost
                        last_model = cost_info.model
                        last_provider = cost_info.provider
                    all_results.append({'pr': pr, 'analysis': analysis, 'cost_info': cost_info})
                    print(f"  {'⚠️' if analysis['has_vulnerabilities'] else '✅'} "
                          f"{'Security issues detected' if analysis['has_vulnerabilities'] else 'No security issues detected'}")
                except Exception as e:
                    print(f"  ❌ Error analyzing PR #{pr.number}: {str(e)}")

            if not all_results:
                print("\n✅ No PRs with code changes were found to analyze.")
                return

            print(f"\n🛡️ Batch Security Review Report")
            print(f"Analyzed {len(all_results)} PRs from {repo_name}")
            if total_cost_amount > 0:
                total_cost = CostInfo(
                    total_cost=total_cost_amount,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    model=last_model,
                    provider=last_provider
                )
                print(f"Total Cost: {total_cost}")

            vulnerable_prs = [result for result in all_results if result['analysis']['has_vulnerabilities']]
            if vulnerable_prs:
                print(f"\n⚠️ Found security issues in {len(vulnerable_prs)} PR(s):")
                for result in vulnerable_prs:
                    pr_info = result['pr']
                    analysis = result['analysis']
                    print(f"\n  PR #{pr_info.number}: {pr_info.title}")
                    print(f"  Confidence: {analysis['confidence_score']}%")
                    print(f"  Summary: {analysis['summary']}")
                    for finding in analysis['findings']:
                        print(f"    - {finding['severity']}: {finding['description']}")
                print(f"\n::warning::Security vulnerabilities detected in {len(vulnerable_prs)} out of {len(all_results)} PRs")
            else:
                print(f"\n✅ No security vulnerabilities detected in any of the {len(all_results)} analyzed PRs.")
                print("::notice::No security vulnerabilities detected in batch analysis")
            return
        elif args.pr_url:
            repo_name, pr_number = parse_pr_url(args.pr_url)
            print(f"\nAnalyzing PR #{pr_number}")
            print(f"Repository: {repo_name}")
            repo = reviewer.github.get_repo(repo_name)
            pr = repo.get_pull(pr_number)
            changes = reviewer.get_pr_changes(pr)
            analysis, cost_info = reviewer.analyze_security(changes, repo_name=repo_name, agent_file_path=args.agent_file)
            if args.post_comment and analysis['has_vulnerabilities']:
                reviewer.create_report_comment(pr, analysis, cost_info)
            else:
                print_analysis(analysis, cost_info)
            if analysis['has_vulnerabilities']:
                print(f"::warning::Security vulnerabilities detected with {analysis['confidence_score']}% confidence")
            else:
                print("::notice::No security vulnerabilities detected")
            return
        else:
            raise ValueError("Either --file, --recent-prs, --input-text, or pr_url must be provided")

        if analysis['has_vulnerabilities']:
            print(f"::warning::Security vulnerabilities detected with {analysis['confidence_score']}% confidence")
        else:
            print("::notice::No security vulnerabilities detected")

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
