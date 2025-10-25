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
from github.PullRequest import PullRequest
from github.GithubIntegration import GithubIntegration
from .llm_providers import LLMProvider, ClaudeProvider, GPTProvider, GeminiProvider, DeepseekProvider, LlamaProvider, MultiJudgeProvider, CostInfo
from .document_store import DocumentStore
from .embeddings import OpenAIEmbeddings, VoyageEmbeddings
from .commit_monitor import CommitMonitor, MonitoredRepository, CommitInfo
from .telegram_notifier import TelegramNotifier
from .web_app import SecurityFinderApp
from .queue_listener import QueueListener

class SecurityReview:
    """Handles security review of pull requests using various LLM providers."""
    
    PROVIDERS = {
        'anthropic': ClaudeProvider,
        'openai': GPTProvider,
        'gemini': GeminiProvider,
        'deepseek': DeepseekProvider,
        'llama': LlamaProvider
    }
    
    def __init__(self, provider_name: str = 'anthropic', provider_kwargs: Dict = None, docs_dir: Optional[str] = None, 
                 voyage_key: Optional[str] = None, voyage_model: Optional[str] = None, 
                 multi_judge: bool = None, gemini_key: Optional[str] = None, provider_weights: Dict[str, float] = None):
        """
        Initialize the security review handler.
        
        Args:
            provider_name: Name of the LLM provider to use ('anthropic', 'openai', 'gemini')
            provider_kwargs: Additional provider-specific configuration
            docs_dir: Directory containing vulnerability documentation
            voyage_key: Voyage AI API key for embeddings
            voyage_model: Voyage AI model to use
            multi_judge: Whether to use multi-judge mode (None = auto-detect based on API keys)
            gemini_key: Gemini API key (for multi-judge mode)
            provider_weights: Custom weights for each provider in multi-judge mode
        """
        # Collect all available API keys
        api_keys = {}
        
        # Get Anthropic key
        anthropic_key = os.environ.get('INPUT_ANTHROPIC-API-KEY') or os.environ.get('ANTHROPIC_API_KEY')
        if anthropic_key:
            api_keys['anthropic'] = anthropic_key
        
        # Get OpenAI key
        openai_key = os.environ.get('INPUT_OPENAI-API-KEY') or os.environ.get('OPENAI_API_KEY')
        if openai_key:
            api_keys['openai'] = openai_key
        
        # Get Gemini key
        gemini_api_key = gemini_key or os.environ.get('INPUT_GEMINI-API-KEY') or os.environ.get('GEMINI_API_KEY')
        if gemini_api_key:
            api_keys['gemini'] = gemini_api_key
        
        # Get Deepseek key
        deepseek_key = os.environ.get('INPUT_DEEPSEEK-API-KEY') or os.environ.get('DEEPSEEK_API_KEY')
        if deepseek_key:
            api_keys['deepseek'] = deepseek_key
        
        # Get Llama key
        llama_key = os.environ.get('INPUT_LLAMA-API-KEY') or os.environ.get('LLAMA_API_KEY')
        if llama_key:
            api_keys['llama'] = llama_key
        
        # Auto-detect multi-judge mode if not explicitly set
        if multi_judge is None:
            # Use multi-judge if more than one API key is provided
            multi_judge = len(api_keys) > 1
        
        # Set up provider based on mode
        if multi_judge:
            if len(api_keys) < 2:
                raise ValueError("Multi-judge mode requires at least 2 API keys from different providers")
            
            if 'anthropic' not in api_keys:
                raise ValueError("Anthropic API key is required for multi-judge mode (used for synthesis)")
            
            # Merge provider_kwargs with weights if provided
            multi_judge_kwargs = provider_kwargs or {}
            if provider_weights:
                multi_judge_kwargs['weights'] = provider_weights
                
            # Initialize MultiJudgeProvider
            self.llm = MultiJudgeProvider(api_keys, **multi_judge_kwargs)
        else:
            # Single provider mode
            provider_class = self.PROVIDERS.get(provider_name)
            if not provider_class:
                raise ValueError(f"Unknown LLM provider: {provider_name}")
                
            api_key = self._get_provider_api_key(provider_name)
            if not api_key:
                raise ValueError(f"Missing API key for {provider_name}")
                
            self.llm = provider_class(api_key, **(provider_kwargs or {}))
        
        # Initialize GitHub client
        self.github_token = os.environ.get('INPUT_GITHUB-TOKEN') or os.environ.get('GITHUB_TOKEN')
        if self.github_token:
            self.github = Github(auth=Auth.Token(self.github_token))
        else:
            # When running as GitHub App, the token will be provided later
            self.github = None
        
        # Initialize document store if docs directory is provided
        self.doc_store = None
        if docs_dir:
            print("\nInitializing document store:")
            print(f"Provider: {provider_name}")
            print(f"Docs directory: {docs_dir}")
            print(f"Voyage key present: {bool(voyage_key)}")
            print(f"Voyage model: {voyage_model or 'voyage-3-large'}")
            
            # Choose embedding provider based on availability
            # Priority: Voyage AI (preferred for all providers) > OpenAI (only for single OpenAI provider) > Error
            embeddings_provider = None
            
            if voyage_key:
                print("Using Voyage AI for embeddings")
                embeddings_provider = VoyageEmbeddings(voyage_key, model=voyage_model or "voyage-3-large")
            elif multi_judge:
                # Multi-judge mode requires Voyage AI for best quality across all providers
                raise ValueError("Voyage AI key (--voyage-api-key) is required for document search in multi-judge mode for optimal embedding quality across all providers.")
            elif provider_name == 'openai':
                # For single OpenAI provider, allow OpenAI embeddings as fallback
                openai_key = self._get_provider_api_key('openai')
                if openai_key:
                    print("Using OpenAI for embeddings")
                    embeddings_provider = OpenAIEmbeddings(openai_key)
                else:
                    raise ValueError("OpenAI API key required for embeddings when Voyage AI key is not provided")
            else:
                # For other single providers (anthropic, gemini, deepseek, llama), require Voyage AI
                raise ValueError(f"Voyage AI key (--voyage-api-key) is required for document search with {provider_name} provider.")
            
            if embeddings_provider:
                self.doc_store = DocumentStore(docs_dir, embeddings_provider)
                print("Document store initialized successfully")
                self.doc_store.load_documents()

    def _get_provider_api_key(self, provider_name: str) -> Optional[str]:
        """Get the API key for the specified provider."""
        if provider_name == 'anthropic':
            return os.environ.get('INPUT_ANTHROPIC-API-KEY') or os.environ.get('ANTHROPIC_API_KEY')
        elif provider_name == 'openai':
            return os.environ.get('INPUT_OPENAI-API-KEY') or os.environ.get('OPENAI_API_KEY')
        elif provider_name == 'gemini':
            return os.environ.get('INPUT_GEMINI-API-KEY') or os.environ.get('GEMINI_API_KEY')
        elif provider_name == 'deepseek':
            return os.environ.get('INPUT_DEEPSEEK-API-KEY') or os.environ.get('DEEPSEEK_API_KEY')
        elif provider_name == 'llama':
            return os.environ.get('INPUT_LLAMA-API-KEY') or os.environ.get('LLAMA_API_KEY')
        return None

    def get_pr_changes(self, pr: PullRequest) -> str:
        """
        Get the changes from a pull request.
        
        Args:
            pr: The pull request object
            
        Returns:
            str: A string containing all file changes
        """
        changes = []
        for file in pr.get_files():
            if file.patch:
                changes.append(f"File: {file.filename}\n{file.patch}\n")
        return "\n".join(changes)

    def get_recent_prs(self, repo_name: str, count: int = 10) -> List[PullRequest]:
        """
        Get the most recent PRs from a repository.
        
        Args:
            repo_name: Full name of the repository (e.g., 'owner/repo')
            count: Number of recent PRs to retrieve
            
        Returns:
            List of PullRequest objects, ordered by creation date (newest first)
        """
        if not self.github:
            raise ValueError("GitHub client not initialized")
            
        repo = self.github.get_repo(repo_name)
        # Get recent PRs (both open and closed)
        prs = repo.get_pulls(state='all', sort='created', direction='desc')
        return list(prs[:count])
        
    def get_file_content(self, repo_name: str, branch: str, file_path: str) -> str:
        """
        Get the content of a file from a GitHub repository.
        
        Args:
            repo_name: Full name of the repository (e.g., 'owner/repo')
            branch: Branch name (e.g., 'main', 'dev')
            file_path: Path to the file in the repository
            
        Returns:
            str: The content of the file with metadata
        """
        if not self.github:
            raise ValueError("GitHub client not initialized")
            
        repo = self.github.get_repo(repo_name)
        file_content = repo.get_contents(file_path, ref=branch)
        
        if isinstance(file_content, list):
            raise ValueError(f"Path '{file_path}' refers to a directory, not a file")
            
        decoded_content = file_content.decoded_content.decode('utf-8')
        return f"File: {file_path}\n\n{decoded_content}"

    def analyze_security(self, code_changes: str) -> Tuple[Dict, CostInfo]:
        """
        Analyze code changes for security issues using the configured LLM provider.
        
        Args:
            code_changes: String containing the code changes to analyze
            
        Returns:
            Tuple containing:
            - Dict: Analysis results including confidence and findings
            - CostInfo: Cost information for the request
        """
        # Get relevant context if document store is available
        context = ""
        if self.doc_store:
            context = self.doc_store.get_relevant_context(code_changes)
            
        # Get security analysis with context
        return self.llm.analyze_security(code_changes, context)

    def create_report_comment(self, pr: PullRequest, analysis: Dict, cost_info: CostInfo = None) -> None:
        """
        Create a comment on the PR with the security analysis results.
        
        Args:
            pr: The pull request object
            analysis: The security analysis results
            cost_info: Optional cost information for the analysis
        """
        report = f"""## Security Review

**Confidence Score:** {analysis['confidence_score']}%
**Detected Security Issues:** {'Yes' if analysis['has_vulnerabilities'] else 'No'}

### Summary
{analysis['summary']}

# """
        
#         if cost_info and cost_info.total_cost > 0:
#             report += f"""### Cost Information
# **Analysis Cost:** {cost_info}

# """
        
        if analysis['findings']:
            report += "\n### Detailed Findings\n"
            for finding in analysis['findings']:
                # Get additional resources if available
                has_resources = 'additional_resources' in finding
                additional_resources = finding.get('additional_resources', '')
                
                # Build the report
                report_content = f"""
#### {finding['severity']} Severity Issue
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}
- **Confidence:** {finding['confidence']}%

<details>
<summary>📑 Detailed Explanation</summary>

#### What is the issue?
{finding.get('detailed_explanation', 'No detailed explanation provided.')}

#### What can happen?
{finding.get('impact_explanation', 'The security implications of this vulnerability could lead to unauthorized access, data exposure, or system compromise depending on the specific implementation.')}

#### How to fix it?
{finding.get('detailed_recommendation', finding['recommendation'])}

#### Code example:
```
{finding.get('code_example', '// Example fix not available')}
```
"""
                
                # Only add resources section if resources are actually available
                if has_resources and additional_resources.strip():
                    # Format resources as a list if they're not already formatted
                    if not additional_resources.strip().startswith(('- ', '* ', '1.')):
                        # Split by newlines and format as list
                        resource_lines = [line.strip() for line in additional_resources.strip().split('\n') if line.strip()]
                        formatted_resources = '\n'.join(f"- {line}" for line in resource_lines)
                    else:
                        formatted_resources = additional_resources
                    
                    report_content += f"""
#### Additional resources:
{formatted_resources}
"""
                
                report_content += """
</details>
"""
                
                report += report_content
        
        pr.create_issue_comment(report)

    def analyze_commit(self, repo_name: str, commit_sha: str, branch: str = None) -> Tuple[Dict, CostInfo]:
        """
        Analyze a specific commit for security issues.
        
        Args:
            repo_name: Full repository name (owner/repo)
            commit_sha: Commit SHA to analyze
            branch: Optional branch name for context
            
        Returns:
            Tuple containing analysis results and cost info
        """
        if not self.github:
            raise ValueError("GitHub client not initialized")
            
        # Get commit changes using the existing GitHub client
        # Use the same token that was used to initialize the SecurityReview
        monitor = CommitMonitor(self.github_token)
        commit_changes = monitor.get_commit_changes(repo_name, commit_sha)
        
        if not commit_changes:
            raise ValueError(f"Could not retrieve commit {commit_sha} from {repo_name}")
            
        # Analyze the commit changes
        return self.analyze_security(commit_changes)

    def create_commit_issue(self, repo_name: str, commit_info: CommitInfo, analysis: Dict, cost_info: CostInfo = None) -> None:
        """
        Create an issue for a commit with security findings.
        
        Args:
            repo_name: Full repository name (owner/repo)
            commit_info: Information about the commit
            analysis: Security analysis results
            cost_info: Optional cost information
        """
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
        
        if analysis['findings']:
            body += "\n### Detailed Findings\n"
            for finding in analysis['findings']:
                # Get additional resources if available
                has_resources = 'additional_resources' in finding
                additional_resources = finding.get('additional_resources', '')
                
                # Build the report
                report_content = f"""
#### {finding['severity']} Severity Issue
- **Description:** {finding['description']}
- **Recommendation:** {finding['recommendation']}
- **Confidence:** {finding['confidence']}%

<details>
<summary>📑 Detailed Explanation</summary>

#### What is the issue?
{finding.get('detailed_explanation', 'No detailed explanation provided.')}

#### What can happen?
{finding.get('impact_explanation', 'The security implications of this vulnerability could lead to unauthorized access, data exposure, or system compromise depending on the specific implementation.')}

#### How to fix it?
{finding.get('detailed_recommendation', finding['recommendation'])}

#### Code example:
```
{finding.get('code_example', '// Example fix not available')}
```
"""
                
                # Only add resources section if resources are actually available
                if has_resources and additional_resources.strip():
                    # Format resources as a list if they're not already formatted
                    if not additional_resources.strip().startswith(('- ', '* ', '1.')):
                        # Split by newlines and format as list
                        resource_lines = [line.strip() for line in additional_resources.strip().split('\n') if line.strip()]
                        formatted_resources = '\n'.join(f"- {line}" for line in resource_lines)
                    else:
                        formatted_resources = additional_resources
                    
                    report_content += f"""
#### Additional resources:
{formatted_resources}
"""
                
                report_content += """
</details>
"""
                
                body += report_content
        
        # Create issue with security label
        labels = ['security']
        if analysis['has_vulnerabilities']:
            labels.append('vulnerability')
            
        repo.create_issue(title=title, body=body, labels=labels)

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
                    
                    # Initialize security reviewer
                    provider_name = os.environ.get('INPUT_LLM-PROVIDER', 'anthropic')
                    provider_kwargs = {}
                    if provider_name == 'anthropic':
                        if model := os.environ.get('INPUT_CLAUDE-MODEL'):
                            provider_kwargs['model'] = model
                    elif provider_name == 'openai':
                        if model := os.environ.get('INPUT_GPT-MODEL'):
                            provider_kwargs['model'] = model
                            
                    docs_dir = os.path.abspath(os.environ.get('INPUT_DOCS-DIR')) if os.environ.get('INPUT_DOCS-DIR') else None
                    reviewer = SecurityReview(
                        provider_name,
                        provider_kwargs,
                        docs_dir=docs_dir,
                        voyage_key=os.environ.get('INPUT_VOYAGE-API-KEY'),
                        voyage_model=os.environ.get('INPUT_VOYAGE-MODEL')
                    )
                    
                    # Get PR changes and analyze
                    changes = reviewer.get_pr_changes(pr)
                    analysis, cost_info = reviewer.analyze_security(changes)
                    
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
                    
                    # Initialize security reviewer
                    provider_name = os.environ.get('INPUT_LLM-PROVIDER', 'anthropic')
                    provider_kwargs = {}
                    if provider_name == 'anthropic':
                        if model := os.environ.get('INPUT_CLAUDE-MODEL'):
                            provider_kwargs['model'] = model
                    elif provider_name == 'openai':
                        if model := os.environ.get('INPUT_GPT-MODEL'):
                            provider_kwargs['model'] = model
                            
                    docs_dir = os.path.abspath(os.environ.get('INPUT_DOCS-DIR')) if os.environ.get('INPUT_DOCS-DIR') else None
                    reviewer = SecurityReview(
                        provider_name,
                        provider_kwargs,
                        docs_dir=docs_dir,
                        voyage_key=os.environ.get('INPUT_VOYAGE-API-KEY'),
                        voyage_model=os.environ.get('INPUT_VOYAGE-MODEL')
                    )
                    
                    # Get PR changes and analyze
                    changes = reviewer.get_pr_changes(pr)
                    analysis, cost_info = reviewer.analyze_security(changes)
                    
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
                  private_key_path: str = None, anthropic_key: str = None, openai_key: str = None, voyage_key: str = None,
                  llm_provider: str = None, model: str = None, docs_dir: str = None):
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
        os.environ['INPUT_ANTHROPIC-API-KEY'] = anthropic_key
    if openai_key:
        os.environ['INPUT_OPENAI-API-KEY'] = openai_key
    if voyage_key:
        os.environ['INPUT_VOYAGE-API-KEY'] = voyage_key
    if llm_provider:
        os.environ['INPUT_LLM-PROVIDER'] = llm_provider
    if model:
        if llm_provider == 'anthropic':
            os.environ['INPUT_CLAUDE-MODEL'] = model
        else:  # openai
            os.environ['INPUT_GPT-MODEL'] = model
    if docs_dir:
        os.environ['INPUT_DOCS-DIR'] = docs_dir

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

def run_commit_monitor_callback(reviewer: SecurityReview, monitored_repo: MonitoredRepository, commits: List[CommitInfo], 
                               telegram_notifier: Optional[TelegramNotifier] = None, notify_clean_commits: bool = False) -> None:
    """
    Callback function for commit monitoring to analyze new commits.
    
    Args:
        reviewer: SecurityReview instance to use for analysis
        monitored_repo: Repository being monitored
        commits: List of new commits found
        telegram_notifier: Optional Telegram notifier for sending alerts
        notify_clean_commits: Whether to send notifications for clean commits (no vulnerabilities)
    """
    print(f"\nAnalyzing {len(commits)} new commits in {monitored_repo.full_name}")
    
    # Load repository-specific agent configuration if running as web service
    if os.environ.get('DATABASE_URL'):
        from .config_loader import agent_config
        
        try:
            # Try to load repository-specific agent
            if agent_config.load_for_repository(monitored_repo.full_name):
                print(f"  ✓ Using repository-specific agent configuration")
            else:
                print(f"  ℹ Using main agent configuration")
        except Exception as e:
            print(f"  ⚠️ Failed to load repository-specific agent, using main agent: {e}")
    
    # Show telegram configuration if present
    if monitored_repo.telegram_channel_id:
        print(f"  Telegram channel: {monitored_repo.telegram_channel_id}")
        print(f"  Also notify default channel: {monitored_repo.notify_default_channel}")
    
    for commit_info in commits:
        print(f"\nAnalyzing commit {commit_info.sha[:7]} on branch {commit_info.branch}")
        print(f"  Author: {commit_info.author}")
        print(f"  Message: {commit_info.message[:80]}{'...' if len(commit_info.message) > 80 else ''}")
        
        try:
            # Analyze the commit
            analysis, cost_info = reviewer.analyze_commit(monitored_repo.full_name, commit_info.sha, commit_info.branch)
            
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
                        notify_default_channel=monitored_repo.notify_default_channel
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
                    print(f"   Created security issue for commit {commit_info.sha[:7]}")
            else:
                print(f"  ✅ No security issues detected")
                
                # Send notification for clean commits if enabled
                if notify_clean_commits and telegram_notifier:
                    if telegram_notifier.send_clean_commit(monitored_repo.full_name, commit_info, analysis, cost_info):
                        print(f"  📱 Sent clean commit notification to Telegram for commit {commit_info.sha[:7]}")
                    else:
                        print(f"  ❌ Failed to send clean commit notification for commit {commit_info.sha[:7]}")
                
        except Exception as e:
            print(f"  ❌ Error analyzing commit {commit_info.sha[:7]}: {str(e)}")

def main():
    """Main entry point for the security review action."""
    try:
        # Load environment variables from .env file
        dotenv.load_dotenv()
        
        # Import config loader after dotenv is loaded
        from .config_loader import load_agent_config
        
        # Fix for token loading - ensure we load the real token from .env
        env_path = os.path.join(os.getcwd(), '.env')
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        if line.startswith('GITHUB_TOKEN='):
                            token_value = line.split('=', 1)[1].strip()
                            if token_value != 'your_github_token_here' and token_value != 'your_actual_token_here':
                                os.environ['GITHUB_TOKEN'] = token_value
        
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='Analyze PR or file for security vulnerabilities')
        parser.add_argument('--github-app', action='store_true', help='Run as a GitHub App webhook server', default=os.environ.get('GITHUB_APP', '').lower() in ('true', 'yes', '1'))
        parser.add_argument('--agent', help='Path to agent configuration JSON file (defaults to agent.json if not specified)', 
                           default=None)
        parser.add_argument('--port', type=int, default=3000, help='Port for GitHub App webhook server')
        parser.add_argument('--github-app-id', help='GitHub App ID')
        parser.add_argument('--github-private-key', help='GitHub App private key')
        parser.add_argument('--github-private-key-path', help='Path to GitHub App private key file')
        parser.add_argument('--github-webhook-secret', help='GitHub App webhook secret')
        parser.add_argument('--file', help='GitHub file URL to analyze (e.g., https://github.com/owner/repo/blob/branch/path/to/file.rs)')
        parser.add_argument('--recent-prs', help='Repository to analyze recent PRs from (e.g., owner/repo)')
        parser.add_argument('--pr-count', type=int, default=10, help='Number of recent PRs to analyze (default: 10)')
        parser.add_argument('pr_url', nargs='?', help='GitHub PR URL (e.g., https://github.com/owner/repo/pull/123)')
        parser.add_argument('--github-token', help='GitHub token', default=os.environ.get('GITHUB_TOKEN'))
        parser.add_argument('--llm-provider', help='LLM provider to use (anthropic, openai, gemini, deepseek, or llama)', default='anthropic')
        parser.add_argument('--anthropic-api-key', help='Anthropic API key', default=os.environ.get('ANTHROPIC_API_KEY'))
        parser.add_argument('--openai-api-key', help='OpenAI API key', default=os.environ.get('OPENAI_API_KEY'))
        parser.add_argument('--gemini-api-key', help='Gemini API key', default=os.environ.get('GEMINI_API_KEY'))
        parser.add_argument('--deepseek-api-key', help='Deepseek API key', default=os.environ.get('DEEPSEEK_API_KEY'))
        parser.add_argument('--llama-api-key', help='Llama API key', default=os.environ.get('LLAMA_API_KEY'))
        parser.add_argument('--multi-judge', action='store_true', 
                          default=os.environ.get('MULTI_JUDGE', '').lower() in ('true', 'yes', '1'),
                          help='Use multi-judge mode with weighted voting from multiple LLMs (can also set MULTI_JUDGE=true env var)')
        
        # Provider weight arguments for multi-judge mode
        weight_group = parser.add_argument_group('multi-judge weights')
        weight_group.add_argument('--anthropic-weight', type=float, 
                                help='Weight for Anthropic in multi-judge mode (default: 1.0)',
                                default=float(os.environ.get('ANTHROPIC_WEIGHT', '1.0')))
        weight_group.add_argument('--openai-weight', type=float,
                                help='Weight for OpenAI in multi-judge mode (default: 0.1)',
                                default=float(os.environ.get('OPENAI_WEIGHT', '0.1')))
        weight_group.add_argument('--gemini-weight', type=float,
                                help='Weight for Gemini in multi-judge mode (default: 0.1)',
                                default=float(os.environ.get('GEMINI_WEIGHT', '0.1')))
        weight_group.add_argument('--deepseek-weight', type=float,
                                help='Weight for Deepseek in multi-judge mode (default: 0.1)',
                                default=float(os.environ.get('DEEPSEEK_WEIGHT', '0.1')))
        weight_group.add_argument('--llama-weight', type=float,
                                help='Weight for Llama in multi-judge mode (default: 0.1)',
                                default=float(os.environ.get('LLAMA_WEIGHT', '0.1')))
        
        parser.add_argument('--model', help='Specific model to use (e.g., claude-sonnet-4-20250514)')
        parser.add_argument('--docs-dir', help='Directory containing vulnerability documentation', default=os.environ.get('DOCS_DIR'))
        parser.add_argument('--voyage-api-key', help='Voyage AI API key for embeddings (preferred for all providers with --docs-dir, falls back to OpenAI embeddings if available)', default=os.environ.get('VOYAGE_API_KEY'))
        parser.add_argument('--voyage-model', help='Voyage AI model to use', default='voyage-3-large')
        parser.add_argument('--post-comment', help='Post analysis as a comment on the PR', action='store_true')
        parser.add_argument('--input-text', help='Analyze text input directly and output JSON result', action='store_true')
        
        # LLM Prompt configuration arguments
        prompt_group = parser.add_argument_group('llm prompts')
        prompt_group.add_argument('--llm-security-prompt-intro', 
                                help='Security analysis introduction prompt',
                                default=os.environ.get('LLM_SECURITY_PROMPT_INTRO'))
        prompt_group.add_argument('--llm-security-prompt-focus-areas',
                                help='Security focus areas prompt',
                                default=os.environ.get('LLM_SECURITY_PROMPT_FOCUS_AREAS'))
        prompt_group.add_argument('--llm-security-prompt-important-notes',
                                help='Important notes for security analysis',
                                default=os.environ.get('LLM_SECURITY_PROMPT_IMPORTANT_NOTES'))
        prompt_group.add_argument('--llm-security-prompt-examples',
                                help='Examples of concrete vulnerabilities',
                                default=os.environ.get('LLM_SECURITY_PROMPT_EXAMPLES'))
        prompt_group.add_argument('--llm-security-prompt-response-format',
                                help='Expected JSON response format',
                                default=os.environ.get('LLM_SECURITY_PROMPT_RESPONSE_FORMAT'))
        prompt_group.add_argument('--llm-security-prompt-no-vulns-response',
                                help='Response format when no vulnerabilities found',
                                default=os.environ.get('LLM_SECURITY_PROMPT_NO_VULNS_RESPONSE'))
        prompt_group.add_argument('--llm-skeptical-verification-intro',
                                help='Skeptical verification introduction',
                                default=os.environ.get('LLM_SKEPTICAL_VERIFICATION_INTRO'))
        prompt_group.add_argument('--llm-skeptical-verification-critical-questions',
                                help='Critical questions for verification',
                                default=os.environ.get('LLM_SKEPTICAL_VERIFICATION_CRITICAL_QUESTIONS'))
        prompt_group.add_argument('--llm-skeptical-verification-be-critical',
                                help='Instructions to be critical',
                                default=os.environ.get('LLM_SKEPTICAL_VERIFICATION_BE_CRITICAL'))
        prompt_group.add_argument('--llm-skeptical-verification-only-confirm',
                                help='Criteria for confirming vulnerabilities',
                                default=os.environ.get('LLM_SKEPTICAL_VERIFICATION_ONLY_CONFIRM'))
        prompt_group.add_argument('--llm-skeptical-verification-response-format',
                                help='Verification response format',
                                default=os.environ.get('LLM_SKEPTICAL_VERIFICATION_RESPONSE_FORMAT'))
        prompt_group.add_argument('--llm-synthesis-prompt-intro',
                                help='Multi-judge synthesis introduction',
                                default=os.environ.get('LLM_SYNTHESIS_PROMPT_INTRO'))
        prompt_group.add_argument('--llm-synthesis-prompt-instruction',
                                help='Synthesis instructions',
                                default=os.environ.get('LLM_SYNTHESIS_PROMPT_INSTRUCTION'))
        prompt_group.add_argument('--llm-synthesis-system-prompt',
                                help='Main system prompt',
                                default=os.environ.get('LLM_SYNTHESIS_SYSTEM_PROMPT'))
        prompt_group.add_argument('--llm-synthesis-system-prompt-anthropic',
                                help='Anthropic-specific system prompt',
                                default=os.environ.get('LLM_SYNTHESIS_SYSTEM_PROMPT_ANTHROPIC'))
        prompt_group.add_argument('--llm-synthesis-system-prompt-synthesize',
                                help='Synthesis system prompt',
                                default=os.environ.get('LLM_SYNTHESIS_SYSTEM_PROMPT_SYNTHESIZE'))
        
        # Queue listener arguments
        queue_group = parser.add_argument_group('queue listener')
        queue_group.add_argument('--listen-queue', action='store_true', 
                               help='Listen to RabbitMQ/AMQP queue for analysis requests', default=os.environ.get('LISTEN_QUEUE', '').lower() in ('true', 'yes', '1'))
        queue_group.add_argument('--amqp-url', help='AMQP connection URL (or set AMQP_URL env var)', 
                               default=os.environ.get('AMQP_URL'))
        queue_group.add_argument('--queue-name', help='Queue name to listen to (or set QUEUE_NAME env var)', 
                               default=os.environ.get('QUEUE_NAME', 'security_analysis'))
        queue_group.add_argument('--response-queue-name', help='Queue name for responses (defaults to {queue_name}_response)', 
                               default=os.environ.get('RESPONSE_QUEUE_NAME'))
        
        # Commit monitoring arguments
        monitor_group = parser.add_argument_group('commit monitoring')
        monitor_group.add_argument('--config-file', help='Path to configuration file for commit monitoring (optional)', default=None)
        monitor_group.add_argument('--monitor-add', metavar='URL', help='Add a repository to monitor (e.g., https://github.com/owner/repo)')
        monitor_group.add_argument('--monitor-branches', nargs='+', default=['main', 'master'], help='Branches to monitor (default: main master)')
        monitor_group.add_argument('--monitor-remove', metavar='URL', help='Remove a repository from monitoring')
        monitor_group.add_argument('--monitor-list', action='store_true', help='List all monitored repositories')
        monitor_group.add_argument('--monitor-check', action='store_true', help='Check for new commits once')
        monitor_group.add_argument('--monitor-continuous', action='store_true', help='Continuously monitor for new commits', default=os.environ.get('MONITOR_CONTINUOUS', '').lower() in ('true', 'yes', '1'))
        monitor_group.add_argument('--monitor-interval', type=int, default=300, help='Check interval in seconds for continuous monitoring (default: 300)')
        monitor_group.add_argument('--analyze-commit', metavar='SHA', help='Analyze a specific commit (requires --repository)')
        monitor_group.add_argument('--repository', help='Repository for commit analysis (e.g., owner/repo)')
        monitor_group.add_argument('--telegram-bot-token', help='Telegram bot token for notifications', default=os.environ.get('TELEGRAM_BOT_TOKEN'))
        monitor_group.add_argument('--telegram-chat-id', help='Telegram chat ID for notifications', default=os.environ.get('TELEGRAM_CHAT_ID'))
        monitor_group.add_argument('--notify-clean-commits', action='store_true', help='Send Telegram notifications for clean commits (no vulnerabilities)', default=os.environ.get('NOTIFY_CLEAN_COMMITS', '').lower() in ('true', 'yes', '1'))
        
        args = parser.parse_args()
        
        # Load agent configuration
        load_agent_config(args.agent)
        
        # Set LLM prompt environment variables from command-line flags if provided
        if args.llm_security_prompt_intro:
            os.environ['LLM_SECURITY_PROMPT_INTRO'] = args.llm_security_prompt_intro
        if args.llm_security_prompt_focus_areas:
            os.environ['LLM_SECURITY_PROMPT_FOCUS_AREAS'] = args.llm_security_prompt_focus_areas
        if args.llm_security_prompt_important_notes:
            os.environ['LLM_SECURITY_PROMPT_IMPORTANT_NOTES'] = args.llm_security_prompt_important_notes
        if args.llm_security_prompt_examples:
            os.environ['LLM_SECURITY_PROMPT_EXAMPLES'] = args.llm_security_prompt_examples
        if args.llm_security_prompt_response_format:
            os.environ['LLM_SECURITY_PROMPT_RESPONSE_FORMAT'] = args.llm_security_prompt_response_format
        if args.llm_security_prompt_no_vulns_response:
            os.environ['LLM_SECURITY_PROMPT_NO_VULNS_RESPONSE'] = args.llm_security_prompt_no_vulns_response
        if args.llm_skeptical_verification_intro:
            os.environ['LLM_SKEPTICAL_VERIFICATION_INTRO'] = args.llm_skeptical_verification_intro
        if args.llm_skeptical_verification_critical_questions:
            os.environ['LLM_SKEPTICAL_VERIFICATION_CRITICAL_QUESTIONS'] = args.llm_skeptical_verification_critical_questions
        if args.llm_skeptical_verification_be_critical:
            os.environ['LLM_SKEPTICAL_VERIFICATION_BE_CRITICAL'] = args.llm_skeptical_verification_be_critical
        if args.llm_skeptical_verification_only_confirm:
            os.environ['LLM_SKEPTICAL_VERIFICATION_ONLY_CONFIRM'] = args.llm_skeptical_verification_only_confirm
        if args.llm_skeptical_verification_response_format:
            os.environ['LLM_SKEPTICAL_VERIFICATION_RESPONSE_FORMAT'] = args.llm_skeptical_verification_response_format
        if args.llm_synthesis_prompt_intro:
            os.environ['LLM_SYNTHESIS_PROMPT_INTRO'] = args.llm_synthesis_prompt_intro
        if args.llm_synthesis_prompt_instruction:
            os.environ['LLM_SYNTHESIS_PROMPT_INSTRUCTION'] = args.llm_synthesis_prompt_instruction
        if args.llm_synthesis_system_prompt:
            os.environ['LLM_SYNTHESIS_SYSTEM_PROMPT'] = args.llm_synthesis_system_prompt
        if args.llm_synthesis_system_prompt_anthropic:
            os.environ['LLM_SYNTHESIS_SYSTEM_PROMPT_ANTHROPIC'] = args.llm_synthesis_system_prompt_anthropic
        if args.llm_synthesis_system_prompt_synthesize:
            os.environ['LLM_SYNTHESIS_SYSTEM_PROMPT_SYNTHESIZE'] = args.llm_synthesis_system_prompt_synthesize
        
        # Handle --input-text mode for direct text analysis
        if args.input_text:
            # Read text from stdin
            import sys
            try:
                print("Enter the code to analyze (press Ctrl+D when done):", file=sys.stderr)
                text_input = sys.stdin.read()
                
                if not text_input.strip():
                    print("Error: No input provided", file=sys.stderr)
                    sys.exit(1)
                
                # Set up environment variables for the selected provider
                if args.llm_provider == 'anthropic':
                    if not args.anthropic_api_key:
                        print("Error: Anthropic API key required for Anthropic provider", file=sys.stderr)
                        sys.exit(1)
                    os.environ['INPUT_ANTHROPIC-API-KEY'] = args.anthropic_api_key
                elif args.llm_provider == 'openai':
                    if not args.openai_api_key:
                        print("Error: OpenAI API key required for OpenAI provider", file=sys.stderr)
                        sys.exit(1)
                    os.environ['INPUT_OPENAI-API-KEY'] = args.openai_api_key
                elif args.llm_provider == 'gemini':
                    if not args.gemini_api_key:
                        print("Error: Gemini API key required for Gemini provider", file=sys.stderr)
                        sys.exit(1)
                    os.environ['INPUT_GEMINI-API-KEY'] = args.gemini_api_key
                elif args.llm_provider == 'deepseek':
                    if not args.deepseek_api_key:
                        print("Error: Deepseek API key required for Deepseek provider", file=sys.stderr)
                        sys.exit(1)
                    os.environ['INPUT_DEEPSEEK-API-KEY'] = args.deepseek_api_key
                elif args.llm_provider == 'llama':
                    if not args.llama_api_key:
                        print("Error: Llama API key required for Llama provider", file=sys.stderr)
                        sys.exit(1)
                    os.environ['INPUT_LLAMA-API-KEY'] = args.llama_api_key
                
                # Set up provider kwargs
                provider_kwargs = {}
                if args.model:
                    provider_kwargs['model'] = args.model
                
                # Convert docs_dir to absolute path if provided
                docs_dir = os.path.abspath(args.docs_dir) if args.docs_dir else None
                
                # Build provider weights dictionary
                provider_weights = {
                    'anthropic': args.anthropic_weight,
                    'openai': args.openai_weight,
                    'gemini': args.gemini_weight,
                    'deepseek': args.deepseek_weight,
                    'llama': args.llama_weight
                }
                
                # Initialize the security reviewer
                reviewer = SecurityReview(
                    args.llm_provider,
                    provider_kwargs,
                    docs_dir=docs_dir,
                    voyage_key=args.voyage_api_key,
                    voyage_model=args.voyage_model,
                    multi_judge=args.multi_judge,
                    gemini_key=args.gemini_api_key,
                    provider_weights=provider_weights
                )
                
                # Analyze the input text
                analysis, cost_info = reviewer.analyze_security(text_input)
                
                # Prepare JSON output
                output = {
                    "confidence_score": analysis['confidence_score'],
                    "has_vulnerabilities": analysis['has_vulnerabilities'],
                    "summary": analysis['summary'],
                    "findings": analysis['findings']
                }
                
                # Add cost information if available
                if cost_info and cost_info.total_cost > 0:
                    output["cost_info"] = {
                        "total_cost": cost_info.total_cost,
                        "input_tokens": cost_info.input_tokens,
                        "output_tokens": cost_info.output_tokens,
                        "model": cost_info.model,
                        "provider": cost_info.provider
                    }
                
                # Output JSON to stdout
                print(json.dumps(output, indent=2))
                return
                
            except KeyboardInterrupt:
                print("\nAnalysis cancelled by user", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(f"Error during analysis: {str(e)}", file=sys.stderr)
                sys.exit(1)
        
        # Handle queue listener mode
        if args.listen_queue:
            # Validate required parameters
            if not args.amqp_url:
                print("Error: AMQP URL required for queue listener (use --amqp-url or set AMQP_URL env var)")
                sys.exit(1)
            
            # Set up environment variables for the selected provider
            if args.llm_provider == 'anthropic':
                if not args.anthropic_api_key:
                    print("Error: Anthropic API key required for Anthropic provider", file=sys.stderr)
                    sys.exit(1)
                os.environ['INPUT_ANTHROPIC-API-KEY'] = args.anthropic_api_key
            elif args.llm_provider == 'openai':
                if not args.openai_api_key:
                    print("Error: OpenAI API key required for OpenAI provider", file=sys.stderr)
                    sys.exit(1)
                os.environ['INPUT_OPENAI-API-KEY'] = args.openai_api_key
            elif args.llm_provider == 'gemini':
                if not args.gemini_api_key:
                    print("Error: Gemini API key required for Gemini provider", file=sys.stderr)
                    sys.exit(1)
                os.environ['INPUT_GEMINI-API-KEY'] = args.gemini_api_key
            elif args.llm_provider == 'deepseek':
                if not args.deepseek_api_key:
                    print("Error: Deepseek API key required for Deepseek provider", file=sys.stderr)
                    sys.exit(1)
                os.environ['INPUT_DEEPSEEK-API-KEY'] = args.deepseek_api_key
            elif args.llm_provider == 'llama':
                if not args.llama_api_key:
                    print("Error: Llama API key required for Llama provider", file=sys.stderr)
                    sys.exit(1)
                os.environ['INPUT_LLAMA-API-KEY'] = args.llama_api_key
            
            # Set up provider kwargs
            provider_kwargs = {}
            if args.model:
                provider_kwargs['model'] = args.model
            
            # Convert docs_dir to absolute path if provided
            docs_dir = os.path.abspath(args.docs_dir) if args.docs_dir else None
            
            # Build provider weights dictionary
            provider_weights = {
                'anthropic': args.anthropic_weight,
                'openai': args.openai_weight,
                'gemini': args.gemini_weight,
                'deepseek': args.deepseek_weight,
                'llama': args.llama_weight
            }
            
            # Show multi-judge mode status if enabled
            if args.multi_judge:
                print("\n" + "="*60)
                print("🤖 MULTI-JUDGE MODE ENABLED")
                print("="*60)
                print("Using weighted voting from multiple LLMs:")
                
                # Only show weights for providers that have API keys
                if args.anthropic_api_key:
                    print(f"  • Anthropic (Claude): weight {args.anthropic_weight}")
                if args.gemini_api_key:
                    print(f"  • Gemini: weight {args.gemini_weight}")
                if args.openai_api_key:
                    print(f"  • OpenAI (GPT): weight {args.openai_weight}")
                if args.deepseek_api_key:
                    print(f"  • Deepseek: weight {args.deepseek_weight}")
                if args.llama_api_key:
                    print(f"  • Llama: weight {args.llama_weight}")
                    
                print("\nThis mode provides higher confidence through cross-validation.")
                print("You will see individual results from each LLM before the final consensus.")
                print("="*60 + "\n")
            else:
                print("\n" + "="*60)
                print(f"🤖 Using single LLM provider: {args.llm_provider} with model {args.model or 'default'}")
                print("="*60 + "\n")
            
            if docs_dir:
                print(f"  Documentation directory: {docs_dir}")
            
            reviewer = SecurityReview(
                args.llm_provider,
                provider_kwargs,
                docs_dir=docs_dir,
                voyage_key=args.voyage_api_key,
                voyage_model=args.voyage_model,
                multi_judge=args.multi_judge,
                gemini_key=args.gemini_api_key,
                provider_weights=provider_weights
            )
            
            # Initialize queue listener
            print("\n🐰 Initializing RabbitMQ Queue Listener...")
            print(f"  AMQP URL: {args.amqp_url.split('@')[1] if '@' in args.amqp_url else args.amqp_url}")
            print(f"  Queue name: {args.queue_name}")
            print(f"  Response queue: {args.response_queue_name or f'{args.queue_name}_response'}")
            
            listener = QueueListener(
                amqp_url=args.amqp_url,
                queue_name=args.queue_name,
                response_queue_name=args.response_queue_name
            )
            
            # Set the security reviewer for the listener
            listener.set_security_reviewer(reviewer)
            
            # Start listening with reconnection support
            print("\n🚀 Starting queue listener with auto-reconnect...")
            listener.run_with_reconnect(max_retries=10, retry_delay=5)
            
            return
        
        # Handle commit monitoring commands
        if any([args.monitor_add, args.monitor_remove, args.monitor_list, args.monitor_check, args.monitor_continuous, args.analyze_commit]):
            # Ensure we have a GitHub token
            github_token = args.github_token
            if not github_token:
                print("Error: GitHub token required for commit monitoring")
                sys.exit(1)
                
            # Initialize commit monitor with config file if specified (use getattr for safety)
            config_file = getattr(args, 'config_file', None)
            monitor = CommitMonitor(github_token, config_file=config_file)
            
            # Handle monitor commands
            if args.monitor_add:
                print(f"Adding repository to monitoring: {args.monitor_add}")
                print(f"Branches: {', '.join(args.monitor_branches)}")
                monitor.add_repository(args.monitor_add, args.monitor_branches)
                print("✅ Repository added to monitoring")
                
            elif args.monitor_remove:
                print(f"Removing repository from monitoring: {args.monitor_remove}")
                monitor.remove_repository(args.monitor_remove)
                print("✅ Repository removed from monitoring")
                
            elif args.monitor_list:
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
                    
            elif args.monitor_check or args.monitor_continuous:
                # Initialize security reviewer for commit analysis
                provider_kwargs = {}
                if args.model:
                    provider_kwargs['model'] = args.model
                    
                docs_dir = os.path.abspath(args.docs_dir) if args.docs_dir else None
                
                # Build provider weights dictionary
                provider_weights = {
                    'anthropic': args.anthropic_weight,
                    'openai': args.openai_weight,
                    'gemini': args.gemini_weight,
                    'deepseek': args.deepseek_weight,
                    'llama': args.llama_weight
                }
                
                # Show multi-judge mode status if enabled
                if args.multi_judge:
                    print("\n" + "="*60)
                    print("🤖 MULTI-JUDGE MODE ENABLED")
                    print("="*60)
                    print("Using weighted voting from multiple LLMs:")
                    
                    # Only show weights for providers that have API keys
                    if args.anthropic_api_key:
                        print(f"  • Anthropic (Claude): weight {args.anthropic_weight}")
                    if args.gemini_api_key:
                        print(f"  • Gemini: weight {args.gemini_weight}")
                    if args.openai_api_key:
                        print(f"  • OpenAI (GPT): weight {args.openai_weight}")
                    if args.deepseek_api_key:
                        print(f"  • Deepseek: weight {args.deepseek_weight}")
                    if args.llama_api_key:
                        print(f"  • Llama: weight {args.llama_weight}")
                        
                    print("\nThis mode provides higher confidence through cross-validation.")
                    print("You will see individual results from each LLM before the final consensus.")
                    print("="*60 + "\n")
                
                reviewer = SecurityReview(
                    args.llm_provider,
                    provider_kwargs,
                    docs_dir=docs_dir,
                    voyage_key=args.voyage_api_key,
                    voyage_model=args.voyage_model,
                    multi_judge=args.multi_judge,
                    gemini_key=args.gemini_api_key,
                    provider_weights=provider_weights
                )
                
                # Initialize Telegram notifier if configured
                telegram_notifier = None
                if args.telegram_bot_token and args.telegram_chat_id:
                    try:
                        # Start web application for security findings using Gunicorn
                        host = os.environ.get('WEB_APP_HOST', '0.0.0.0')
                        port = int(os.environ.get('WEB_APP_PORT', 5000))
                        workers = int(os.environ.get('WEB_APP_WORKERS', 1))
                        
                        print(f"🌐 Starting Security Findings Web Application with Gunicorn at http://{host}:{port}")
                        print(f"👷 Workers: {workers}")
                        print(f"🔐 Google OAuth Client ID: {os.environ.get('GOOGLE_CLIENT_ID', 'Not configured')[:20]}...")
                        print(f"📧 Authorized emails: {os.environ.get('AUTHORIZED_EMAILS', 'Not configured')}")
                        print(f"🗄️  Database: {os.environ.get('DATABASE_URL', 'Not configured').split('@')[1] if '@' in os.environ.get('DATABASE_URL', '') else 'Not configured'}")
                        
                        # Start Gunicorn in a separate thread since we need to continue with monitoring
                        import threading
                        import subprocess
                        import sys
                        
                        def start_gunicorn():
                            """Start Gunicorn server in a subprocess."""
                            cmd = [
                                sys.executable, '-m', 'gunicorn',
                                '--config', 'gunicorn.conf.py',
                                'pr_security_review.web_app:create_app()'
                            ]
                            
                            try:
                                # Explicitly pass the current environment to the subprocess
                                subprocess.run(cmd, check=True, env=os.environ.copy())
                            except subprocess.CalledProcessError as e:
                                print(f"❌ Gunicorn failed to start: {e}")
                            except KeyboardInterrupt:
                                print("🔄 Gunicorn shutting down...")
                        
                        web_app_thread = threading.Thread(target=start_gunicorn)
                        web_app_thread.daemon = True
                        web_app_thread.start()
                        
                        print(f"✅ Gunicorn web server started at http://{host}:{port}")
                        
                        # Initialize Telegram notifier with GitHub token for command access
                        telegram_notifier = TelegramNotifier(
                            args.telegram_bot_token,
                            args.telegram_chat_id,
                            github_token=args.github_token
                        )
                        print("✅ Telegram notifications enabled")
                        
                        # Start polling for commands if in continuous mode
                        if args.monitor_continuous:
                            telegram_notifier.start_polling()
                            print("✅ Telegram bot is now listening for commands (e.g. /lastcommits)")
                    except Exception as e:
                        print(f"⚠️ Telegram notifications disabled: {e}")
                else:
                    print("ℹ️ Telegram notifications not configured (will create GitHub issues instead)")
                
                if args.monitor_check:
                    # One-time check
                    print("\nChecking for new commits...")
                    new_commits = monitor.get_new_commits()
                    
                    if new_commits:
                        for monitored_repo, commits in new_commits:
                            run_commit_monitor_callback(reviewer, monitored_repo, commits, telegram_notifier)
                    else:
                        print("No new commits found.")
                        
                else:  # continuous monitoring
                    # Create callback with reviewer and Telegram notifier
                    notify_clean = args.notify_clean_commits
                    callback = lambda repo, commits: run_commit_monitor_callback(
                        reviewer, repo, commits, telegram_notifier, notify_clean_commits=notify_clean
                    )
                    
                    try:
                        print("\n🤖 Monitoring repositories for new commits...")
                        if telegram_notifier and hasattr(telegram_notifier, '_polling_active') and telegram_notifier._polling_active:
                            print("📱 Telegram bot active and listening for commands (e.g. /lastcommits)")
                            
                        monitor.monitor_continuously(
                            check_interval=args.monitor_interval,
                            callback=callback
                        )
                    except KeyboardInterrupt:
                        print("\n\nStopping continuous monitoring...")
                        # Stop Telegram polling if active
                        if telegram_notifier and hasattr(telegram_notifier, 'stop_polling'):
                            telegram_notifier.stop_polling()
                            print("Telegram bot polling stopped")
                        
            elif args.analyze_commit:
                if not args.repository:
                    print("Error: --repository required when using --analyze-commit")
                    sys.exit(1)
                    
                # Initialize security reviewer
                provider_kwargs = {}
                if args.model:
                    provider_kwargs['model'] = args.model
                    
                docs_dir = os.path.abspath(args.docs_dir) if args.docs_dir else None
                
                # Show multi-judge mode status if enabled
                if args.multi_judge:
                    print("\n" + "="*60)
                    print("🤖 MULTI-JUDGE MODE ENABLED")
                    print("="*60)
                    print("Using weighted voting from multiple LLMs:")
                    print("  • Anthropic (Claude): weight 1.0")
                    print("  • Gemini: weight 0.5") 
                    print("  • OpenAI (GPT): weight 0.4")
                    print("\nThis mode provides higher confidence through cross-validation.")
                    print("You will see individual results from each LLM before the final consensus.")
                    print("="*60 + "\n")
                
                reviewer = SecurityReview(
                    args.llm_provider,
                    provider_kwargs,
                    docs_dir=docs_dir,
                    voyage_key=args.voyage_api_key,
                    voyage_model=args.voyage_model,
                    multi_judge=args.multi_judge,
                    gemini_key=args.gemini_api_key
                )
                
                print(f"\nAnalyzing commit {args.analyze_commit[:7]} in {args.repository}")
                
                try:
                    analysis, cost_info = reviewer.analyze_commit(args.repository, args.analyze_commit)
                    
                    # Print results
                    if analysis['has_vulnerabilities']:
                        print(f"\n⚠️ Security issues detected (confidence: {analysis['confidence_score']}%)")
                        print(f"\nSummary:\n{analysis['summary']}")
                        
                        if analysis['findings']:
                            print("\nDetailed Findings:")
                            for finding in analysis['findings']:
                                print(f"\n{finding['severity']} Severity Issue")
                                print(f"Description: {finding['description']}")
                                print(f"Recommendation: {finding['recommendation']}")
                                print(f"Confidence: {finding['confidence']}%")
                    else:
                        print("\n✅ No security vulnerabilities detected")
                        
                    if cost_info and cost_info.total_cost > 0:
                        print(f"\nCost Information: {cost_info}")
                        
                except Exception as e:
                    print(f"Error analyzing commit: {str(e)}")
                    sys.exit(1)
                    
            return
        
        # Run as GitHub App if specified
        if args.github_app:
            run_github_app(
                port=args.port,
                app_id=args.github_app_id,
                private_key=args.github_private_key,
                webhook_secret=args.github_webhook_secret,
                private_key_path=args.github_private_key_path,
                anthropic_key=args.anthropic_api_key,
                openai_key=args.openai_api_key,
                voyage_key=args.voyage_api_key,
                llm_provider=args.llm_provider,
                model=args.model,
                docs_dir=args.docs_dir
            )
            return
            
        # Check if running as GitHub Action
        event_path = os.environ.get('GITHUB_EVENT_PATH')
        
        # Parse provider configuration
        provider_name = os.environ.get('INPUT_LLM-PROVIDER', 'anthropic')
        provider_kwargs = {}
        
        if provider_name == 'anthropic':
            if model := os.environ.get('INPUT_CLAUDE-MODEL'):
                provider_kwargs['model'] = model
        elif provider_name == 'openai':
            if model := os.environ.get('INPUT_GPT-MODEL'):
                provider_kwargs['model'] = model
        
        if event_path:
            # Running as GitHub Action
            with open(event_path, 'r') as f:
                event = json.load(f)
                
            # Convert docs_dir to absolute path if provided
            docs_dir = os.path.abspath(os.environ.get('INPUT_DOCS-DIR')) if os.environ.get('INPUT_DOCS-DIR') else None
            reviewer = SecurityReview(
                provider_name,
                provider_kwargs,
                docs_dir=docs_dir,
                voyage_key=os.environ.get('INPUT_VOYAGE-API-KEY'),
                voyage_model=os.environ.get('INPUT_VOYAGE-MODEL')
            )
            repo = reviewer.github.get_repo(event['repository']['full_name'])
            pr = repo.get_pull(event['pull_request']['number'])
            
            # Get PR changes for analysis
            changes = reviewer.get_pr_changes(pr)
            
        else:
            # Running as CLI tool
            if not args.multi_judge and args.llm_provider not in ['anthropic', 'openai', 'gemini', 'deepseek', 'llama']:
                print("Error: --llm-provider must be 'anthropic', 'openai', 'gemini', 'deepseek', or 'llama'")
                sys.exit(1)
                
            # Set up environment variables based on selected provider or multi-judge mode
            os.environ['INPUT_GITHUB-TOKEN'] = args.github_token
            
            if args.multi_judge:
                # Multi-judge mode - set all API keys if provided
                if args.anthropic_api_key:
                    os.environ['INPUT_ANTHROPIC-API-KEY'] = args.anthropic_api_key
                if args.openai_api_key:
                    os.environ['INPUT_OPENAI-API-KEY'] = args.openai_api_key
                if args.gemini_api_key:
                    os.environ['INPUT_GEMINI-API-KEY'] = args.gemini_api_key
                    
                # Check that at least Anthropic key is provided (required for synthesis)
                if not args.anthropic_api_key:
                    print("Error: Anthropic API key is required for multi-judge mode (used for synthesis)")
                    sys.exit(1)
            else:
                # Single provider mode
                if args.llm_provider == 'anthropic':
                    if not args.anthropic_api_key:
                        print("Error: Anthropic API key required for Anthropic provider")
                        sys.exit(1)
                    os.environ['INPUT_ANTHROPIC-API-KEY'] = args.anthropic_api_key
                elif args.llm_provider == 'openai':
                    if not args.openai_api_key:
                        print("Error: OpenAI API key required for OpenAI provider")
                        sys.exit(1)
                    os.environ['INPUT_OPENAI-API-KEY'] = args.openai_api_key
                elif args.llm_provider == 'gemini':
                    if not args.gemini_api_key:
                        print("Error: Gemini API key required for Gemini provider")
                        sys.exit(1)
                    os.environ['INPUT_GEMINI-API-KEY'] = args.gemini_api_key
            
            if args.model:
                provider_kwargs['model'] = args.model
            
            # Convert docs_dir to absolute path if provided
            docs_dir = os.path.abspath(args.docs_dir) if args.docs_dir else None
            
            # Build provider weights dictionary
            provider_weights = {
                'anthropic': args.anthropic_weight,
                'openai': args.openai_weight,
                'gemini': args.gemini_weight,
                'deepseek': args.deepseek_weight,
                'llama': args.llama_weight
            }
            
            # Show multi-judge mode status clearly
            if args.multi_judge:
                print("\n" + "="*60)
                print("🤖 MULTI-JUDGE MODE ENABLED")
                print("="*60)
                print("Using weighted voting from multiple LLMs:")
                
                # Only show weights for providers that have API keys
                if args.anthropic_api_key:
                    print(f"  • Anthropic (Claude): weight {args.anthropic_weight}")
                if args.gemini_api_key:
                    print(f"  • Gemini: weight {args.gemini_weight}")
                if args.openai_api_key:
                    print(f"  • OpenAI (GPT): weight {args.openai_weight}")
                if args.deepseek_api_key:
                    print(f"  • Deepseek: weight {args.deepseek_weight}")
                if args.llama_api_key:
                    print(f"  • Llama: weight {args.llama_weight}")
                    
                print("\nThis mode provides higher confidence through cross-validation.")
                print("You will see individual results from each LLM before the final consensus.")
                print("="*60 + "\n")
            
            reviewer = SecurityReview(
                args.llm_provider,
                provider_kwargs,
                docs_dir=docs_dir,
                voyage_key=args.voyage_api_key,
                voyage_model=args.voyage_model,
                multi_judge=args.multi_judge,
                gemini_key=args.gemini_api_key,
                provider_weights=provider_weights
            )
            
            # Check if we're analyzing a file, recent PRs, or a specific PR
            if args.file:
                # Analyze a single file
                try:
                    repo_name, branch, file_path = parse_file_url(args.file)
                    print(f"\nAnalyzing file: {file_path}")
                    print(f"Repository: {repo_name}")
                    print(f"Branch: {branch}")
                    
                    # Get file content
                    changes = reviewer.get_file_content(repo_name, branch, file_path)
                    
                    # No PR to comment on
                    pr = None
                except ValueError as e:
                    print(f"Error parsing file URL: {str(e)}")
                    sys.exit(1)
            elif args.recent_prs:
                # Analyze recent PRs from a repository
                try:
                    repo_name = args.recent_prs
                    pr_count = args.pr_count
                    print(f"\nAnalyzing last {pr_count} PRs from repository: {repo_name}")
                    
                    # Get recent PRs
                    recent_prs = reviewer.get_recent_prs(repo_name, pr_count)
                    
                    if not recent_prs:
                        print(f"No PRs found in repository {repo_name}")
                        sys.exit(0)
                    
                    print(f"Found {len(recent_prs)} PRs to analyze:")
                    for pr in recent_prs:
                        print(f"  - PR #{pr.number}: {pr.title}")
                    
                    # Analyze each PR and collect results
                    all_results = []
                    total_input_tokens = 0
                    total_output_tokens = 0
                    total_cost_amount = 0.0
                    last_model = "unknown"
                    last_provider = "unknown"
                    
                    for i, pr in enumerate(recent_prs, 1):
                        print(f"\n[{i}/{len(recent_prs)}] Analyzing PR #{pr.number}: {pr.title}")
                        
                        try:
                            changes = reviewer.get_pr_changes(pr)
                            if not changes.strip():
                                print(f"  No code changes found in PR #{pr.number}, skipping...")
                                continue
                                
                            analysis, cost_info = reviewer.analyze_security(changes)
                            
                            # Accumulate costs
                            if cost_info:
                                total_input_tokens += cost_info.input_tokens
                                total_output_tokens += cost_info.output_tokens
                                total_cost_amount += cost_info.total_cost
                                last_model = cost_info.model
                                last_provider = cost_info.provider
                            
                            all_results.append({
                                'pr': pr,
                                'analysis': analysis,
                                'cost_info': cost_info
                            })
                            
                            # Print individual result
                            if analysis['has_vulnerabilities']:
                                print(f"  ⚠️ Security issues detected (confidence: {analysis['confidence_score']}%)")
                            else:
                                print(f"  ✅ No security issues detected")
                                
                        except Exception as e:
                            print(f"  ❌ Error analyzing PR #{pr.number}: {str(e)}")
                            continue
                    
                    # No single PR to comment on for batch analysis
                    pr = None
                    changes = None  # Will handle output differently for batch analysis
                    
                except Exception as e:
                    print(f"Error analyzing recent PRs: {str(e)}")
                    sys.exit(1)
            elif args.pr_url:
                # Analyze a specific PR
                try:
                    repo_name, pr_number = parse_pr_url(args.pr_url)
                    print(f"\nAnalyzing PR #{pr_number}")
                    print(f"Repository: {repo_name}")
                    
                    # Get PR and changes
                    repo = reviewer.github.get_repo(repo_name)
                    pr = repo.get_pull(pr_number)
                    changes = reviewer.get_pr_changes(pr)
                except ValueError as e:
                    print(f"Error parsing PR URL: {str(e)}")
                    sys.exit(1)
            else:
                print("Error: Either --file, --recent-prs, or pr_url must be provided")
                sys.exit(1)
        
        # Handle different analysis types
        if args.recent_prs and not event_path:
            # Handle batch analysis results
            if not all_results:
                print("\n✅ No PRs with code changes were found to analyze.")
                return
                
            # Print summary report for batch analysis
            print(f"\n🛡️ Batch Security Review Report")
            print(f"Analyzed {len(all_results)} PRs from {repo_name}")
            
            if total_cost_amount > 0:
                # Create a total cost info object for display
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
                    
                    if analysis['findings']:
                        for finding in analysis['findings']:
                            print(f"    - {finding['severity']}: {finding['description']}")
                            
                print(f"\n::warning::Security vulnerabilities detected in {len(vulnerable_prs)} out of {len(all_results)} PRs")
            else:
                print(f"\n✅ No security vulnerabilities detected in any of the {len(all_results)} analyzed PRs.")
                print("::notice::No security vulnerabilities detected in batch analysis")
        else:
            # Handle single analysis (file or specific PR)
            analysis, cost_info = reviewer.analyze_security(changes)
            
            # Handle report output
            if event_path or (args.post_comment and pr is not None):
                # Post comment on PR if running as GitHub Action or --post-comment is specified
                # and we have a PR to comment on, but only if vulnerabilities were found
                if analysis['has_vulnerabilities']:
                    reviewer.create_report_comment(pr, analysis, cost_info)
            else:
                # Print report to console when running as CLI without --post-comment
                if analysis['confidence_score'] == 0:
                    print("\n⚠️ Analysis failed or returned unexpected results.")
                elif analysis['has_vulnerabilities']:
                    print("\n🛡️ Security Review Report")
                    # print(f"\nConfidence Score: {analysis['confidence_score']}%")
                    print(f"Vulnerabilities Detected: Yes")
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
                    # if cost_info and cost_info.total_cost > 0:
                    #     print(f"\nCost Information: {cost_info}")
            
            # Set action status
            if analysis['has_vulnerabilities']:
                print(f"::warning::Security vulnerabilities detected with {analysis['confidence_score']}% confidence")
            else:
                print("::notice::No security vulnerabilities detected")
            
    except ValueError as e:
        print(f"::error::{str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"::error::Action failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
