"""
Telegram notification module for security findings.
"""

import os
import re
import requests
import json
import time
import threading
import csv
import zipfile
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any, Tuple
from .commit_monitor import CommitInfo, CommitMonitor
from .findings_server import store_security_finding
from .database import get_database_manager


class TelegramNotifier:
    """Handles sending security findings to Telegram."""
    
    # Command handlers dictionary
    COMMANDS = {}
    
    def __init__(self, bot_token: Optional[str] = None, chat_id: Optional[str] = None, github_token: Optional[str] = None):
        """
        Initialize the Telegram notifier.
        
        Args:
            bot_token: Telegram bot token (falls back to TELEGRAM_BOT_TOKEN env var)
            chat_id: Telegram chat ID (falls back to TELEGRAM_CHAT_ID env var)
            github_token: GitHub token for API access (falls back to GITHUB_TOKEN env var)
        """
        self.bot_token = bot_token or os.environ.get('TELEGRAM_BOT_TOKEN')
        self.chat_id = chat_id or os.environ.get('TELEGRAM_CHAT_ID')
        self.chat_id_good = os.environ.get('TELEGRAM_CHAT_ID_GOOD')  # Channel for clean commits
        self.github_token = github_token or os.environ.get('GITHUB_TOKEN')
        self._polling_active = False
        self._polling_thread = None
        self._last_update_id = 0
        
        if not self.bot_token or not self.chat_id:
            raise ValueError("Telegram bot token and chat ID are required")
            
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}"
        
        # Register command handlers
        self.register_command("lastcommits", self.handle_lastcommits_command)
        self.register_command("listrepos", self.handle_listrepos_command)
        self.register_command("check", self.handle_check_pr_command)
        self.register_command("export", self.handle_export_command)
        self.register_command("help", self.handle_help_command)
        
    def split_message(self, text: str, max_length: int = 4000) -> List[str]:
        """
        Split a long message into chunks that fit within Telegram's message limit.
        
        Args:
            text: The message text to split
            max_length: Maximum length per message (default 4000 to leave some buffer)
            
        Returns:
            List of message chunks
        """
        if len(text) <= max_length:
            return [text]
            
        chunks = []
        current_chunk = ""
        
        # Try to split by double newlines first (between sections)
        sections = text.split('\n\n')
        
        for section in sections:
            # If adding this section would exceed the limit
            if len(current_chunk) + len(section) + 2 > max_length:
                # If current chunk has content, save it
                if current_chunk:
                    chunks.append(current_chunk.strip())
                    current_chunk = ""
                
                # If the section itself is too long, split it by lines
                if len(section) > max_length:
                    lines = section.split('\n')
                    for line in lines:
                        if len(current_chunk) + len(line) + 1 > max_length:
                            if current_chunk:
                                chunks.append(current_chunk.strip())
                                current_chunk = ""
                            # If a single line is too long, force split it
                            if len(line) > max_length:
                                for i in range(0, len(line), max_length):
                                    chunks.append(line[i:i+max_length])
                            else:
                                current_chunk = line
                        else:
                            if current_chunk:
                                current_chunk += '\n'
                            current_chunk += line
                else:
                    current_chunk = section
            else:
                # Add section to current chunk
                if current_chunk:
                    current_chunk += '\n\n'
                current_chunk += section
        
        # Don't forget the last chunk
        if current_chunk:
            chunks.append(current_chunk.strip())
            
        return chunks
    
    def send_message(self, text: str, parse_mode: str = "HTML", chat_id: Optional[str] = None) -> bool:
        """
        Send a message to the configured Telegram chat.
        
        Args:
            text: Message text to send
            parse_mode: Parse mode for formatting (default: HTML)
            chat_id: Optional chat ID to send to (defaults to self.chat_id)
            
        Returns:
            bool: True if message was sent successfully
        """
        # Use provided chat_id or fall back to default
        target_chat_id = chat_id or self.chat_id
        
        # Split message if it's too long
        chunks = self.split_message(text)
        
        all_successful = True
        for i, chunk in enumerate(chunks):
            try:
                response = requests.post(
                    f"{self.api_url}/sendMessage",
                    json={
                        "chat_id": target_chat_id,
                        "text": chunk,
                        "parse_mode": parse_mode,
                        "disable_web_page_preview": False  # Enable preview for the link
                    }
                )
                response.raise_for_status()
                
                # Small delay between messages to avoid rate limiting
                if i < len(chunks) - 1:
                    time.sleep(0.5)
                    
            except Exception as e:
                print(f"Error sending Telegram message: {e}")
                print(f"Response content: {response.content if 'response' in locals() else 'No response'}")
                # Fall back to HTML mode if MarkdownV2 fails
                if parse_mode == "MarkdownV2":
                    print("Retrying with HTML format...")
                    return self.send_message(self.convert_to_html(text), "HTML", chat_id)
                all_successful = False
                
        return all_successful
    
    def send_document(self, file_path: str, filename: str, caption: str = None, chat_id: Optional[str] = None) -> bool:
        """
        Send a document file to the configured Telegram chat.
        
        Args:
            file_path: Path to the file to send
            filename: Name to display for the file
            caption: Optional caption for the file
            chat_id: Optional chat ID to send to (defaults to self.chat_id)
            
        Returns:
            bool: True if file was sent successfully
        """
        # Use provided chat_id or fall back to default
        target_chat_id = chat_id or self.chat_id
        
        try:
            with open(file_path, 'rb') as file:
                files = {
                    'document': (filename, file, 'application/zip')
                }
                
                data = {
                    'chat_id': target_chat_id
                }
                
                if caption:
                    data['caption'] = caption
                    data['parse_mode'] = 'HTML'
                
                response = requests.post(
                    f"{self.api_url}/sendDocument",
                    files=files,
                    data=data
                )
                response.raise_for_status()
                
                return True
                
        except Exception as e:
            print(f"Error sending Telegram document: {e}")
            print(f"Response content: {response.content if 'response' in locals() else 'No response'}")
            return False
    
    def send_message_to_channels(self, text: str, repo_telegram_channel_id: Optional[str] = None, 
                                notify_default_channel: bool = True, parse_mode: str = "HTML") -> bool:
        """
        Send a message to the appropriate Telegram channels based on repository configuration.
        
        Args:
            text: Message text to send
            repo_telegram_channel_id: Optional repository-specific channel ID
            notify_default_channel: Whether to also send to the default channel
            parse_mode: Parse mode for formatting (default: HTML)
            
        Returns:
            bool: True if all messages were sent successfully
        """
        all_successful = True
        
        # Determine which channels to send to
        channels_to_notify = []
        
        if repo_telegram_channel_id:
            # Send to repo-specific channel
            channels_to_notify.append(repo_telegram_channel_id)
            
        if notify_default_channel:
            # Send to default channel
            channels_to_notify.append(self.chat_id)
            
        # If no repo-specific channel and notify_default_channel is False, still send to default
        if not channels_to_notify:
            channels_to_notify.append(self.chat_id)
            
        # Remove duplicates while preserving order
        unique_channels = []
        for channel in channels_to_notify:
            if channel not in unique_channels:
                unique_channels.append(channel)
        
        # Send to each channel
        for channel_id in unique_channels:
            try:
                success = self.send_message(text, parse_mode, channel_id)
                if not success:
                    all_successful = False
                    print(f"Failed to send message to channel {channel_id}")
                else:
                    print(f"Successfully sent message to channel {channel_id}")
            except Exception as e:
                print(f"Error sending message to channel {channel_id}: {e}")
                all_successful = False
                
        return all_successful
            
    def convert_to_html(self, markdown_text: str) -> str:
        """Convert markdown text to HTML for Telegram."""
        # Replace markdown links with HTML links
        html_text = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2">\1</a>', markdown_text)
        
        # Replace bold
        html_text = re.sub(r'\*(.+?)\*', r'<b>\1</b>', html_text)
        
        # Replace italic
        html_text = re.sub(r'_(.+?)_', r'<i>\1</i>', html_text)
        
        # Replace code
        html_text = re.sub(r'`(.+?)`', r'<code>\1</code>', html_text)
        
        return html_text
            
    def format_security_finding(self, repo_name: str, commit_info: CommitInfo, analysis: Dict, cost_info=None) -> Dict:
        """
        Format a security finding for Telegram using findings server for detailed content.
        
        Args:
            repo_name: Repository name
            commit_info: Commit information
            analysis: Security analysis results
            cost_info: Optional cost information for the analysis
            
        Returns:
            Dict containing:
            - short_message: Formatted short message for Telegram
            - finding_url: URL to view the full details
        """
        # Escape special characters for HTML
        def escape_html(text: str) -> str:
            return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        
        # Generate URL for detailed findings
        finding_url = store_security_finding(repo_name, commit_info, analysis)
        
        # Create a short message with a link to the detailed findings
        severity_counts = {}
        for finding in analysis['findings']:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        severity_summary = []
        for severity, count in severity_counts.items():
            emoji = {
                'HIGH': '🔴',
                'MEDIUM': '🟠',
                'LOW': '🟡'
            }.get(severity, '⚪')
            severity_summary.append(f"{emoji} {count} {severity}")
        
        message = f"🚨 <b>Security Alert</b>\n\n"
        message += f"<b>Repository:</b> <code>{repo_name}</code>\n"
        message += f"<b>Branch:</b> <code>{commit_info.branch}</code>\n"
        message += f'<b>Commit:</b> <a href="{commit_info.url}">{commit_info.sha[:7]}</a>\n'
        message += f"<b>Confidence:</b> {analysis['confidence_score']}%\n"
        
        # Add commit message (shortened)
        commit_msg = escape_html(commit_info.message.split('\n')[0])  # Just first line
        if len(commit_msg) > 80:
            commit_msg = commit_msg[:80] + "..."
        message += f"<b>Commit Message:</b> {commit_msg}\n\n"
        
        # Add severity summary
        if severity_summary:
            message += f"<b>Issues Found:</b> {' | '.join(severity_summary)}\n\n"
        
        # Add summary (shortened)
        summary = escape_html(analysis['summary'])
        if len(summary) > 200:
            summary = summary[:200] + "..."
        message += f"<b>Summary:</b>\n{summary}\n\n"
        
        # Add cost information if available
        if cost_info:
            message += f"<b>Analysis Cost:</b> ${cost_info.total_cost:.4f}\n"
            
            # If multi-judge details are available, show individual LLM costs
            if 'multi_judge_details' in analysis and analysis['multi_judge_details'].get('enabled'):
                message += f"  • Total tokens: {cost_info.input_tokens:,} in / {cost_info.output_tokens:,} out\n"
                # Note: Individual LLM costs would need to be passed separately
                # For now, just show that multi-judge was used
                message += f"  • Used {len(analysis['multi_judge_details']['providers'])} LLMs with weighted voting\n"
        
        message += f'\n<a href="{finding_url}">View Detailed Security Report</a>'
        
        return {
            'short_message': message,
            'finding_url': finding_url
        }
        
    def send_security_finding(self, repo_name: str, commit_info: CommitInfo, analysis: Dict, cost_info=None, 
                             repo_telegram_channel_id: Optional[str] = None, notify_default_channel: bool = True) -> bool:
        """
        Send a security finding to Telegram.
        
        Args:
            repo_name: Repository name
            commit_info: Commit information
            analysis: Security analysis results
            cost_info: Optional cost information for the analysis
            repo_telegram_channel_id: Optional repository-specific channel ID
            notify_default_channel: Whether to also notify the default channel
            
        Returns:
            bool: True if message was sent successfully
        """
        # Format the message and get finding URL
        result = self.format_security_finding(repo_name, commit_info, analysis, cost_info)
        
        # Send the short message with a link to detailed findings
        return self.send_message_to_channels(
            result['short_message'], 
            repo_telegram_channel_id=repo_telegram_channel_id, 
            notify_default_channel=notify_default_channel
        )
        
    def format_clean_commit(self, repo_name: str, commit_info: CommitInfo, analysis: Dict = None, cost_info=None) -> str:
        """
        Format a message for a commit that has been reviewed and found clean.
        
        Args:
            repo_name: Repository name
            commit_info: Commit information
            analysis: Optional analysis results (for multi-judge details)
            cost_info: Optional cost information
            
        Returns:
            str: Formatted message for a clean commit
        """
        # Use HTML format to avoid excessive escaping
        message = "✅ <b>Clean Commit</b>\n\n"
        message += f"<b>Repository:</b> <code>{repo_name}</code>\n"
        message += f"<b>Branch:</b> <code>{commit_info.branch}</code>\n"
        message += f'<b>Commit:</b> <a href="{commit_info.url}">{commit_info.sha[:7]}</a>\n'
        message += f"<b>Author:</b> {commit_info.author}\n"
        
        # Add commit message (shortened)
        commit_msg = commit_info.message.split('\n')[0]  # Just first line
        if len(commit_msg) > 80:
            commit_msg = commit_msg[:80] + "..."
        # Escape HTML special chars
        commit_msg = commit_msg.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        message += f"<b>Commit Message:</b> {commit_msg}\n\n"
        
        message += "This commit has been reviewed and no security vulnerabilities were detected.\n"
        
        # Add cost information if available
        if cost_info:
            message += f"\n<b>Analysis Cost:</b> ${cost_info.total_cost:.4f}\n"
            
            # If multi-judge details are available, show individual costs and results
            if analysis and 'multi_judge_details' in analysis and analysis['multi_judge_details'].get('enabled'):
                message += f"  • Total tokens: {cost_info.input_tokens:,} in / {cost_info.output_tokens:,} out\n"
                message += f"  • Used {len(analysis['multi_judge_details']['providers'])} LLMs with weighted voting\n"
                
                # Show individual LLM costs
                message += "\n<b>Cost Breakdown:</b>\n"
                for provider in analysis['multi_judge_details']['providers']:
                    result = analysis['multi_judge_details']['individual_results'].get(provider, {})
                    provider_cost = result.get('cost', 0.0)
                    message += f"  • <b>{provider.capitalize()}:</b> ${provider_cost:.4f}\n"
                
                # Show individual LLM results (which voted NO)
                message += "\n<b>Individual LLM Results:</b>\n"
                for provider in analysis['multi_judge_details']['providers']:
                    result = analysis['multi_judge_details']['individual_results'].get(provider, {})
                    vote = "✅" if not result.get('has_vulnerabilities', True) else "⚠️"
                    message += f"  • <b>{provider.capitalize()}:</b> {vote} (confidence: {result.get('confidence_score', 0)}%)\n"
        
        return message
        
    def send_clean_commit(self, repo_name: str, commit_info: CommitInfo, analysis: Dict = None, cost_info=None) -> bool:
        """
        Send a notification for a clean commit (no vulnerabilities found).
        
        Args:
            repo_name: Repository name
            commit_info: Commit information
            analysis: Optional analysis results (for multi-judge details)
            cost_info: Optional cost information
            
        Returns:
            bool: True if message was sent successfully
        """
        # Format the message
        message = self.format_clean_commit(repo_name, commit_info, analysis, cost_info)
        
        # Send to the GOOD channel if configured, otherwise to the default chat
        chat_id_to_use = self.chat_id_good if self.chat_id_good else self.chat_id
        
        # Send the message using HTML parse mode
        return self.send_message(message, parse_mode="HTML", chat_id=chat_id_to_use)
        
    # Command registration and handling
    
    @classmethod
    def register_command(cls, command_name: str, handler: Callable) -> None:
        """
        Register a command handler.
        
        Args:
            command_name: Name of the command (without /)
            handler: Handler function to call
        """
        cls.COMMANDS[command_name] = handler
        
    def handle_command(self, message: Dict) -> None:
        """
        Process and handle a command from a Telegram message.
        
        Args:
            message: Telegram message object
        """
        if 'text' not in message:
            return
            
        text = message['text']
        chat_id = message.get('chat', {}).get('id')
        chat_type = message.get('chat', {}).get('type', '')
        username = message.get('from', {}).get('username', '')
        
        # Check if this is a DM from the authorized user
        is_authorized_dm = (
            chat_type == 'private' and 
            username == 'fredrik0x'
        )
        
        # Check if this is the configured chat
        is_configured_chat = str(chat_id) == str(self.chat_id)
        
        # Only process messages in the configured chat OR authorized DMs
        if not (is_configured_chat or is_authorized_dm):
            return
            
        if not text.startswith('/'):
            return
            
        # Extract command and arguments
        parts = text.split()
        command = parts[0][1:]  # Remove the leading /
        args = parts[1:] if len(parts) > 1 else []
        
        # For DMs, only allow the /check command
        if is_authorized_dm and not is_configured_chat:
            if command != 'check':
                self.send_message("❌ Only the /check command is available in DMs.", chat_id=str(chat_id))
                return
        
        # Export command is restricted to the main configured chat only
        if command == 'export' and not is_configured_chat:
            self.send_message("❌ The /export command is only available in the main monitoring channel.", chat_id=str(chat_id))
            return
        
        # Find and call the handler
        handler = self.COMMANDS.get(command)
        if handler:
            try:
                # Handler methods are instance methods, so don't pass self explicitly
                response = handler(args, message)
                if response:
                    # Send response to the same chat where the command came from
                    target_chat_id = str(chat_id) if is_authorized_dm else None
                    self.send_message(response, chat_id=target_chat_id)
            except Exception as e:
                error_msg = f"❌ Error executing command /{command}: {str(e)}"
                print(error_msg)
                # Send error to the same chat where the command came from
                target_chat_id = str(chat_id) if is_authorized_dm else None
                self.send_message(error_msg, chat_id=target_chat_id)
                
    def handle_listrepos_command(self, args: List[str], message: Dict) -> str:
        """
        Handle the /listrepos command to list all monitored repositories.
        
        Args:
            args: Command arguments
            message: Full message object
            
        Returns:
            str: Response message with list of repositories
        """
        if not self.github_token:
            return "❌ GitHub token not configured. Cannot retrieve repositories."
            
        try:
            # Initialize commit monitor
            monitor = CommitMonitor(self.github_token)
            
            # Get monitored repositories
            repos = monitor.list_monitored_repositories()
            
            if not repos:
                return "No repositories are currently being monitored."
                
            # Format response more compactly
            response = f"<b>Monitored Repositories</b> ({len(repos)} total)\n\n"
            
            for i, repo_info in enumerate(repos, 1):
                repo_name = repo_info['repository']
                branches = repo_info['branches']
                
                # More compact format
                response += f"{i}. <code>{repo_name}</code>\n"
                response += f"   Branches: <code>{', '.join(branches)}</code>\n"
                
            return response
        except Exception as e:
            return f"❌ Error retrieving repositories: {str(e)}"
    
    def handle_lastcommits_command(self, args: List[str], message: Dict) -> str:
        """
        Handle the /lastcommits command.
        
        Args:
            args: Command arguments
            message: Full message object
            
        Returns:
            str: Response message
        """
        if not self.github_token:
            return "❌ GitHub token not configured. Cannot retrieve commits."
            
        try:
            # Initialize commit monitor
            monitor = CommitMonitor(self.github_token)
            
            # Get monitored repositories
            repos = monitor.list_monitored_repositories()
            
            if not repos:
                return "No repositories are currently being monitored."
                
            # Count total commits
            total_commits = sum(len(repo['last_commits']) for repo in repos)
            
            # Format response more compactly
            response = f"<b>Latest Commits</b> ({total_commits} tracked)\n\n"
            
            for repo_info in repos:
                repo_name = repo_info['repository']
                
                if not repo_info['last_commits']:
                    response += f"<code>{repo_name}</code> - No commits tracked yet\n"
                    continue
                
                response += f"<b>{repo_name}</b>\n"
                    
                for branch, sha in repo_info['last_commits'].items():
                    # Get repository object to get commit details
                    try:
                        repo = monitor.github.get_repo(repo_name)
                        commit = repo.get_commit(sha)
                        
                        # Format commit information more compactly
                        author = commit.commit.author.name if commit.commit.author else "Unknown"
                        # Shorten author name if too long
                        if len(author) > 20:
                            author = author[:17] + "..."
                        
                        date = commit.commit.author.date.strftime("%m/%d %H:%M") if commit.commit.author and commit.commit.author.date else "Unknown"
                        msg = commit.commit.message.split('\n')[0]  # Just the first line
                        if len(msg) > 50:
                            msg = msg[:47] + "..."
                        # Escape HTML special chars
                        msg = msg.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                            
                        # One-line format per commit
                        response += f'  • <code>{branch}</code>: <a href="{commit.html_url}">{sha[:7]}</a> - {msg}\n'
                        response += f'    {author} ({date})\n'
                    except Exception as e:
                        response += f"  • <code>{branch}</code>: {sha[:7]} - ❌ Error\n"
                
                response += "\n"  # Single newline between repos
                        
            return response.strip()
        except Exception as e:
            return f"❌ Error retrieving commits: {str(e)}"
    
    def handle_check_pr_command(self, args: List[str], message: Dict) -> str:
        """
        Handle the /check command to analyze a specific PR or commit.
        
        Args:
            args: Command arguments (should contain PR/commit URL or repo + SHA)
            message: Full message object
            
        Returns:
            str: Response message with analysis results
        """
        # Check if URL or arguments were provided
        if not args:
            return ("❌ Please provide a PR URL, commit URL, or repository + commit SHA.\n"
                    "Usage examples:\n"
                    "  • /check https://github.com/owner/repo/pull/123\n"
                    "  • /check https://github.com/owner/repo/commit/abc123\n"
                    "  • /check owner/repo abc123")
            
        url_or_repo = args[0]
        
        # Determine if this is a PR, commit URL, or repo + SHA format
        pr_match = re.match(r"https?://github\.com/([^/]+/[^/]+)/pull/(\d+)", url_or_repo)
        commit_url_match = re.match(r"https?://github\.com/([^/]+/[^/]+)/commit/([a-fA-F0-9]+)", url_or_repo)
        repo_match = re.match(r"^([^/]+/[^/]+)$", url_or_repo)
        
        if pr_match:
            # PR URL format
            repo_name = pr_match.group(1)
            pr_number = int(pr_match.group(2))
            is_pr = True
            commit_sha = None
            url = url_or_repo
        elif commit_url_match:
            # Commit URL format
            repo_name = commit_url_match.group(1)
            commit_sha = commit_url_match.group(2)
            is_pr = False
            pr_number = None
            url = url_or_repo
        elif repo_match and len(args) >= 2:
            # Repo + SHA format
            repo_name = url_or_repo
            commit_sha = args[1]
            # Validate SHA format
            if not re.match(r"^[a-fA-F0-9]+$", commit_sha):
                return "❌ Invalid commit SHA format. Expected hexadecimal string."
            is_pr = False
            pr_number = None
            url = f"https://github.com/{repo_name}/commit/{commit_sha}"
        else:
            return ("❌ Invalid format. Expected:\n"
                    "  • PR URL: https://github.com/owner/repo/pull/123\n"
                    "  • Commit URL: https://github.com/owner/repo/commit/abc123\n"
                    "  • Repo + SHA: owner/repo abc123")
            
        if not self.github_token:
            return "❌ GitHub token not configured. Cannot analyze."
            
        # Send initial processing message to the same chat where command was initiated
        chat_id = message.get('chat', {}).get('id')
        chat_type = message.get('chat', {}).get('type', '')
        username = message.get('from', {}).get('username', '')
        
        # Check if this is a DM from the authorized user
        is_authorized_dm = (
            chat_type == 'private' and 
            username == 'fredrik0x'
        )
        
        # Determine target chat for the processing message
        target_chat_id = str(chat_id) if is_authorized_dm else None
        
        if is_pr:
            self.send_message("🔍 Analyzing PR... This may take a moment.", chat_id=target_chat_id)
        else:
            self.send_message("🔍 Analyzing commit... This may take a moment.", chat_id=target_chat_id)
        
        try:
            # Import required modules
            from .__main__ import SecurityReview
            from github import Github, Auth
            
            # Initialize security reviewer
            # Use environment variables for API keys
            provider_name = os.environ.get('LLM_PROVIDER', 'anthropic')
            multi_judge = os.environ.get('MULTI_JUDGE', '').lower() in ('true', 'yes', '1')
            
            provider_kwargs = {}
            if provider_name == 'anthropic':
                if model := os.environ.get('CLAUDE_MODEL'):
                    provider_kwargs['model'] = model
            elif provider_name == 'openai':
                if model := os.environ.get('GPT_MODEL'):
                    provider_kwargs['model'] = model
                    
            # Set up document directory if specified
            docs_dir = os.environ.get('DOCS_DIR')
            if docs_dir:
                docs_dir = os.path.abspath(docs_dir)
                
            reviewer = SecurityReview(
                provider_name,
                provider_kwargs,
                docs_dir=docs_dir,
                voyage_key=os.environ.get('VOYAGE_API_KEY'),
                voyage_model=os.environ.get('VOYAGE_MODEL'),
                multi_judge=multi_judge,
                gemini_key=os.environ.get('GEMINI_API_KEY')
            )
            
            # Initialize GitHub client
            github = Github(auth=Auth.Token(self.github_token))
            repo = github.get_repo(repo_name)
            
            if is_pr:
                # Handle PR analysis
                pr = repo.get_pull(pr_number)
                
                # Get PR info for display
                pr_title = pr.title
                pr_author = pr.user.login
                pr_state = pr.state
                
                # Check if PR is closed
                if pr_state == 'closed':
                    response = f"<b>PR Analysis</b>\n\n"
                    response += f"<b>PR:</b> <a href='{url}'>#{pr_number}</a> - {pr_title}\n"
                    response += f"<b>Author:</b> {pr_author}\n"
                    response += f"<b>Status:</b> <code>CLOSED</code>\n\n"
                else:
                    response = ""
                
                # Get PR changes
                changes = reviewer.get_pr_changes(pr)
                
                # Analyze the PR
                analysis, cost_info = reviewer.analyze_security(changes)
                
                # Format response
                if not response:  # If we didn't add closed warning
                    response = f"<b>PR Analysis Complete</b>\n\n"
                    response += f"<b>PR:</b> <a href='{url}'>#{pr_number}</a> - {pr_title}\n"
                    response += f"<b>Author:</b> {pr_author}\n"
                    response += f"<b>Status:</b> <code>{pr_state.upper()}</code>\n\n"
            else:
                # Handle commit analysis
                # Get commit details
                commit = repo.get_commit(commit_sha)
                
                # Get commit info for display
                commit_author = commit.commit.author.name if commit.commit.author else "Unknown"
                commit_date = commit.commit.author.date.strftime("%Y-%m-%d %H:%M:%S") if commit.commit.author and commit.commit.author.date else "Unknown"
                commit_message = commit.commit.message.split('\n')[0]  # First line
                
                # Analyze the commit
                analysis, cost_info = reviewer.analyze_commit(repo_name, commit_sha)
                
                # Format response
                response = f"<b>Commit Analysis Complete</b>\n\n"
                response += f"<b>Repository:</b> <code>{repo_name}</code>\n"
                response += f'<b>Commit:</b> <a href="{url}">{commit_sha[:7]}</a>\n'
                response += f"<b>Author:</b> {commit_author}\n"
                response += f"<b>Date:</b> {commit_date}\n"
                response += f"<b>Message:</b> {commit_message}\n\n"
            
            if analysis['has_vulnerabilities']:
                response += f"⚠️ <b>Security Issues Detected</b>\n"
                response += f"<b>Confidence:</b> {analysis['confidence_score']}%\n\n"
                
                # Count issues by severity
                severity_counts = {}
                for finding in analysis['findings']:
                    severity = finding['severity']
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                # Show severity summary
                severity_summary = []
                for severity, count in severity_counts.items():
                    emoji = {
                        'HIGH': '🔴',
                        'MEDIUM': '🟠',
                        'LOW': '🟡'
                    }.get(severity, '⚪')
                    severity_summary.append(f"{emoji} {count} {severity}")
                
                response += f"<b>Issues Found:</b> {' | '.join(severity_summary)}\n\n"
                
                # Add summary
                summary = analysis['summary']
                if len(summary) > 300:
                    summary = summary[:300] + "..."
                response += f"<b>Summary:</b>\n{summary}\n\n"
                
                # Add detailed findings (shortened for Telegram)
                response += "<b>Key Findings:</b>\n"
                for i, finding in enumerate(analysis['findings'][:3], 1):  # Show top 3
                    response += f"\n{i}. <b>{finding['severity']}</b>: {finding['description']}\n"
                    if len(finding['recommendation']) > 100:
                        rec = finding['recommendation'][:100] + "..."
                    else:
                        rec = finding['recommendation']
                    response += f"   <i>Fix:</i> {rec}\n"
                
                if len(analysis['findings']) > 3:
                    response += f"\n... and {len(analysis['findings']) - 3} more issues.\n"
                    
                # Store finding for detailed view
                from .commit_monitor import CommitInfo
                
                if is_pr:
                    # Create a pseudo CommitInfo for PR analysis
                    commit_info = CommitInfo(
                        sha=f"PR-{pr_number}",
                        author=pr_author,
                        date=pr.created_at.isoformat() if pr.created_at else "",
                        message=pr_title,
                        branch=pr.base.ref,
                        url=url
                    )
                else:
                    # Create CommitInfo for commit analysis
                    commit_info = CommitInfo(
                        sha=commit_sha,
                        author=commit_author,
                        date=commit_date,
                        message=commit_message,
                        branch="",  # Branch info not available from commit object
                        url=url
                    )
                
                finding_url = store_security_finding(repo_name, commit_info, analysis)
                response += f'\n<a href="{finding_url}">View Detailed Security Report</a>'
                
            else:
                response += "✅ <b>No security issues detected</b>\n\n"
                if is_pr:
                    response += "This PR appears to be safe from a security perspective."
                else:
                    response += "This commit appears to be safe from a security perspective."
            
            # Add cost information if available
            if cost_info and cost_info.total_cost > 0:
                response += f"\n\n<b>Analysis Cost:</b> ${cost_info.total_cost:.4f}"
                if multi_judge:
                    response += f"\n<i>Multi-judge enabled</i>"
                    
            return response
            
        except Exception as e:
            if is_pr:
                return f"❌ Error analyzing PR: {str(e)}"
            else:
                return f"❌ Error analyzing commit: {str(e)}"
            
    def handle_export_command(self, args: List[str], message: Dict) -> str:
        """
        Handle the /export command to export database findings as CSV and send as zip file.
        
        Args:
            args: Command arguments
            message: Full message object
            
        Returns:
            str: Response message confirming export or error
        """
        try:
            # Get database manager
            db_manager = get_database_manager()
            
            # Get all findings from the database
            session = db_manager.get_session()
            try:
                from .database import SecurityFinding
                findings = session.query(SecurityFinding).all()
                
                if not findings:
                    return "❌ No security findings found in database."
                
                # Create temporary directory for files
                with tempfile.TemporaryDirectory() as temp_dir:
                    # Create CSV file
                    csv_filename = f"security_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    csv_path = os.path.join(temp_dir, csv_filename)
                    
                    # Define CSV headers
                    csv_headers = [
                        'UUID',
                        'Repository',
                        'Commit SHA',
                        'Commit URL',
                        'Branch',
                        'Author',
                        'Commit Date',
                        'Commit Message',
                        'Has Vulnerabilities',
                        'Confidence Score',
                        'Findings Count',
                        'Summary',
                        'Created At',
                        'Expires At',
                        'Analysis Data'
                    ]
                    
                    # Write CSV file
                    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(csv_headers)
                        
                        for finding in findings:
                            # Extract individual findings for detailed export
                            analysis_data = finding.analysis_data or {}
                            findings_list = analysis_data.get('findings', [])
                            
                            # Create summary of findings
                            findings_summary = []
                            for f in findings_list:
                                findings_summary.append({
                                    'severity': f.get('severity', 'UNKNOWN'),
                                    'description': f.get('description', ''),
                                    'recommendation': f.get('recommendation', '')
                                })
                            
                            writer.writerow([
                                str(finding.uuid),
                                finding.repo_name,
                                finding.commit_sha,
                                finding.commit_url or '',
                                finding.branch or '',
                                finding.author or '',
                                finding.commit_date.isoformat() if finding.commit_date else '',
                                finding.commit_message or '',
                                finding.has_vulnerabilities,
                                finding.confidence_score or 0,
                                finding.findings_count or 0,
                                finding.summary or '',
                                finding.created_at.isoformat() if finding.created_at else '',
                                finding.expires_at.isoformat() if finding.expires_at else '',
                                json.dumps(findings_summary, ensure_ascii=False)
                            ])
                    
                    # Create zip file
                    zip_filename = f"security_findings_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
                    zip_path = os.path.join(temp_dir, zip_filename)
                    
                    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        zipf.write(csv_path, csv_filename)
                    
                    # Send zip file to Telegram
                    success = self.send_document(zip_path, zip_filename)
                    
                    if success:
                        return f"<b>Database Export Complete</b>\n\nExported {len(findings)} security findings to CSV\n"
                    else:
                        return "❌ Failed to send export file to Telegram"
                    
            finally:
                session.close()
                
        except Exception as e:
            return f"❌ Error exporting database: {str(e)}"
    
    def handle_help_command(self, args: List[str], message: Dict) -> str:
        """
        Handle the /help command to display available commands.
        
        Args:
            args: Command arguments
            message: Full message object
            
        Returns:
            str: Response message with list of available commands
        """
        response = "<b>Available Commands</b>\n\n"
        
        # Define command descriptions
        command_descriptions = {
            "listrepos": {
                "usage": "/listrepos",
                "description": "List all monitored GitHub repositories and their branches"
            },
            "lastcommits": {
                "usage": "/lastcommits",
                "description": "Show the latest tracked commits for all monitored repositories"
            },
            "check": {
                "usage": "/check &lt;URL or REPO SHA&gt;",
                "description": "Analyze a GitHub pull request or commit for security vulnerabilities",
                "example": "/check https://github.com/owner/repo/pull/123\n         /check https://github.com/owner/repo/commit/abc123\n         /check owner/repo abc123"
            },
            "export": {
                "usage": "/export",
                "description": "Export all security findings from database as CSV in a compressed zip file (main channel only)"
            }
        }
        
        # Sort commands alphabetically
        sorted_commands = sorted(command_descriptions.items())
        
        for cmd_name, cmd_info in sorted_commands:
            response += f"<b>{cmd_info['usage']}</b>\n"
            response += f"   {cmd_info['description']}\n"
            if 'example' in cmd_info:
                response += f"   <i>Example: {cmd_info['example']}</i>\n"
            response += "\n"        
        return response
            
    # Telegram Bot API methods
    
    def get_updates(self, offset: int = 0, timeout: int = 30) -> List[Dict]:
        """
        Get updates from Telegram Bot API.
        
        Args:
            offset: Update ID to start from
            timeout: Long polling timeout in seconds
            
        Returns:
            List of update objects
        """
        try:
            response = requests.get(
                f"{self.api_url}/getUpdates",
                params={
                    "offset": offset,
                    "timeout": timeout
                }
            )
            response.raise_for_status()
            result = response.json()
            
            if result.get("ok") and "result" in result:
                return result["result"]
            
            print(f"Error getting updates: {result.get('description', 'Unknown error')}")
            return []
        except Exception as e:
            print(f"Exception while getting updates: {e}")
            return []
            
    def start_polling(self) -> bool:
        """
        Start polling for Telegram updates in a separate thread.
        
        Returns:
            bool: True if polling started successfully
        """
        if self._polling_active:
            return False
            
        self._polling_active = True
        self._polling_thread = threading.Thread(target=self._polling_loop)
        self._polling_thread.daemon = True
        self._polling_thread.start()
        
        print("✅ Telegram bot polling started")
        return True
        
    def stop_polling(self) -> None:
        """Stop the polling thread."""
        self._polling_active = False
        if self._polling_thread:
            self._polling_thread.join(timeout=5.0)
            
    def _polling_loop(self) -> None:
        """Main polling loop that runs in a separate thread."""
        print("Starting Telegram bot polling loop...")
        
        while self._polling_active:
            try:
                updates = self.get_updates(offset=self._last_update_id + 1, timeout=30)
                
                for update in updates:
                    # Update the last update ID
                    if update["update_id"] > self._last_update_id:
                        self._last_update_id = update["update_id"]
                        
                    # Process message
                    if "message" in update:
                        self.handle_command(update["message"])
            except Exception as e:
                print(f"Error in polling loop: {e}")
                # Sleep a bit before retrying to avoid hammering the API
                time.sleep(5)
