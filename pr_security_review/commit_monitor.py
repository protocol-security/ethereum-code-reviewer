"""
Module for monitoring commits on specified GitHub repository branches.
"""

import os
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import threading
from pathlib import Path
import sys

from github import Github, Auth
from github.Repository import Repository
from github.Commit import Commit
from github.GithubException import GithubException

# Database imports
try:
    from .database import get_database_manager
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False


@dataclass
class MonitoredRepository:
    """Configuration for a monitored repository."""
    owner: str
    repo: str
    branches: List[str]
    telegram_channel_id: Optional[str] = None  # Specific channel for this repo
    notify_default_channel: bool = True  # Whether to also notify the default channel
    
    @property
    def full_name(self) -> str:
        """Get the full repository name."""
        return f"{self.owner}/{self.repo}"
    
    @classmethod
    def from_url(cls, url: str, branches: List[str], telegram_channel_id: Optional[str] = None, 
                notify_default_channel: bool = True) -> 'MonitoredRepository':
        """
        Create MonitoredRepository from a GitHub URL.
        
        Args:
            url: GitHub repository URL (e.g., https://github.com/owner/repo)
            branches: List of branch names to monitor
            telegram_channel_id: Optional specific Telegram channel ID for this repo
            notify_default_channel: Whether to also notify the default channel
            
        Returns:
            MonitoredRepository instance
        """
        # Extract owner and repo from URL
        parts = url.rstrip('/').split('/')
        if len(parts) < 2:
            raise ValueError(f"Invalid GitHub URL: {url}")
        
        owner = parts[-2]
        repo = parts[-1]
        
        # Remove .git suffix if present
        if repo.endswith('.git'):
            repo = repo[:-4]
            
        return cls(owner=owner, repo=repo, branches=branches, 
                  telegram_channel_id=telegram_channel_id, notify_default_channel=notify_default_channel)


@dataclass
class CommitInfo:
    """Information about a commit."""
    sha: str
    author: str
    date: str
    message: str
    branch: str
    url: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class CommitMonitor:
    """Monitors GitHub repositories for new commits on specified branches."""
    
    def __init__(self, github_token: str, state_file: Optional[str] = None, config_file: Optional[str] = None):
        """
        Initialize the commit monitor.
        
        Args:
            github_token: GitHub API token
            state_file: Path to file for persisting state between runs
            config_file: Path to configuration file containing repositories to monitor
        """
        # Validate GitHub token
        if not github_token or len(github_token) < 5:
            raise ValueError("Invalid GitHub token: Token is empty or too short")
        
        # Try to initialize GitHub client
        try:
            self.github = Github(auth=Auth.Token(github_token))
            user = self.github.get_user()
        except Exception as e:
            print(f"❌ GitHub authentication error: {str(e)}")
            print("Please check your GitHub token and ensure it has appropriate permissions")
            # Still initialize the client even if the test fails
            self.github = Github(auth=Auth.Token(github_token))
            
        self.state_file = state_file or os.path.join(os.path.expanduser("~"), ".pr_security_review", "commit_monitor_state.json")
        self.monitored_repos: List[MonitoredRepository] = []
        self.last_commits: Dict[str, Dict[str, str]] = {}  # repo -> branch -> last_commit_sha
        
        # Load state first to ensure we have the last commit information
        self._load_state()
        
        # Load repositories from database if available, otherwise from config file
        if DATABASE_AVAILABLE:
            try:
                self._load_repositories_from_database()
                # After loading from database, sync with GitHub to catch any commits that happened while monitoring was off
                self._sync_with_github()
            except Exception as e:
                print(f"Warning: Failed to load repositories from database: {e}")
                # Fall back to config file if database fails
                if config_file and os.path.exists(config_file):
                    self._load_repositories_from_config(config_file)
                    self._sync_with_github()
        elif config_file and os.path.exists(config_file):
            self._load_repositories_from_config(config_file)
            # After loading config, sync with GitHub to catch any commits that happened while monitoring was off
            self._sync_with_github()
    
    def _sync_with_github(self) -> None:
        """
        Synchronize the current state with GitHub at startup.
        This ensures we have the latest commit information for all monitored repositories.
        """
        if not self.monitored_repos:
            return
        
        print("\n🔄 Synchronizing with GitHub to get current state...")
        
        for monitored_repo in self.monitored_repos:
            print(f"\nChecking {monitored_repo.full_name}:")
            # Force update to get the current state from GitHub
            self._initialize_last_commits(monitored_repo, force_update=True)
        
        # Save the synchronized state
        self._save_state()
        print("\n✅ Synchronization complete. Ready to monitor for new commits.")
        
    def _load_state(self) -> None:
        """Load persisted state from file."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    self.last_commits = data.get('last_commits', {})
                    
                    # Restore monitored repositories
                    repos_data = data.get('monitored_repos', [])
                    self.monitored_repos = [
                        MonitoredRepository(**repo_data) for repo_data in repos_data
                    ]
            except Exception as e:
                print(f"Warning: Failed to load state from {self.state_file}: {e}")
                
    def _save_state(self) -> None:
        """Save current state to file."""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            
            data = {
                'last_commits': self.last_commits,
                'monitored_repos': [asdict(repo) for repo in self.monitored_repos],
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            
            with open(self.state_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save state to {self.state_file}: {e}")
            
    def add_repository(self, repo_url: str, branches: List[str]) -> None:
        """
        Add a repository to monitor.
        
        Args:
            repo_url: GitHub repository URL
            branches: List of branch names to monitor
        """
        monitored_repo = MonitoredRepository.from_url(repo_url, branches)
        
        # Check if already monitoring this repo
        existing = next((r for r in self.monitored_repos if r.full_name == monitored_repo.full_name), None)
        if existing:
            # Update branches
            existing.branches = list(set(existing.branches + branches))
        else:
            self.monitored_repos.append(monitored_repo)
            
        # Initialize last commits for new branches
        self._initialize_last_commits(monitored_repo)
        self._save_state()
        
    def remove_repository(self, repo_url: str) -> None:
        """
        Remove a repository from monitoring.
        
        Args:
            repo_url: GitHub repository URL
        """
        full_name = MonitoredRepository.from_url(repo_url, []).full_name
        self.monitored_repos = [r for r in self.monitored_repos if r.full_name != full_name]
        
        # Remove from last_commits
        if full_name in self.last_commits:
            del self.last_commits[full_name]
            
        self._save_state()
    
    def _load_repositories_from_config(self, config_file: str) -> None:
        """
        Load repositories to monitor from a configuration file.
        
        Args:
            config_file: Path to the configuration file
        """
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                
            if 'repositories' not in config:
                print(f"Warning: Config file {config_file} does not contain a 'repositories' key.")
                return
            
            print(f"\nLoading repositories from config file: {config_file}")
            print(f"Found {len(config['repositories'])} repositories to monitor\n")
                
            for repo_config in config['repositories']:
                if 'url' not in repo_config:
                    print(f"Warning: Skipping repository config without 'url': {repo_config}")
                    continue
                    
                url = repo_config['url']
                branches = repo_config.get('branches', ['main', 'master'])
                telegram_channel_id = repo_config.get('telegram_channel_id')
                notify_default_channel = repo_config.get('notify_default_channel', True)
                
                print(f"Loading repository: {url}")
                print(f"  Branches to monitor: {', '.join(branches)}")
                if telegram_channel_id:
                    print(f"  Telegram channel ID: {telegram_channel_id}")
                    print(f"  Also notify default channel: {notify_default_channel}")
                
                try:
                    # Create monitored repository with telegram config
                    monitored_repo = MonitoredRepository.from_url(
                        url, branches, telegram_channel_id, notify_default_channel
                    )
                    
                    # Check if already monitoring this repo
                    existing = next((r for r in self.monitored_repos if r.full_name == monitored_repo.full_name), None)
                    if existing:
                        # Update existing repository configuration
                        existing.branches = list(set(existing.branches + branches))
                        existing.telegram_channel_id = telegram_channel_id
                        existing.notify_default_channel = notify_default_channel
                    else:
                        self.monitored_repos.append(monitored_repo)
                        
                    # Initialize last commits for new branches
                    self._initialize_last_commits(monitored_repo)
                    print(f"  ✅ Successfully initialized monitoring for {url}")
                except Exception as e:
                    print(f"  ❌ Error adding repository {url} from config: {e}")
                    
            print(f"\n✅ Config loading complete. Monitoring {len(self.monitored_repos)} repositories.")
            
        except json.JSONDecodeError as e:
            print(f"Error parsing config file {config_file}: {e}")
        except Exception as e:
            print(f"Error loading repositories from config file {config_file}: {e}")
    
    def _load_repositories_from_database(self) -> None:
        """
        Load repositories to monitor from the database.
        """
        try:
            db_manager = get_database_manager()
            repositories = db_manager.get_repositories_for_monitoring()
            
            print(f"\nLoading repositories from database")
            print(f"Found {len(repositories)} active repositories to monitor\n")
            
            for repo_config in repositories:
                url = repo_config.get('url', '')
                branches = repo_config.get('branches', [])
                telegram_channel_id = repo_config.get('telegram_channel_id')
                notify_default_channel = repo_config.get('notify_default_channel', False)
                
                if not url or not branches:
                    print(f"Warning: Skipping repository with missing URL or branches: {repo_config}")
                    continue
                
                print(f"Loading repository: {url}")
                print(f"  Branches to monitor: {', '.join(branches)}")
                if telegram_channel_id:
                    print(f"  Telegram channel ID: {telegram_channel_id}")
                    print(f"  Also notify default channel: {notify_default_channel}")
                
                try:
                    # Create monitored repository with telegram config
                    monitored_repo = MonitoredRepository.from_url(
                        url, branches, telegram_channel_id, notify_default_channel
                    )
                    
                    # Check if already monitoring this repo
                    existing = next((r for r in self.monitored_repos if r.full_name == monitored_repo.full_name), None)
                    if existing:
                        # Update existing repository configuration
                        existing.branches = list(set(existing.branches + branches))
                        existing.telegram_channel_id = telegram_channel_id
                        existing.notify_default_channel = notify_default_channel
                    else:
                        self.monitored_repos.append(monitored_repo)
                        
                    # Initialize last commits for new branches
                    self._initialize_last_commits(monitored_repo)
                    print(f"  ✅ Successfully initialized monitoring for {url}")
                except Exception as e:
                    print(f"  ❌ Error adding repository {url} from database: {e}")
                    
            print(f"\n✅ Database loading complete. Monitoring {len(self.monitored_repos)} repositories.")
            
        except Exception as e:
            print(f"Error loading repositories from database: {e}")
            raise
        
    def _initialize_last_commits(self, monitored_repo: MonitoredRepository, force_update: bool = False) -> None:
        """
        Initialize last commit tracking for a repository's branches.
        
        Args:
            monitored_repo: Repository configuration
            force_update: If True, query GitHub even if we have saved state
        """
        try:
            repo = self.github.get_repo(monitored_repo.full_name)
            
            if monitored_repo.full_name not in self.last_commits:
                self.last_commits[monitored_repo.full_name] = {}
                
            for branch_name in monitored_repo.branches:
                # Query GitHub if we haven't seen this branch before OR if force_update is True
                if branch_name not in self.last_commits[monitored_repo.full_name] or force_update:
                    try:
                        branch = repo.get_branch(branch_name)
                        current_sha = branch.commit.sha
                        
                        # Check if this is different from what we had saved
                        if branch_name in self.last_commits[monitored_repo.full_name]:
                            saved_sha = self.last_commits[monitored_repo.full_name][branch_name]
                            if saved_sha != current_sha:
                                print(f"    Branch {branch_name}: HEAD has moved since last run")
                                print(f"      Saved: {saved_sha[:7]}")
                                print(f"      Current: {current_sha[:7]}")
                            else:
                                print(f"    Branch {branch_name}: No changes since last run (HEAD: {current_sha[:7]})")
                        else:
                            print(f"    Branch {branch_name}: Initial state captured (HEAD: {current_sha[:7]})")
                        
                        self.last_commits[monitored_repo.full_name][branch_name] = current_sha
                    except GithubException as e:
                        print(f"    ⚠️ Could not get branch {branch_name}: {e}")
                        
        except GithubException as e:
            print(f"  ⚠️ Could not access repository {monitored_repo.full_name}: {e}")
            
    def get_new_commits(self) -> List[Tuple[MonitoredRepository, List[CommitInfo]]]:
        """
        Check all monitored repositories for new commits.
        
        Returns:
            List of tuples containing (repository, new_commits)
        """
        results = []
        
        for monitored_repo in self.monitored_repos:
            new_commits = self._check_repository(monitored_repo)
            if new_commits:
                results.append((monitored_repo, new_commits))
                
        # Save state after checking all repositories
        self._save_state()
        return results
        
    def _check_repository(self, monitored_repo: MonitoredRepository) -> List[CommitInfo]:
        """
        Check a single repository for new commits.
        
        Args:
            monitored_repo: Repository configuration
            
        Returns:
            List of new commits found
        """
        new_commits = []
        
        try:
            repo = self.github.get_repo(monitored_repo.full_name)
            
            for branch_name in monitored_repo.branches:
                try:
                    branch = repo.get_branch(branch_name)
                    current_sha = branch.commit.sha
                    
                    # Get last known commit for this branch
                    last_sha = self.last_commits.get(monitored_repo.full_name, {}).get(branch_name)
                    
                    if last_sha:
                        if last_sha != current_sha:
                            print(f"  Branch {branch_name}: New commits detected")
                            print(f"    Last known: {last_sha[:7]}")
                            print(f"    Current: {current_sha[:7]}")
                            
                            # Get commits between last known and current
                            commits = self._get_commits_between(repo, branch_name, last_sha, current_sha)
                            
                            for commit in commits:
                                commit_info = CommitInfo(
                                    sha=commit.sha,
                                    author=commit.commit.author.name if commit.commit.author else "Unknown",
                                    date=commit.commit.author.date.isoformat() if commit.commit.author else "",
                                    message=commit.commit.message,
                                    branch=branch_name,
                                    url=commit.html_url
                                )
                                new_commits.append(commit_info)
                        else:
                            print(f"  Branch {branch_name}: No new commits (HEAD: {current_sha[:7]})")
                    else:
                        print(f"  Branch {branch_name}: First time monitoring (HEAD: {current_sha[:7]})")
                            
                    # Update last known commit
                    if monitored_repo.full_name not in self.last_commits:
                        self.last_commits[monitored_repo.full_name] = {}
                    self.last_commits[monitored_repo.full_name][branch_name] = current_sha
                    
                except GithubException as e:
                    print(f"Warning: Could not check branch {branch_name} for {monitored_repo.full_name}: {e}")
                    
        except GithubException as e:
            print(f"Warning: Could not access repository {monitored_repo.full_name}: {e}")
            
        return new_commits
        
    def _get_commits_between(self, repo: Repository, branch: str, since_sha: str, until_sha: str) -> List[Commit]:
        """
        Get commits between two SHAs on a branch.
        
        Args:
            repo: GitHub repository object
            branch: Branch name
            since_sha: Starting commit SHA (exclusive)
            until_sha: Ending commit SHA (inclusive)
            
        Returns:
            List of commits between the two SHAs
        """
        commits = []
        
        try:
            # First, get the branch object to ensure we have the correct SHA
            branch_obj = repo.get_branch(branch)
            
            # Get commits on the branch starting from the current HEAD
            # Note: This gets commits in reverse chronological order (newest first)
            found_until = False
            for commit in repo.get_commits(sha=branch_obj.commit.sha):
                if not found_until:
                    # Skip commits until we find the until_sha
                    if commit.sha == until_sha:
                        found_until = True
                        commits.append(commit)
                    continue
                
                if commit.sha == since_sha:
                    # We've reached the last known commit, stop
                    break
                    
                commits.append(commit)
                    
            # Reverse to get chronological order (oldest first)
            commits.reverse()
            
            # Log what we found
            if commits:
                print(f"  Found {len(commits)} new commits between {since_sha[:7]} and {until_sha[:7]}")
                for commit in commits:
                    print(f"    - {commit.sha[:7]}: {commit.commit.message.split(chr(10))[0][:60]}...")
            
        except GithubException as e:
            print(f"Warning: Could not get commits for {repo.full_name}/{branch}: {e}")
            
        return commits
        
    def get_commit_changes(self, repo_name: str, commit_sha: str) -> str:
        """
        Get the changes introduced by a specific commit.
        
        Args:
            repo_name: Full repository name (owner/repo)
            commit_sha: Commit SHA
            
        Returns:
            String containing the commit changes in patch format
        """
        try:
            repo = self.github.get_repo(repo_name)
            commit = repo.get_commit(commit_sha)
            
            changes = []
            changes.append(f"Commit: {commit.sha}")
            changes.append(f"Author: {commit.commit.author.name if commit.commit.author else 'Unknown'}")
            changes.append(f"Date: {commit.commit.author.date if commit.commit.author else 'Unknown'}")
            changes.append(f"Message: {commit.commit.message}")
            changes.append("\nFiles changed:")
            
            for file in commit.files:
                if file.patch:
                    changes.append(f"\nFile: {file.filename}")
                    changes.append(f"Status: {file.status}")
                    changes.append(f"Changes: +{file.additions} -{file.deletions}")
                    changes.append(f"\n{file.patch}")
                    
            return "\n".join(changes)
            
        except GithubException as e:
            print(f"Error getting commit changes for {commit_sha} in {repo_name}: {e}")
            return ""
            
    def list_monitored_repositories(self) -> List[Dict[str, Any]]:
        """
        Get list of currently monitored repositories.
        
        Returns:
            List of repository configurations
        """
        return [
            {
                "repository": repo.full_name,
                "branches": repo.branches,
                "last_commits": self.last_commits.get(repo.full_name, {})
            }
            for repo in self.monitored_repos
        ]
        
    def monitor_continuously(self, check_interval: int = 300, callback=None) -> None:
        """
        Continuously monitor repositories for new commits.
        
        Args:
            check_interval: Seconds between checks (default: 5 minutes)
            callback: Function to call when new commits are found. 
                     Should accept (MonitoredRepository, List[CommitInfo])
        """
        print(f"Starting continuous monitoring (checking every {check_interval} seconds)...")
        
        while True:
            try:
                print(f"\n[{datetime.now()}] Checking for new commits...")
                new_commits = self.get_new_commits()
                
                if new_commits:
                    for monitored_repo, commits in new_commits:
                        print(f"Found {len(commits)} new commits in {monitored_repo.full_name}")
                        
                        if callback:
                            callback(monitored_repo, commits)
                else:
                    print("No new commits found.")
                    
            except Exception as e:
                print(f"Error during monitoring: {e}")
                
            # Wait before next check
            time.sleep(check_interval)
