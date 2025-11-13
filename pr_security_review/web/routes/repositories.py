"""
Repository routes blueprint.
"""

import logging
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash
from ..auth import get_auth_service
from ..decorators import login_required
from ..services import FindingsService, RepositoryService

logger = logging.getLogger(__name__)

repositories_bp = Blueprint('repositories_bp', __name__)

# Import database layer
try:
    from ...database import get_database_manager
    DATABASE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database not available: {e}")
    DATABASE_AVAILABLE = False


@repositories_bp.route('/repositories')
@login_required
def repositories_list():
    """Show repositories list (authenticated users only)."""
    try:
        # Get show_inactive parameter from query string
        show_inactive = request.args.get('show_inactive', 'false').lower() == 'true'
        
        repositories = RepositoryService.load_repositories()
        
        # Filter out inactive repositories by default
        if not show_inactive:
            repositories = [repo for repo in repositories if repo.get('is_active', True)]
        
        # Get statistics for each repository
        auth_service = get_auth_service()
        user_email = auth_service.get_current_user()['email']
        all_findings = FindingsService.get_all_findings(user_email=user_email)
        
        for repo in repositories:
            repo_findings = [f for f in all_findings if f.get('repo_name') == repo['name']]
            repo['commits_count'] = len(repo_findings)
            repo['vulnerable_count'] = len([f for f in repo_findings if f.get('has_vulnerabilities')])
        
        return render_template('repositories_list.html',
                             repositories=repositories,
                             show_inactive=show_inactive,
                             user=auth_service.get_current_user())
        
    except Exception as e:
        logger.error(f"Error showing repositories list: {e}")
        flash('Error loading repositories', 'error')
        return redirect(url_for('main_bp.index'))


@repositories_bp.route('/repository/<path:repo_name>')
@login_required
def repository_detail(repo_name):
    """Show repository detail with commits and PRs (authenticated users only)."""
    try:
        if not DATABASE_AVAILABLE:
            flash('Database not available', 'error')
            return redirect(url_for('repositories_bp.repositories_list'))
        
        db_manager = get_database_manager()
        
        # Get repository info
        repository = db_manager.get_repository(repo_name)
        if not repository:
            flash('Repository not found', 'error')
            return redirect(url_for('repositories_bp.repositories_list'))
        
        # Get pagination and filter parameters
        page = request.args.get('page', 1, type=int)
        author_filter = request.args.get('author', None, type=str)
        show_all = request.args.get('show_all', 'false').lower() == 'true'
        page_size = 25
        
        # Ensure page is at least 1
        if page < 1:
            page = 1
        
        commits = []
        pull_requests = []
        
        try:
            import os
            import requests
            
            github_token = os.getenv('GITHUB_TOKEN')
            if not github_token:
                logger.warning("GITHUB_TOKEN not set, cannot fetch commits from GitHub")
                flash('GitHub token not configured', 'warning')
            else:
                # Extract owner and repo from repo_name (e.g., "ethereum/go-ethereum")
                parts = repo_name.split('/')
                if len(parts) >= 2:
                    owner = parts[0]
                    repo = parts[1]
                    
                    # Use the first branch from the branches list
                    branches = repository.branches
                    branch = branches[0] if branches else 'main'
                    
                    # Fetch commits from GitHub API
                    headers = {
                        'Authorization': f'token {github_token}',
                        'Accept': 'application/vnd.github.v3+json'
                    }
                    
                    url = f'https://api.github.com/repos/{owner}/{repo}/commits'
                    params = {
                        'sha': branch,
                        'per_page': page_size,
                        'page': page
                    }
                    
                    # Add author filter if specified
                    if author_filter:
                        params['author'] = author_filter
                    
                    # Fetch all commits if show_all is enabled and author is filtered
                    if show_all and author_filter:
                        github_commits = []
                        current_page = 1
                        max_pages = 20  # Limit to 500 commits (20 pages * 25)
                        
                        while current_page <= max_pages:
                            params['page'] = current_page
                            response = requests.get(url, headers=headers, params=params, timeout=10)
                            
                            if response.status_code == 200:
                                page_commits = response.json()
                                if not page_commits:  # No more commits
                                    break
                                github_commits.extend(page_commits)
                                if len(page_commits) < page_size:  # Last page
                                    break
                                current_page += 1
                            else:
                                logger.error(f"GitHub API error on page {current_page}: {response.status_code}")
                                break
                    else:
                        response = requests.get(url, headers=headers, params=params, timeout=10)
                        
                        if response.status_code == 200:
                            github_commits = response.json()
                        else:
                            github_commits = []
                            logger.error(f"GitHub API error: {response.status_code} - {response.text}")
                            flash(f'Failed to fetch commits from GitHub: {response.status_code}', 'error')
                    
                    if github_commits:
                        
                        # Get all findings for this repository to match with commits
                        auth_service = get_auth_service()
                        user_email = auth_service.get_current_user()['email']
                        all_findings = FindingsService.get_all_findings(user_email=user_email)
                        repo_findings = {f['commit_sha']: f for f in all_findings if f.get('repo_name') == repo_name}
                        
                        # Build commits list with review status
                        for gh_commit in github_commits:
                            commit_sha = gh_commit['sha']
                            commit_data = gh_commit.get('commit', {})
                            author_data = commit_data.get('author', {})
                            
                            # Check if this commit has been reviewed
                            finding = repo_findings.get(commit_sha)
                            
                            if finding:
                                # Commit has been reviewed
                                commit = {
                                    'sha': commit_sha,
                                    'message': commit_data.get('message', 'N/A'),
                                    'author': author_data.get('name', 'Unknown'),
                                    'date': author_data.get('date', 'N/A')[:10] if author_data.get('date') else 'N/A',
                                    'scan_status': 'scanned',
                                    'has_vulnerabilities': finding.get('has_vulnerabilities', False),
                                    'finding_uuid': finding.get('uuid')
                                }
                            else:
                                # Commit has not been reviewed yet
                                commit = {
                                    'sha': commit_sha,
                                    'message': commit_data.get('message', 'N/A'),
                                    'author': author_data.get('name', 'Unknown'),
                                    'date': author_data.get('date', 'N/A')[:10] if author_data.get('date') else 'N/A',
                                    'scan_status': 'not-scanned',
                                    'has_vulnerabilities': False,
                                    'finding_uuid': None
                                }
                            
                            commits.append(commit)
                    
                    # Fetch pull requests from GitHub API
                    pr_url = f'https://api.github.com/repos/{owner}/{repo}/pulls'
                    pr_params = {
                        'state': 'all',  # Get open, closed, and merged PRs
                        'sort': 'updated',
                        'direction': 'desc',
                        'per_page': page_size,
                        'page': page
                    }
                    
                    pr_response = requests.get(pr_url, headers=headers, params=pr_params, timeout=10)
                    
                    if pr_response.status_code == 200:
                        github_prs = pr_response.json()
                        
                        # Get all findings for this repository to match with PRs
                        # Query database directly for PR findings
                        from ...database import SecurityFinding
                        session = db_manager.get_session()
                        try:
                            pr_finding_records = session.query(SecurityFinding).filter(
                                SecurityFinding.repo_name == repo_name,
                                SecurityFinding.pr_number.isnot(None)
                            ).all()
                            
                            # Create a mapping of PR numbers to findings
                            pr_findings = {}
                            for finding in pr_finding_records:
                                pr_findings[finding.pr_number] = finding.to_dict()
                        finally:
                            session.close()
                        
                        # Build PRs list with review status
                        for gh_pr in github_prs:
                            pr_number = gh_pr['number']
                            pr_head = gh_pr.get('head', {})
                            pr_user = gh_pr.get('user', {})
                            
                            # Check if this PR has been reviewed
                            finding = pr_findings.get(pr_number)
                            
                            if finding:
                                # PR has been reviewed
                                pr = {
                                    'number': pr_number,
                                    'title': gh_pr.get('title', 'N/A'),
                                    'state': gh_pr.get('state', 'unknown'),
                                    'merged': gh_pr.get('merged', False),
                                    'author': pr_user.get('login', 'Unknown'),
                                    'head_sha': pr_head.get('sha', 'N/A'),
                                    'created_at': gh_pr.get('created_at', 'N/A')[:10] if gh_pr.get('created_at') else 'N/A',
                                    'updated_at': gh_pr.get('updated_at', 'N/A')[:10] if gh_pr.get('updated_at') else 'N/A',
                                    'url': gh_pr.get('html_url', ''),
                                    'scan_status': 'scanned',
                                    'has_vulnerabilities': finding.get('has_vulnerabilities', False),
                                    'finding_uuid': finding.get('uuid')
                                }
                            else:
                                # PR has not been reviewed yet
                                pr = {
                                    'number': pr_number,
                                    'title': gh_pr.get('title', 'N/A'),
                                    'state': gh_pr.get('state', 'unknown'),
                                    'merged': gh_pr.get('merged', False),
                                    'author': pr_user.get('login', 'Unknown'),
                                    'head_sha': pr_head.get('sha', 'N/A'),
                                    'created_at': gh_pr.get('created_at', 'N/A')[:10] if gh_pr.get('created_at') else 'N/A',
                                    'updated_at': gh_pr.get('updated_at', 'N/A')[:10] if gh_pr.get('updated_at') else 'N/A',
                                    'url': gh_pr.get('html_url', ''),
                                    'scan_status': 'not-scanned',
                                    'has_vulnerabilities': False,
                                    'finding_uuid': None
                                }
                            
                            pull_requests.append(pr)
                    else:
                        logger.error(f"GitHub API error for PRs: {pr_response.status_code} - {pr_response.text}")
                        flash(f'Failed to fetch PRs from GitHub: {pr_response.status_code}', 'warning')
                else:
                    logger.error(f"Invalid repository name format: {repo_name}")
                    flash('Invalid repository name format', 'error')
                    
        except Exception as github_error:
            logger.error(f"Error fetching data from GitHub: {github_error}")
            flash('Error fetching data from GitHub', 'error')
        
        # If GitHub fetch failed, fall back to database findings
        if not commits:
            auth_service = get_auth_service()
            user_email = auth_service.get_current_user()['email']
            all_findings = FindingsService.get_all_findings(user_email=user_email)
            repo_findings = [f for f in all_findings if f.get('repo_name') == repo_name]
            
            # Sort by created_at descending (most recent first)
            repo_findings.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            
            # Limit to last 25 commits
            repo_findings = repo_findings[:page_size]
            
            # Build commits list
            for finding in repo_findings:
                commit = {
                    'sha': finding['commit_sha'],
                    'message': finding.get('commit_message', 'N/A'),
                    'author': finding.get('author', 'Unknown'),
                    'date': finding.get('commit_date', 'N/A')[:10] if finding.get('commit_date') else 'N/A',
                    'scan_status': 'scanned',
                    'has_vulnerabilities': finding.get('has_vulnerabilities', False),
                    'finding_uuid': finding.get('uuid')
                }
                commits.append(commit)
        
        # Get unique authors from commits for filter dropdown
        unique_authors = sorted(list(set([c['author'] for c in commits if c.get('author')])))
        
        return render_template('repository_detail.html',
                             repository=repository.to_dict(),
                             commits=commits,
                             pull_requests=pull_requests,
                             page_size=page_size,
                             current_page=page,
                             author_filter=author_filter,
                             show_all=show_all,
                             unique_authors=unique_authors,
                             user=auth_service.get_current_user())
        
    except Exception as e:
        logger.error(f"Error showing repository detail for {repo_name}: {e}")
        flash('Error loading repository details', 'error')
        return redirect(url_for('repositories_bp.repositories_list'))
