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
    """Show repository detail with commits (authenticated users only)."""
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
        
        # Fetch last 25 commits from GitHub API
        page_size = 25
        commits = []
        
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
                        'per_page': page_size
                    }
                    
                    response = requests.get(url, headers=headers, params=params, timeout=10)
                    
                    if response.status_code == 200:
                        github_commits = response.json()
                        
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
                    else:
                        logger.error(f"GitHub API error: {response.status_code} - {response.text}")
                        flash(f'Failed to fetch commits from GitHub: {response.status_code}', 'error')
                else:
                    logger.error(f"Invalid repository name format: {repo_name}")
                    flash('Invalid repository name format', 'error')
                    
        except Exception as github_error:
            logger.error(f"Error fetching commits from GitHub: {github_error}")
            flash('Error fetching commits from GitHub', 'error')
        
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
        
        return render_template('repository_detail.html',
                             repository=repository.to_dict(),
                             commits=commits,
                             page_size=page_size,
                             user=auth_service.get_current_user())
        
    except Exception as e:
        logger.error(f"Error showing repository detail for {repo_name}: {e}")
        flash('Error loading repository details', 'error')
        return redirect(url_for('repositories_bp.repositories_list'))


@repositories_bp.route('/scan-commit', methods=['POST'])
@login_required
def scan_commit():
    """Scan or rescan a commit (authenticated users only)."""
    try:
        data = request.get_json()
        repo_name = data.get('repo_name')
        commit_sha = data.get('commit_sha')
        rescan = data.get('rescan', False)
        
        if not repo_name or not commit_sha:
            return jsonify({'error': 'Repository name and commit SHA required'}), 400
        
        # TODO: Implement actual scanning logic
        return jsonify({
            'success': True,
            'message': f'Scan {"queued" if not rescan else "re-queued"} for commit {commit_sha[:7]}'
        })
        
    except Exception as e:
        logger.error(f"Error scanning commit: {e}")
        return jsonify({'error': 'Internal server error'}), 500
