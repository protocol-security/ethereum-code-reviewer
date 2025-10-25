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
        repositories = RepositoryService.load_repositories()
        
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
        
        # Get all findings for this repository
        auth_service = get_auth_service()
        user_email = auth_service.get_current_user()['email']
        all_findings = FindingsService.get_all_findings(user_email=user_email)
        repo_findings = [f for f in all_findings if f.get('repo_name') == repo_name]
        
        # Sort by created_at descending (most recent first)
        repo_findings.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        # Limit to last 25 commits
        page_size = 25
        repo_findings = repo_findings[:page_size]
        
        # Build commits list
        commits = []
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
