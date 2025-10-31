"""
API routes blueprint for AJAX endpoints.
"""

import logging
from flask import Blueprint, jsonify, request
from ..auth import get_auth_service
from ..decorators import login_required, admin_required
from ..services import FindingsService

logger = logging.getLogger(__name__)

api_bp = Blueprint('api_bp', __name__)

# Import database layer
try:
    from ...database import get_database_manager
    DATABASE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database not available: {e}")
    DATABASE_AVAILABLE = False


@api_bp.route('/findings')
@login_required
def api_findings():
    """API endpoint for findings list (authenticated users only)."""
    try:
        auth_service = get_auth_service()
        user_email = auth_service.get_current_user()['email']
        findings = FindingsService.get_all_findings(user_email=user_email)
        return jsonify({
            'success': True,
            'findings': findings,
            'total': len(findings)
        })
    except Exception as e:
        logger.error(f"Error fetching findings: {e}")
        return jsonify({'error': 'Failed to fetch findings'}), 500


@api_bp.route('/triage/<finding_uuid>', methods=['POST'])
@login_required
def update_triage(finding_uuid):
    """Update triage status of a finding (authenticated users only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        new_status = data.get('status')
        notes = data.get('notes')
        completion_classification = data.get('completion_classification')
        
        if not new_status:
            return jsonify({'error': 'Status is required'}), 400
        
        # Validate status
        valid_statuses = ['unassigned', 'reviewing', 'escalated_to_client', 'completed']
        if new_status not in valid_statuses:
            return jsonify({'error': 'Invalid status'}), 400
        
        # Validate completion classification if status is completed
        if new_status == 'completed':
            if not completion_classification:
                return jsonify({'error': 'Completion classification required for completed status'}), 400
            if completion_classification not in ['true_positive', 'false_positive']:
                return jsonify({'error': 'Invalid completion classification'}), 400
        
        auth_service = get_auth_service()
        user_email = auth_service.get_current_user()['email']
        
        db_manager = get_database_manager()
        success = db_manager.update_triage_status(
            finding_uuid=finding_uuid,
            new_status=new_status,
            user_email=user_email,
            notes=notes,
            completion_classification=completion_classification
        )
        
        if success:
            return jsonify({'success': True, 'message': 'Triage status updated successfully'})
        else:
            return jsonify({'error': 'Failed to update triage status'}), 500
        
    except Exception as e:
        logger.error(f"Error updating triage status for {finding_uuid}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/notes/<finding_uuid>', methods=['GET', 'POST', 'DELETE'])
@login_required
def handle_notes(finding_uuid):
    """Handle notes operations (GET, POST, DELETE)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        db_manager = get_database_manager()
        auth_service = get_auth_service()
        user_email = auth_service.get_current_user()['email']
        
        if request.method == 'GET':
            notes = db_manager.get_notes(finding_uuid)
            return jsonify({'success': True, 'notes': notes})
        
        elif request.method == 'POST':
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            note_text = data.get('note')
            if not note_text or not note_text.strip():
                return jsonify({'error': 'Note text is required'}), 400
            
            success = db_manager.add_note(
                finding_uuid=finding_uuid,
                note_text=note_text.strip(),
                user_email=user_email
            )
            
            if success:
                return jsonify({'success': True, 'message': 'Note added successfully'})
            else:
                return jsonify({'error': 'Failed to add note'}), 500
        
    except Exception as e:
        logger.error(f"Error handling notes for {finding_uuid}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/notes/<finding_uuid>/<int:note_id>', methods=['DELETE'])
@login_required
def delete_note(finding_uuid, note_id):
    """Delete a note from a finding (authenticated users only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        auth_service = get_auth_service()
        user_email = auth_service.get_current_user()['email']
        
        db_manager = get_database_manager()
        success = db_manager.delete_note(
            finding_uuid=finding_uuid,
            note_id=note_id,
            user_email=user_email
        )
        
        if success:
            return jsonify({'success': True, 'message': 'Note deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete note'}), 500
        
    except Exception as e:
        logger.error(f"Error deleting note {note_id} from {finding_uuid}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/triage/statistics')
@login_required
def triage_statistics():
    """Get triage statistics (authenticated users only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        db_manager = get_database_manager()
        stats = db_manager.get_triage_statistics()
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error fetching triage statistics: {e}")
        return jsonify({'error': 'Failed to fetch statistics'}), 500


@api_bp.route('/api-keys', methods=['GET', 'POST', 'DELETE'])
@login_required
def manage_api_keys():
    """Manage API keys for the current user."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        auth_service = get_auth_service()
        user_email = auth_service.get_current_user()['email']
        db_manager = get_database_manager()
        
        if request.method == 'GET':
            # Get all API keys for the user
            api_keys = db_manager.get_user_api_keys(user_email)
            return jsonify({'success': True, 'api_keys': api_keys})
        
        elif request.method == 'POST':
            # Create a new API key
            data = request.get_json()
            if not data or not data.get('name'):
                return jsonify({'error': 'API key name is required'}), 400
            
            name = data.get('name').strip()
            if not name:
                return jsonify({'error': 'API key name cannot be empty'}), 400
            
            # Generate the API key
            api_key = db_manager.create_api_key(user_email, name)
            
            if api_key:
                # Get the user's accessible repositories for the curl example
                accessible_repos = db_manager.get_user_repository_access(user_email)
                example_repo = accessible_repos[0] if accessible_repos else 'ethereum/go-ethereum'
                
                # Generate curl example
                import os
                base_url = os.getenv('BASE_URL', request.host_url.rstrip('/'))
                curl_example = f"""curl -X POST {base_url}/api/v1/alerts \\
  -H "Authorization: Bearer {api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "repository": "{example_repo}",
    "title": "Potential vulnerability found",
    "description": "Description of the vulnerability",
    "severity": "high",
    "file_path": "contracts/MyContract.sol",
    "line_number": 42
  }}'"""
                
                return jsonify({
                    'success': True,
                    'api_key': api_key,
                    'curl_example': curl_example,
                    'message': 'API key created successfully. Copy it now - you won\'t be able to see it again!'
                })
            else:
                return jsonify({'error': 'Failed to create API key'}), 500
        
        elif request.method == 'DELETE':
            # Revoke/delete an API key
            data = request.get_json()
            if not data or not data.get('key_id'):
                return jsonify({'error': 'API key ID is required'}), 400
            
            key_id = data.get('key_id')
            
            # Delete the key
            success = db_manager.delete_api_key(key_id, user_email)
            
            if success:
                return jsonify({'success': True, 'message': 'API key deleted successfully'})
            else:
                return jsonify({'error': 'Failed to delete API key'}), 500
    
    except Exception as e:
        logger.error(f"Error managing API keys: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/scan-commit', methods=['POST'])
@login_required
def scan_commit():
    """Scan or rescan a commit (authenticated users only)."""
    import os
    import threading
    from github import Github, Auth
    
    try:
        data = request.get_json()
        repo_name = data.get('repo_name')
        commit_sha = data.get('commit_sha')
        rescan = data.get('rescan', False)
        
        if not repo_name or not commit_sha:
            return jsonify({'error': 'Repository name and commit SHA required'}), 400
        
        # Check if commit already has findings
        if DATABASE_AVAILABLE:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                from ...database import SecurityFinding
                existing_findings = session.query(SecurityFinding).filter(
                    SecurityFinding.repo_name == repo_name,
                    SecurityFinding.commit_sha == commit_sha
                ).all()
                
                if existing_findings and not rescan:
                    # Findings exist and this is not a rescan - prevent duplicate
                    session.close()
                    return jsonify({
                        'success': False,
                        'message': f'Commit {commit_sha[:7]} has already been scanned. Use rescan if you want to analyze it again.',
                        'finding_uuid': str(existing_findings[0].uuid)
                    }), 400
                elif existing_findings and rescan:
                    # This is a rescan - delete all existing findings for this commit first
                    for finding in existing_findings:
                        session.delete(finding)
                    session.commit()
                    logger.info(f"Deleted {len(existing_findings)} existing finding(s) for {repo_name}:{commit_sha[:7]} before rescan")
            finally:
                session.close()
        
        # Run the scan in a background thread to avoid blocking the request
        def run_scan():
            try:
                # Import SecurityReview class
                from ...__main__ import SecurityReview, CommitInfo
                from ...config_loader import agent_config
                
                # Load repository-specific agent configuration if available
                try:
                    if agent_config.load_for_repository(repo_name):
                        logger.info(f"Loaded repository-specific agent configuration for {repo_name}")
                    else:
                        logger.info(f"Using main agent configuration for {repo_name}")
                except Exception as e:
                    logger.warning(f"Failed to load repository-specific agent, using main agent: {e}")
                
                # Get GitHub token
                github_token = os.getenv('GITHUB_TOKEN')
                if not github_token:
                    logger.error("GITHUB_TOKEN not configured")
                    return
                
                # Initialize SecurityReview with configuration from environment
                provider_name = os.environ.get('LLM_PROVIDER', 'anthropic')
                provider_kwargs = {}
                
                # Get docs directory if configured
                docs_dir = os.environ.get('DOCS_DIR')
                voyage_key = os.environ.get('VOYAGE_API_KEY')
                voyage_model = os.environ.get('VOYAGE_MODEL', 'voyage-3-large')
                
                logger.info(f"Starting scan for {repo_name}:{commit_sha[:7]}")
                
                # Initialize reviewer
                reviewer = SecurityReview(
                    provider_name,
                    provider_kwargs,
                    docs_dir=docs_dir,
                    voyage_key=voyage_key,
                    voyage_model=voyage_model
                )
                
                # Analyze the commit
                analysis, cost_info = reviewer.analyze_commit(repo_name, commit_sha)
                
                logger.info(f"Analysis complete for {repo_name}:{commit_sha[:7]} - Vulnerabilities: {analysis.get('has_vulnerabilities', False)}")
                
                # Store the finding in database
                if DATABASE_AVAILABLE:
                    # Get commit info from GitHub
                    github = Github(auth=Auth.Token(github_token))
                    repo = github.get_repo(repo_name)
                    commit = repo.get_commit(commit_sha)
                    
                    # Create CommitInfo object
                    commit_info = CommitInfo(
                        sha=commit.sha,
                        url=commit.html_url,
                        message=commit.commit.message,
                        author=commit.commit.author.name if commit.commit.author else 'Unknown',
                        date=commit.commit.author.date if commit.commit.author else None,
                        branch=None  # Branch info not always available from commit
                    )
                    
                    # Generate HTML content for the finding
                    html_content = f"""<h1>Security Review for {repo_name}</h1>
<p><strong>Commit:</strong> <a href="{commit_info.url}">{commit_info.sha[:7]}</a></p>
<p><strong>Author:</strong> {commit_info.author}</p>
<p><strong>Date:</strong> {commit_info.date}</p>
<p><strong>Message:</strong> {commit_info.message}</p>
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
                    
                    # Store in database
                    db_manager = get_database_manager()
                    finding_uuid = db_manager.store_finding(
                        html_content=html_content,
                        repo_name=repo_name,
                        commit_info=commit_info,
                        analysis=analysis,
                        metadata={'cost_info': str(cost_info) if cost_info else None}
                    )
                    
                    logger.info(f"Stored finding {finding_uuid} for {repo_name}:{commit_sha[:7]}")
                else:
                    logger.warning("Database not available, scan results not stored")
                    
            except Exception as e:
                logger.error(f"Error in background scan: {e}", exc_info=True)
        
        # Start the scan in background
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        logger.info(f"Scan {'re-' if rescan else ''}queued for {repo_name}:{commit_sha[:7]}")
        
        return jsonify({
            'success': True,
            'message': f'Scan {"re-queued" if rescan else "queued"} for commit {commit_sha[:7]}. This may take a few moments.'
        })
        
    except Exception as e:
        logger.error(f"Error scanning commit: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/scan-pr', methods=['POST'])
@login_required
def scan_pr():
    """Scan or rescan a pull request (authenticated users only)."""
    import os
    import threading
    from github import Github, Auth
    
    try:
        data = request.get_json()
        repo_name = data.get('repo_name')
        pr_number = data.get('pr_number')
        rescan = data.get('rescan', False)
        
        if not repo_name or not pr_number:
            return jsonify({'error': 'Repository name and PR number required'}), 400
        
        # Check if PR already has findings
        if DATABASE_AVAILABLE:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                from ...database import SecurityFinding
                existing_findings = session.query(SecurityFinding).filter(
                    SecurityFinding.repo_name == repo_name,
                    SecurityFinding.pr_number == pr_number
                ).all()
                
                if existing_findings and not rescan:
                    # Findings exist and this is not a rescan - prevent duplicate
                    session.close()
                    return jsonify({
                        'success': False,
                        'message': f'PR #{pr_number} has already been scanned. Use rescan if you want to analyze it again.',
                        'finding_uuid': str(existing_findings[0].uuid)
                    }), 400
                elif existing_findings and rescan:
                    # This is a rescan - delete all existing findings for this PR first
                    for finding in existing_findings:
                        session.delete(finding)
                    session.commit()
                    logger.info(f"Deleted {len(existing_findings)} existing finding(s) for {repo_name}:PR#{pr_number} before rescan")
            finally:
                session.close()
        
        # Run the scan in a background thread to avoid blocking the request
        def run_scan():
            try:
                # Import SecurityReview class
                from ...__main__ import SecurityReview, CommitInfo
                from ...config_loader import agent_config
                
                # Load repository-specific agent configuration if available
                try:
                    if agent_config.load_for_repository(repo_name):
                        logger.info(f"Loaded repository-specific agent configuration for {repo_name}")
                    else:
                        logger.info(f"Using main agent configuration for {repo_name}")
                except Exception as e:
                    logger.warning(f"Failed to load repository-specific agent, using main agent: {e}")
                
                # Get GitHub token
                github_token = os.getenv('GITHUB_TOKEN')
                if not github_token:
                    logger.error("GITHUB_TOKEN not configured")
                    return
                
                # Initialize SecurityReview with configuration from environment
                provider_name = os.environ.get('LLM_PROVIDER', 'anthropic')
                provider_kwargs = {}
                
                # Get docs directory if configured
                docs_dir = os.environ.get('DOCS_DIR')
                voyage_key = os.environ.get('VOYAGE_API_KEY')
                voyage_model = os.environ.get('VOYAGE_MODEL', 'voyage-3-large')
                
                logger.info(f"Starting scan for {repo_name}:PR#{pr_number}")
                
                # Initialize reviewer
                reviewer = SecurityReview(
                    provider_name,
                    provider_kwargs,
                    docs_dir=docs_dir,
                    voyage_key=voyage_key,
                    voyage_model=voyage_model
                )
                
                # Get PR information from GitHub
                github = Github(auth=Auth.Token(github_token))
                repo = github.get_repo(repo_name)
                pr = repo.get_pull(int(pr_number))
                
                # Get the head commit SHA for the PR
                head_sha = pr.head.sha
                
                # Analyze the PR's head commit
                analysis, cost_info = reviewer.analyze_commit(repo_name, head_sha)
                
                logger.info(f"Analysis complete for {repo_name}:PR#{pr_number} - Vulnerabilities: {analysis.get('has_vulnerabilities', False)}")
                
                # Store the finding in database
                if DATABASE_AVAILABLE:
                    # Create CommitInfo object
                    commit_info = CommitInfo(
                        sha=head_sha,
                        url=pr.html_url,
                        message=pr.title,
                        author=pr.user.login if pr.user else 'Unknown',
                        date=pr.created_at,
                        branch=pr.head.ref
                    )
                    
                    # Generate HTML content for the finding
                    pr_state = 'merged' if pr.merged else pr.state
                    html_content = f"""<h1>Security Review for {repo_name}</h1>
<h2>Pull Request #{pr_number}: {pr.title}</h2>
<p><strong>PR URL:</strong> <a href="{pr.html_url}">{pr.html_url}</a></p>
<p><strong>State:</strong> {pr_state}</p>
<p><strong>Author:</strong> {pr.user.login if pr.user else 'Unknown'}</p>
<p><strong>Created:</strong> {pr.created_at}</p>
<p><strong>Updated:</strong> {pr.updated_at}</p>
<p><strong>Head SHA:</strong> <a href="{commit_info.url}">{head_sha[:7]}</a></p>
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
                    
                    # Store in database with PR metadata
                    db_manager = get_database_manager()
                    finding_uuid = db_manager.store_finding(
                        html_content=html_content,
                        repo_name=repo_name,
                        commit_info=commit_info,
                        analysis=analysis,
                        metadata={
                            'cost_info': str(cost_info) if cost_info else None,
                            'pr_number': pr_number,
                            'pr_title': pr.title,
                            'pr_state': pr_state
                        }
                    )
                    
                    # Update the finding with PR information
                    session = db_manager.get_session()
                    try:
                        from ...database import SecurityFinding
                        finding_record = session.query(SecurityFinding).filter(
                            SecurityFinding.uuid == finding_uuid
                        ).first()
                        
                        if finding_record:
                            finding_record.pr_number = pr_number
                            finding_record.pr_title = pr.title
                            finding_record.pr_state = pr_state
                            session.commit()
                    finally:
                        session.close()
                    
                    logger.info(f"Stored finding {finding_uuid} for {repo_name}:PR#{pr_number}")
                else:
                    logger.warning("Database not available, scan results not stored")
                    
            except Exception as e:
                logger.error(f"Error in background PR scan: {e}", exc_info=True)
        
        # Start the scan in background
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        logger.info(f"Scan {'re-' if rescan else ''}queued for {repo_name}:PR#{pr_number}")
        
        return jsonify({
            'success': True,
            'message': f'Scan {"re-queued" if rescan else "queued"} for PR #{pr_number}. This may take a few moments.'
        })
        
    except Exception as e:
        logger.error(f"Error scanning PR: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500
