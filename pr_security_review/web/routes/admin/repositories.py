"""
Admin repository management routes.
"""

import logging
import threading
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from ...auth import get_auth_service
from ...decorators import admin_required
from ...services import RepositoryService
from ....agent_files import discover_agent_files
from ....review_scheduler import trigger_repository_bootstrap_review

logger = logging.getLogger(__name__)

repositories_bp = Blueprint('repositories_bp', __name__)

# Import database layer
try:
    from ....database import get_database_manager, Repository
    DATABASE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database not available: {e}")
    DATABASE_AVAILABLE = False


def _parse_branch_configs_from_form() -> list[dict]:
    branch_names = request.form.getlist('branch_name[]')
    starting_commit_shas = request.form.getlist('starting_commit_sha[]')
    hardfork_names = request.form.getlist('hardfork_name[]')

    branch_configs = []
    seen = set()
    for index, branch_name in enumerate(branch_names):
        normalized_branch = branch_name.strip()
        if not normalized_branch or normalized_branch in seen:
            continue

        branch_configs.append({
            'branch_name': normalized_branch,
            'starting_commit_sha': (starting_commit_shas[index] if index < len(starting_commit_shas) else '').strip() or None,
            'hardfork_name': (hardfork_names[index] if index < len(hardfork_names) else '').strip() or None,
        })
        seen.add(normalized_branch)

    return branch_configs


def _trigger_bootstrap_review(repo_name: str) -> None:
    worker = threading.Thread(
        target=trigger_repository_bootstrap_review,
        args=(repo_name,),
        daemon=True,
    )
    worker.start()


@repositories_bp.route('/create', methods=['GET', 'POST'])
@admin_required
def create():
    """Create a new repository (admin only)."""
    if not DATABASE_AVAILABLE:
        flash('Database not available', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
    
    auth_service = get_auth_service()
    
    if request.method == 'GET':
        return render_template(
            'admin/create_repository.html',
            agent_files=discover_agent_files(),
            user=auth_service.get_current_user()
        )
    
    try:
        # Get form data
        url = request.form.get('url', '').strip()
        branch_configs = _parse_branch_configs_from_form()
        agent_file_path = request.form.get('agent_file_path', '').strip()
        telegram_channel_id = request.form.get('telegram_channel_id', '').strip()
        notify_default_channel = request.form.get('notify_default_channel') == 'on'
        
        # Validate input
        if not url:
            flash('Repository URL is required', 'error')
            return redirect(url_for('admin_bp.repositories_bp.create'))
        
        available_agent_files = discover_agent_files()
        if not agent_file_path:
            flash('An agent file selection is required', 'error')
            return redirect(url_for('admin_bp.repositories_bp.create'))
        if agent_file_path not in available_agent_files:
            flash('Selected agent file is not available', 'error')
            return redirect(url_for('admin_bp.repositories_bp.create'))

        if not branch_configs:
            flash('At least one valid branch configuration is required', 'error')
            return redirect(url_for('admin_bp.repositories_bp.create'))
        
        # Extract repository name from URL
        repo_name = Repository.extract_repo_name_from_url(url)
        
        # Create repository
        db_manager = get_database_manager()
        current_user = auth_service.get_current_user()
        
        success = db_manager.create_repository(
            name=repo_name,
            url=url,
            branch_configs=branch_configs,
            agent_file_path=agent_file_path,
            telegram_channel_id=telegram_channel_id if telegram_channel_id else None,
            notify_default_channel=notify_default_channel,
            created_by=current_user['email']
        )
        
        if success:
            # Send audit email
            try:
                from ....email_notifications import get_email_service
                email_service = get_email_service()
                repository_data = {
                    'name': repo_name,
                    'url': url,
                    'branches': [config['branch_name'] for config in branch_configs],
                    'branch_configs': branch_configs,
                    'agent_file_path': agent_file_path,
                    'telegram_channel_id': telegram_channel_id,
                    'notify_default_channel': notify_default_channel,
                    'is_active': True
                }
                email_service.send_repository_creation_notification(
                    db_manager=db_manager,
                    repository_data=repository_data,
                    created_by=current_user['email']
                )
                logger.info(f"Audit email sent for repository creation: {repo_name}")
            except Exception as email_error:
                logger.error(f"Failed to send repository creation audit email: {email_error}")
            
            flash(f'Repository {repo_name} created successfully', 'success')
            _trigger_bootstrap_review(repo_name)
            return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
        else:
            flash('Failed to create repository. Repository may already exist.', 'error')
            return redirect(url_for('admin_bp.repositories_bp.create'))
        
    except Exception as e:
        logger.error(f"Error creating repository: {e}")
        flash('Error creating repository', 'error')
        return redirect(url_for('admin_bp.repositories_bp.create'))


@repositories_bp.route('/<path:repo_name>/edit', methods=['GET', 'POST'])
@admin_required
def edit(repo_name):
    """Edit a repository (admin only)."""
    if not DATABASE_AVAILABLE:
        flash('Database not available', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
    
    try:
        auth_service = get_auth_service()
        db_manager = get_database_manager()
        repository = db_manager.get_repository(repo_name)
        
        if not repository:
            flash('Repository not found', 'error')
            return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
        
        if request.method == 'GET':
            return render_template(
                'admin/edit_repository.html',
                repository=repository.to_dict(),
                agent_files=discover_agent_files(),
                user=auth_service.get_current_user()
            )
        
        # Handle POST request
        url = request.form.get('url', '').strip()
        branch_configs = _parse_branch_configs_from_form()
        agent_file_path = request.form.get('agent_file_path', '').strip()
        telegram_channel_id = request.form.get('telegram_channel_id', '').strip()
        notify_default_channel = request.form.get('notify_default_channel') == 'on'
        is_active = request.form.get('is_active') == 'on'
        
        # Validate input
        if not url:
            flash('Repository URL is required', 'error')
            return redirect(url_for('admin_bp.repositories_bp.edit', repo_name=repo_name))
        
        available_agent_files = discover_agent_files()
        if not agent_file_path:
            flash('An agent file selection is required', 'error')
            return redirect(url_for('admin_bp.repositories_bp.edit', repo_name=repo_name))
        if agent_file_path not in available_agent_files:
            flash('Selected agent file is not available', 'error')
            return redirect(url_for('admin_bp.repositories_bp.edit', repo_name=repo_name))

        if not branch_configs:
            flash('At least one valid branch configuration is required', 'error')
            return redirect(url_for('admin_bp.repositories_bp.edit', repo_name=repo_name))
        
        old_repository_data = repository.to_dict()
        
        current_user = auth_service.get_current_user()
        success = db_manager.update_repository(
            name=repo_name,
            url=url,
            branch_configs=branch_configs,
            agent_file_path=agent_file_path,
            telegram_channel_id=telegram_channel_id if telegram_channel_id else None,
            notify_default_channel=notify_default_channel,
            is_active=is_active,
            updated_by=current_user['email']
        )
        
        if success:
            # Send audit email
            try:
                from ....email_notifications import get_email_service
                email_service = get_email_service()
                new_repository_data = {
                    'name': repo_name,
                    'url': url,
                    'branches': [config['branch_name'] for config in branch_configs],
                    'branch_configs': branch_configs,
                    'agent_file_path': agent_file_path,
                    'telegram_channel_id': telegram_channel_id,
                    'notify_default_channel': notify_default_channel,
                    'is_active': is_active
                }
                email_service.send_repository_modification_notification(
                    db_manager=db_manager,
                    old_repository_data=old_repository_data,
                    new_repository_data=new_repository_data,
                    modified_by=current_user['email']
                )
                logger.info(f"Audit email sent for repository modification: {repo_name}")
            except Exception as email_error:
                logger.error(f"Failed to send repository modification audit email: {email_error}")
            
            flash(f'Repository {repo_name} updated successfully', 'success')
            if not old_repository_data.get('is_active') and is_active:
                _trigger_bootstrap_review(repo_name)
            return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
        else:
            flash('Failed to update repository', 'error')
            return redirect(url_for('admin_bp.repositories_bp.edit', repo_name=repo_name))
        
    except Exception as e:
        logger.error(f"Error editing repository {repo_name}: {e}")
        flash('Error editing repository', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))


@repositories_bp.route('/<path:repo_name>/delete', methods=['POST'])
@admin_required
def delete(repo_name):
    """Delete a repository (admin only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        auth_service = get_auth_service()
        db_manager = get_database_manager()
        current_user = auth_service.get_current_user()
        
        repository = db_manager.get_repository(repo_name)
        if not repository:
            return jsonify({'error': 'Repository not found'}), 404
        
        repository_data = repository.to_dict()
        success = db_manager.delete_repository(repo_name)
        
        if success:
            try:
                from ....email_notifications import get_email_service
                email_service = get_email_service()
                email_service.send_repository_deletion_notification(
                    db_manager=db_manager,
                    repository_data=repository_data,
                    deleted_by=current_user['email']
                )
                logger.info(f"Audit email sent for repository deletion: {repo_name}")
            except Exception as email_error:
                logger.error(f"Failed to send repository deletion audit email: {email_error}")
            
            return jsonify({'success': True, 'message': f'Repository {repo_name} deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete repository or repository not found'}), 500
        
    except Exception as e:
        logger.error(f"Error deleting repository {repo_name}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@repositories_bp.route('/<path:repo_name>/toggle-status', methods=['POST'])
@admin_required
def toggle_status(repo_name):
    """Toggle repository active status (admin only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        auth_service = get_auth_service()
        db_manager = get_database_manager()
        current_user = auth_service.get_current_user()
        
        repository = db_manager.get_repository(repo_name)
        if not repository:
            return jsonify({'error': 'Repository not found'}), 404
        
        new_status = not repository.is_active
        
        success = db_manager.update_repository(
            name=repo_name,
            is_active=new_status,
            updated_by=current_user['email']
        )
        
        if success:
            status_text = 'active' if new_status else 'inactive'
            if new_status:
                _trigger_bootstrap_review(repo_name)
            return jsonify({
                'success': True, 
                'message': f'Repository {repo_name} is now {status_text}',
                'is_active': new_status
            })
        else:
            return jsonify({'error': 'Failed to update repository status'}), 500
        
    except Exception as e:
        logger.error(f"Error toggling repository status {repo_name}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@repositories_bp.route('/', methods=['GET'])
@admin_required
def list_repositories():
    """Get all repositories API endpoint (admin only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        db_manager = get_database_manager()
        repositories = db_manager.get_all_repositories(include_inactive=True)
        return jsonify({'success': True, 'repositories': repositories})
        
    except Exception as e:
        logger.error(f"Error fetching repositories: {e}")
        return jsonify({'error': 'Failed to fetch repositories'}), 500
