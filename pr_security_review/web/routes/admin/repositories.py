"""
Admin repository and document management routes.
"""

import os
import logging
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from ...auth import get_auth_service
from ...decorators import admin_required
from ...services import RepositoryService

logger = logging.getLogger(__name__)

repositories_bp = Blueprint('repositories_bp', __name__)

# Import database layer
try:
    from ....database import get_database_manager, Repository
    DATABASE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database not available: {e}")
    DATABASE_AVAILABLE = False


@repositories_bp.route('/create', methods=['GET', 'POST'])
@admin_required
def create():
    """Create a new repository (admin only)."""
    if not DATABASE_AVAILABLE:
        flash('Database not available', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
    
    auth_service = get_auth_service()
    
    if request.method == 'GET':
        return render_template('admin/create_repository.html', 
                             user=auth_service.get_current_user())
    
    try:
        # Get form data
        url = request.form.get('url', '').strip()
        branches_str = request.form.get('branches', '').strip()
        telegram_channel_id = request.form.get('telegram_channel_id', '').strip()
        notify_default_channel = request.form.get('notify_default_channel') == 'on'
        
        # Validate input
        if not url:
            flash('Repository URL is required', 'error')
            return redirect(url_for('admin_bp.repositories_bp.create'))
        
        if not branches_str:
            flash('At least one branch is required', 'error')
            return redirect(url_for('admin_bp.repositories_bp.create'))
        
        # Parse branches
        branches = [branch.strip() for branch in branches_str.split(',') if branch.strip()]
        
        if not branches:
            flash('At least one valid branch is required', 'error')
            return redirect(url_for('admin_bp.repositories_bp.create'))
        
        # Extract repository name from URL
        repo_name = Repository.extract_repo_name_from_url(url)
        
        # Create repository
        db_manager = get_database_manager()
        current_user = auth_service.get_current_user()
        
        success = db_manager.create_repository(
            name=repo_name,
            url=url,
            branches=branches,
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
                    'branches': branches,
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
            agents = db_manager.get_all_agents()
            return render_template('admin/edit_repository.html', 
                                 repository=repository.to_dict(),
                                 agents=agents,
                                 user=auth_service.get_current_user())
        
        # Handle POST request
        url = request.form.get('url', '').strip()
        branches_str = request.form.get('branches', '').strip()
        telegram_channel_id = request.form.get('telegram_channel_id', '').strip()
        notify_default_channel = request.form.get('notify_default_channel') == 'on'
        is_active = request.form.get('is_active') == 'on'
        
        agent_id_str = request.form.get('agent_id', '').strip()
        agent_id = int(agent_id_str) if agent_id_str else None
        
        # Validate input
        if not url:
            flash('Repository URL is required', 'error')
            return redirect(url_for('admin_bp.repositories_bp.edit', repo_name=repo_name))
        
        if not branches_str:
            flash('At least one branch is required', 'error')
            return redirect(url_for('admin_bp.repositories_bp.edit', repo_name=repo_name))
        
        branches = [branch.strip() for branch in branches_str.split(',') if branch.strip()]
        
        if not branches:
            flash('At least one valid branch is required', 'error')
            return redirect(url_for('admin_bp.repositories_bp.edit', repo_name=repo_name))
        
        old_repository_data = repository.to_dict()
        
        current_user = auth_service.get_current_user()
        success = db_manager.update_repository(
            name=repo_name,
            url=url,
            branches=branches,
            telegram_channel_id=telegram_channel_id if telegram_channel_id else None,
            notify_default_channel=notify_default_channel,
            is_active=is_active,
            updated_by=current_user['email']
        )
        
        if success:
            agent_success = db_manager.update_repository_agent(
                repo_name=repo_name,
                agent_id=agent_id,
                updated_by=current_user['email']
            )
            if not agent_success:
                logger.warning(f"Failed to update agent for repository {repo_name}")
        
        if success:
            # Send audit email
            try:
                from ....email_notifications import get_email_service
                email_service = get_email_service()
                new_repository_data = {
                    'name': repo_name,
                    'url': url,
                    'branches': branches,
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


# Document management routes
@repositories_bp.route('/<path:repo_name>/documents')
@admin_required
def documents(repo_name):
    """View and manage documents for a repository (admin only)."""
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
        
        documents = db_manager.get_repository_documents(repo_name)
        
        return render_template('admin/repository_documents.html',
                             repository=repository.to_dict(),
                             documents=documents,
                             user=auth_service.get_current_user())
        
    except Exception as e:
        logger.error(f"Error loading documents for repository {repo_name}: {e}")
        flash('Error loading documents', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))


@repositories_bp.route('/<path:repo_name>/documents/upload', methods=['POST'])
@admin_required
def upload_document(repo_name):
    """Upload a document for a repository (admin only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        allowed_extensions = {'.pdf', '.txt', '.md', '.markdown'}
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in allowed_extensions:
            return jsonify({'error': f'Invalid file type. Allowed: {", ".join(allowed_extensions)}'}), 400
        
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as temp_file:
            file.save(temp_file.name)
            temp_path = temp_file.name
        
        try:
            from ....voyage_vector_store import get_voyage_vector_store
            
            voyage_store = get_voyage_vector_store()
            if not voyage_store:
                return jsonify({'error': 'Voyage AI not configured. Set VOYAGE_API_KEY environment variable.'}), 500
            
            content = voyage_store.read_file_content(temp_path)
            embedding = voyage_store.generate_embedding(content)
            file_size = os.path.getsize(temp_path)
            
            auth_service = get_auth_service()
            db_manager = get_database_manager()
            current_user = auth_service.get_current_user()
            
            success = db_manager.create_repository_document(
                repository_name=repo_name,
                filename=file.filename,
                content=content,
                file_type=file_ext.lstrip('.'),
                file_size=file_size,
                embedding=embedding,
                created_by=current_user['email']
            )
            
            if success:
                return jsonify({'success': True, 'message': f'Document {file.filename} uploaded successfully'})
            else:
                return jsonify({'error': 'Failed to store document'}), 500
            
        finally:
            try:
                os.unlink(temp_path)
            except Exception:
                pass
        
    except Exception as e:
        logger.error(f"Error uploading document for repository {repo_name}: {e}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@repositories_bp.route('/<path:repo_name>/documents/<int:doc_id>/delete', methods=['POST'])
@admin_required
def delete_document(repo_name, doc_id):
    """Delete a document (admin only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        db_manager = get_database_manager()
        
        document = db_manager.get_repository_document(doc_id)
        if not document:
            return jsonify({'error': 'Document not found'}), 404
        
        if document.repository_name != repo_name:
            return jsonify({'error': 'Document does not belong to this repository'}), 400
        
        success = db_manager.delete_repository_document(doc_id)
        
        if success:
            return jsonify({'success': True, 'message': 'Document deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete document'}), 500
        
    except Exception as e:
        logger.error(f"Error deleting document {doc_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500
