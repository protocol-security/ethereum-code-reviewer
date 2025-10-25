"""
Admin user management routes.
"""

import logging
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from ...auth import get_auth_service
from ...decorators import admin_required
from ...services import RepositoryService

logger = logging.getLogger(__name__)

users_bp = Blueprint('users_bp', __name__)

# Import database layer
try:
    from ....database import get_database_manager
    DATABASE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database not available: {e}")
    DATABASE_AVAILABLE = False


@users_bp.route('/create', methods=['GET', 'POST'])
@admin_required
def create():
    """Create a new user (admin only)."""
    if not DATABASE_AVAILABLE:
        flash('Database not available', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
    
    auth_service = get_auth_service()
    
    if request.method == 'GET':
        repositories = RepositoryService.load_repositories()
        return render_template('admin/create_user.html', 
                             repositories=repositories,
                             user=auth_service.get_current_user())
    
    try:
        # Get form data
        email = request.form.get('email', '').strip()
        name = request.form.get('name', '').strip()
        is_admin = request.form.get('is_admin') == 'on'
        
        # Only owners can create admin users
        if is_admin and not auth_service.is_owner():
            flash('Only owners can create admin users', 'error')
            return redirect(url_for('admin_bp.users_bp.create'))
        
        # Get repository access
        repository_access = []
        access_type = request.form.get('access_type')
        if access_type == 'specific':
            repository_access = request.form.getlist('repositories')
        elif access_type == 'all':
            repository_access = None
        
        # Validate input
        if not email:
            flash('Email is required', 'error')
            return redirect(url_for('admin_bp.users_bp.create'))
        
        if not name:
            flash('Name is required', 'error')
            return redirect(url_for('admin_bp.users_bp.create'))
        
        # Create user
        db_manager = get_database_manager()
        current_user = auth_service.get_current_user()
        
        success = db_manager.create_user(
            email=email,
            name=name,
            is_admin=is_admin,
            repository_access=repository_access,
            created_by=current_user['email']
        )
        
        if success:
            flash(f'User {email} created successfully', 'success')
            return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
        else:
            flash('Failed to create user. User may already exist.', 'error')
            return redirect(url_for('admin_bp.users_bp.create'))
        
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        flash('Error creating user', 'error')
        return redirect(url_for('admin_bp.users_bp.create'))


@users_bp.route('/<email>/edit', methods=['GET', 'POST'])
@admin_required
def edit(email):
    """Edit a user (admin only)."""
    if not DATABASE_AVAILABLE:
        flash('Database not available', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
    
    try:
        auth_service = get_auth_service()
        db_manager = get_database_manager()
        user_data = db_manager.get_user(email)
        
        if not user_data:
            flash('User not found', 'error')
            return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
        
        if request.method == 'GET':
            repositories = RepositoryService.load_repositories()
            return render_template('admin/edit_user.html', 
                                 user_data=user_data.to_dict(),
                                 repositories=repositories,
                                 user=auth_service.get_current_user())
        
        # Handle POST request
        name = request.form.get('name', '').strip()
        is_admin = request.form.get('is_admin') == 'on'
        is_active = request.form.get('is_active') == 'on'
        email_notifications = request.form.get('email_notifications') == 'on'
        
        # Get repository access
        repository_access = []
        access_type = request.form.get('access_type')
        if access_type == 'specific':
            repository_access = request.form.getlist('repositories')
        elif access_type == 'all':
            repository_access = None
        
        # Validate input
        if not name:
            flash('Name is required', 'error')
            return redirect(url_for('admin_bp.users_bp.edit', email=email))
        
        # Update user
        success = db_manager.update_user(
            email=email,
            name=name,
            is_admin=is_admin,
            repository_access=repository_access,
            is_active=is_active,
            email_notifications_enabled=email_notifications
        )
        
        if success:
            flash(f'User {email} updated successfully', 'success')
            return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
        else:
            flash('Failed to update user', 'error')
            return redirect(url_for('admin_bp.users_bp.edit', email=email))
        
    except Exception as e:
        logger.error(f"Error editing user {email}: {e}")
        flash('Error editing user', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))


@users_bp.route('/<email>/delete', methods=['POST'])
@admin_required
def delete(email):
    """Delete a user (admin only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        db_manager = get_database_manager()
        
        # Check if user is owner before attempting deletion
        user_data = db_manager.get_user(email)
        if user_data and user_data.is_owner:
            return jsonify({'error': 'Cannot delete owner user'}), 400
        
        success = db_manager.delete_user(email)
        
        if success:
            return jsonify({'success': True, 'message': f'User {email} deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete user or user not found'}), 500
        
    except Exception as e:
        logger.error(f"Error deleting user {email}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@users_bp.route('/', methods=['GET'])
@admin_required
def list_users():
    """Get all users API endpoint (admin only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        db_manager = get_database_manager()
        users = db_manager.get_all_users()
        return jsonify({'success': True, 'users': users})
        
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return jsonify({'error': 'Failed to fetch users'}), 500
