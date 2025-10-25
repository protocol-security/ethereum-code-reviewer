"""
Admin dashboard routes.
"""

import logging
from flask import Blueprint, render_template, redirect, url_for, flash
from ...auth import get_auth_service
from ...decorators import admin_required
from ...services import RepositoryService

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard_bp', __name__)

# Import database layer
try:
    from ....database import get_database_manager
    DATABASE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database not available: {e}")
    DATABASE_AVAILABLE = False


@dashboard_bp.route('/')
@admin_required
def admin_dashboard():
    """Admin dashboard (admin users only)."""
    if not DATABASE_AVAILABLE:
        flash('Database not available', 'error')
        return redirect(url_for('main_bp.index'))
    
    try:
        auth_service = get_auth_service()
        db_manager = get_database_manager()
        users = db_manager.get_all_users()
        repositories = RepositoryService.load_repositories()
        
        return render_template('admin/dashboard.html', 
                             users=users,
                             repositories=repositories,
                             user=auth_service.get_current_user())
        
    except Exception as e:
        logger.error(f"Error loading admin dashboard: {e}")
        flash('Error loading admin dashboard', 'error')
        return redirect(url_for('main_bp.index'))
