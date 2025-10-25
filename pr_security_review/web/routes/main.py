"""
Main routes blueprint for home and dashboard pages.
"""

import logging
from flask import Blueprint, render_template, redirect, url_for
from ..auth import get_auth_service
from ..decorators import login_required
from ..services import FindingsService

logger = logging.getLogger(__name__)

main_bp = Blueprint('main_bp', __name__)


@main_bp.route('/')
def index():
    """Main page - shows login if not authenticated, dashboard if authenticated."""
    auth_service = get_auth_service()
    if not auth_service.is_authenticated():
        return redirect(url_for('auth_bp.login'))
    
    # User is authenticated, show dashboard
    return show_dashboard()


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page (alternative route)."""
    return show_dashboard()


@main_bp.route('/health')
def health():
    """Health check endpoint."""
    from datetime import datetime, timezone
    from flask import jsonify
    
    status = {
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'database': False
    }
    
    # Check database
    try:
        from ...database import get_database_manager
        db_manager = get_database_manager()
        status['database'] = db_manager.health_check()
    except Exception:
        pass
    
    return jsonify(status)


def show_dashboard() -> str:
    """Show the dashboard page."""
    try:
        auth_service = get_auth_service()
        
        # Get all findings
        user_email = auth_service.get_current_user()['email'] if auth_service.is_authenticated() else None
        all_findings = FindingsService.get_all_findings(user_email=user_email)
        
        # Calculate statistics
        stats = FindingsService.calculate_statistics(all_findings)
        
        # Get recent VULNERABLE findings only (last 10)
        vulnerable_findings = [f for f in all_findings if f.get('has_vulnerabilities')]
        recent_findings = vulnerable_findings[:10]
        
        return render_template('dashboard.html',
                             stats=stats,
                             recent_findings=recent_findings,
                             user=auth_service.get_current_user())
        
    except Exception as e:
        logger.error(f"Error showing dashboard: {e}")
        from flask import flash
        flash('Error loading dashboard', 'error')
        return redirect(url_for('main_bp.index'))
