"""
Findings routes blueprint for viewing and managing security findings.
"""

import os
import logging
from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app
from ..auth import get_auth_service
from ..decorators import login_required
from ..services import FindingsService, RepositoryService, PaginationService
from ..utils import render_finding_page, render_error_page, generate_example_report

logger = logging.getLogger(__name__)

findings_bp = Blueprint('findings_bp', __name__)

# Import database layer
try:
    from ...database import get_database_manager
    DATABASE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database not available: {e}")
    DATABASE_AVAILABLE = False


@findings_bp.route('/alerts')
@login_required
def alerts():
    """Show alerts/findings list (authenticated users only)."""
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get filter parameters
    vulnerability_filter = request.args.get('vulnerability_filter', 'vulnerable')
    repository_filter = request.args.get('repository_filter', '')
    status_filter = request.args.get('status_filter', 'unassigned')
    classification_filter = request.args.get('classification_filter', '')
    user_filter = request.args.get('user_filter', '')
    
    # Validate per_page values
    if per_page not in [10, 25, 50, 75, 100]:
        per_page = 10
    
    try:
        auth_service = get_auth_service()
        user = auth_service.get_current_user()
        
        # Get all findings for statistics (unfiltered)
        all_findings = FindingsService.get_all_findings(user_email=user['email'])
        
        # Apply filters to get filtered dataset
        filtered_findings = FindingsService.apply_filters(
            all_findings, 
            vulnerability_filter, 
            repository_filter, 
            status_filter, 
            classification_filter,
            user_filter
        )
        
        # Get repositories and users
        repositories = RepositoryService.load_repositories()
        
        # Get user's repository access for filtering
        user_accessible_repos = None
        if DATABASE_AVAILABLE:
            try:
                db_manager = get_database_manager()
                user_accessible_repos = db_manager.get_user_repository_access(user['email'])
            except Exception as e:
                logger.error(f"Error getting user repository access: {e}")
        
        # Filter unique users based on user's repository access
        unique_users = RepositoryService.get_unique_users(user_accessible_repos)
        
        # Filter repositories based on user access (for repository dropdown)
        if user_accessible_repos:
            accessible_repositories = [repo for repo in repositories if repo['name'] in user_accessible_repos]
        else:
            accessible_repositories = repositories
        
        # Paginate filtered results
        paginated_findings, pagination = PaginationService.paginate(filtered_findings, page, per_page)
        
        # Current filter state
        current_filters = {
            'vulnerability_filter': vulnerability_filter,
            'repository_filter': repository_filter,
            'status_filter': status_filter,
            'classification_filter': classification_filter,
            'user_filter': user_filter
        }
        
        # Calculate filtered statistics
        filtered_stats = {
            'total': len(filtered_findings),
            'vulnerable': len([f for f in filtered_findings if f.get('has_vulnerabilities')]),
            'safe': len([f for f in filtered_findings if not f.get('has_vulnerabilities')])
        }
        
        return render_template('findings_list.html', 
                             findings=paginated_findings,
                             all_findings=all_findings,
                             user=user,
                             total_findings=len(all_findings),
                             repositories=repositories,
                             accessible_repositories=accessible_repositories,
                             unique_users=unique_users,
                             pagination=pagination,
                             current_filters=current_filters,
                             filtered_stats=filtered_stats)
    except Exception as e:
        logger.error(f"Error showing findings list: {e}")
        flash('Error loading findings', 'error')
        return render_template('findings_list.html', 
                             findings=[],
                             all_findings=[],
                             user=auth_service.get_current_user(),
                             total_findings=0,
                             repositories=[],
                             accessible_repositories=[],
                             unique_users=[],
                             pagination={'page': 1, 'per_page': per_page, 'total': 0, 'pages': 0, 
                                       'has_prev': False, 'has_next': False, 'iter_pages': []},
                             current_filters={'vulnerability_filter': 'vulnerable', 'repository_filter': '', 
                                            'status_filter': 'unassigned', 'classification_filter': '', 
                                            'user_filter': ''},
                             filtered_stats={'total': 0, 'vulnerable': 0, 'safe': 0})


@findings_bp.route('/finding/<finding_id>')
def view_finding(finding_id):
    """Redirect to triage view."""
    return redirect(url_for('findings_bp.triage_finding', finding_uuid=finding_id))


@findings_bp.route('/report/<finding_uuid>')
def public_finding(finding_uuid):
    """Public access to findings via UUID (for backwards compatibility)."""
    # This route allows public access to findings via UUID links
    # No authentication required - this maintains backwards compatibility
    
    # Handle example report
    if finding_uuid == 'example-report':
        finding_data = generate_example_report()
        return render_finding_page(finding_data, finding_uuid, is_authenticated=False)
    
    # Get finding from database
    finding_data = None
    if DATABASE_AVAILABLE:
        try:
            db_manager = get_database_manager()
            finding_data = db_manager.get_finding(finding_uuid)
        except Exception as e:
            logger.error(f"Error retrieving finding {finding_uuid}: {e}")
    
    if not finding_data:
        return render_error_page("Finding not found or has expired", 404)
    
    auth_service = get_auth_service()
    return render_finding_page(finding_data, finding_uuid, 
                              is_authenticated=auth_service.is_authenticated())


@findings_bp.route('/triage/<finding_uuid>')
def triage_finding(finding_uuid):
    """View finding with optional triage controls (public access with limited data for unauthenticated users)."""
    
    if not DATABASE_AVAILABLE:
        return render_error_page("Database not available", 503)
    
    try:
        db_manager = get_database_manager()
        finding = db_manager.get_finding_full(finding_uuid)
        
        if not finding:
            return render_error_page("Finding not found", 404)
        
        auth_service = get_auth_service()
        is_authenticated = auth_service.is_authenticated()
        user = auth_service.get_current_user() if is_authenticated else None
        
        # Prepare finding data based on authentication status
        finding_data = finding.to_dict()
        
        if not is_authenticated:
            # Remove sensitive triage data for unauthenticated users
            sensitive_fields = [
                'triage_status', 'assigned_to', 'assigned_at', 
                'completion_classification', 'completed_at', 'completed_by',
                'triage_notes', 'status_history', 'priority', 'severity'
            ]
            for field in sensitive_fields:
                finding_data.pop(field, None)
        
        return render_template('finding_detail.html', 
                             finding=finding_data,
                             user=user,
                             is_authenticated=is_authenticated,
                             google_client_id=current_app.config.get('GOOGLE_CLIENT_ID'))
        
    except Exception as e:
        logger.error(f"Error retrieving finding for triage {finding_uuid}: {e}")
        return render_error_page("Error loading finding", 500)


@findings_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    """User settings page (authenticated users only)."""
    if not DATABASE_AVAILABLE:
        flash('Database not available', 'error')
        return redirect(url_for('main_bp.index'))
    
    try:
        auth_service = get_auth_service()
        db_manager = get_database_manager()
        current_user = auth_service.get_current_user()
        user_data = db_manager.get_user(current_user['email'])
        
        if not user_data:
            flash('User data not found', 'error')
            return redirect(url_for('main_bp.index'))
        
        if request.method == 'GET':
            return render_template('user_settings.html', 
                                 user=current_user,
                                 user_data=user_data.to_dict())
        
        # Handle POST request (save settings)
        email_notifications = request.form.get('email_notifications') == 'on'
        
        # Update user's email notification preference
        success = db_manager.update_user(
            email=current_user['email'],
            email_notifications_enabled=email_notifications
        )
        
        if success:
            flash('Settings updated successfully', 'success')
        else:
            flash('Failed to update settings', 'error')
        
        return redirect(url_for('findings_bp.user_settings'))
        
    except Exception as e:
        logger.error(f"Error in user settings for {current_user['email']}: {e}")
        flash('Error loading settings', 'error')
        return redirect(url_for('main_bp.index'))
