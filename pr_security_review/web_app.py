"""
Flask web application with Google Sign-In authentication for security findings.
"""

import os
import json
import secrets
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import logging

# Load environment variables from .env file
try:
    import dotenv
    dotenv.load_dotenv()
except ImportError:
    pass  # dotenv is optional, continue without it

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_session import Session
from google.oauth2 import id_token
from google.auth.transport import requests
from google.auth.exceptions import GoogleAuthError

# Import database layer
try:
    from .database import get_database_manager, SecurityFinding, User
    from .findings_server import get_server
    DATABASE_AVAILABLE = True
except ImportError as e:
    print(f"Database not available: {e}")
    DATABASE_AVAILABLE = False

logger = logging.getLogger(__name__)

class SecurityFinderApp:
    """Main Flask application for security findings with Google authentication."""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_config()
        self.setup_routes()
        
        # Initialize Flask-Session
        Session(self.app)
        
        # Google OAuth settings
        self.google_client_id = os.getenv('GOOGLE_CLIENT_ID')
        if not self.google_client_id:
            logger.warning("GOOGLE_CLIENT_ID not set. Google Sign-In will not work.")
        
        # Authorized email whitelist
        self.authorized_emails = self._load_authorized_emails()
        
        logger.info("Security Finder web app initialized")
    
    def setup_config(self):
        """Configure Flask application settings."""
        self.app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
        self.app.config['SESSION_TYPE'] = 'filesystem'
        self.app.config['SESSION_PERMANENT'] = False
        self.app.config['SESSION_USE_SIGNER'] = True
        self.app.config['SESSION_KEY_PREFIX'] = 'security_finder:'
        
        # Session security
        self.app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'
        self.app.config['SESSION_COOKIE_HTTPONLY'] = True
        self.app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    def _load_authorized_emails(self) -> List[str]:
        """Load authorized email addresses from environment or config."""
        # Check environment variable first
        emails_env = os.getenv('AUTHORIZED_EMAILS', '')
        if emails_env:
            return [email.strip() for email in emails_env.split(',') if email.strip()]
        
        # Default whitelist if none provided
        default_emails = ['']
        
        # Try to load from config file
        try:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    if 'authorized_emails' in config:
                        return config['authorized_emails']
        except Exception as e:
            logger.warning(f"Could not load authorized emails from config: {e}")
        
        return default_emails
    
    def _load_repositories(self) -> List[Dict[str, Any]]:
        """Load repository configuration from database."""
        if not DATABASE_AVAILABLE:
            return []
        
        try:
            db_manager = get_database_manager()
            repositories = db_manager.get_all_repositories(include_inactive=True)
            
            # Convert database format to expected format
            repo_list = []
            for repo in repositories:
                repo_list.append({
                    'name': repo['name'],
                    'url': repo['url'],
                    'branches': repo['branches'],
                    'telegram_channel_id': repo.get('telegram_channel_id'),
                    'notify_default_channel': repo.get('notify_default_channel', False),
                    'is_active': repo.get('is_active', True),
                    'created_at': repo.get('created_at'),
                    'created_by': repo.get('created_by'),
                    'updated_at': repo.get('updated_at'),
                    'updated_by': repo.get('updated_by')
                })
            
            # Sort by active status first (active=True first), then by name
            return sorted(repo_list, key=lambda x: (not x.get('is_active', True), x['name'].lower()))
            
        except Exception as e:
            logger.warning(f"Could not load repositories from database: {e}")
            
        return []
    
    def _get_unique_users(self, user_accessible_repos: List[str] = None) -> List[str]:
        """Get unique users who have worked on findings from the database."""
        if not DATABASE_AVAILABLE:
            return []
        
        try:
            db_manager = get_database_manager()
            session_db = db_manager.get_session()
            
            # Get all unique users from assigned_to and completed_by fields
            unique_users = set()
            
            # Build query with repository filter if user has restricted access
            query_filter = []
            if user_accessible_repos:
                query_filter.append(SecurityFinding.repo_name.in_(user_accessible_repos))
            
            # Get users who have been assigned to findings
            assigned_query = session_db.query(SecurityFinding.assigned_to).filter(
                SecurityFinding.assigned_to.isnot(None)
            )
            if query_filter:
                assigned_query = assigned_query.filter(*query_filter)
            
            assigned_users = assigned_query.distinct().all()
            
            for (user,) in assigned_users:
                if user:
                    unique_users.add(user)
            
            # Get users who have completed findings
            completed_query = session_db.query(SecurityFinding.completed_by).filter(
                SecurityFinding.completed_by.isnot(None)
            )
            if query_filter:
                completed_query = completed_query.filter(*query_filter)
            
            completed_users = completed_query.distinct().all()
            
            for (user,) in completed_users:
                if user:
                    unique_users.add(user)
            
            session_db.close()
            return sorted(list(unique_users))
            
        except Exception as e:
            logger.error(f"Error fetching unique users: {e}")
            return []
    
    def setup_routes(self):
        """Setup Flask routes."""
        
        @self.app.route('/')
        def index():
            """Main page - shows login if not authenticated, findings list if authenticated."""
            if not self.is_authenticated():
                return render_template('login.html', 
                                     google_client_id=self.google_client_id)
            
            # User is authenticated, show findings list
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
            
            return self.show_findings_list(
                page=page, 
                per_page=per_page,
                vulnerability_filter=vulnerability_filter,
                repository_filter=repository_filter,
                status_filter=status_filter,
                classification_filter=classification_filter,
                user_filter=user_filter
            )
        
        @self.app.route('/login')
        def login():
            """Login page."""
            if self.is_authenticated():
                return redirect(url_for('index'))
            
            return render_template('login.html', 
                                 google_client_id=self.google_client_id)
        
        @self.app.route('/auth/google', methods=['POST'])
        def google_auth():
            """Handle Google Sign-In authentication."""
            try:
                # Get the ID token from the request
                token = request.json.get('idToken')
                if not token:
                    return jsonify({'error': 'No ID token provided'}), 400
                
                # Get the redirect URL from the request (optional)
                redirect_url = request.json.get('redirectUrl')
                
                # Verify the token
                id_info = id_token.verify_oauth2_token(
                    token, requests.Request(), self.google_client_id
                )
                
                # Check if email is authorized
                email = id_info.get('email')
                if not email:
                    return jsonify({'error': 'No email in token'}), 400
                
                # Check if user is authorized (either in authorized_emails or exists in database)
                is_authorized = email in self.authorized_emails
                
                if not is_authorized and DATABASE_AVAILABLE:
                    try:
                        db_manager = get_database_manager()
                        user_in_db = db_manager.get_user(email)
                        if user_in_db and user_in_db.is_active:
                            is_authorized = True
                    except Exception as e:
                        logger.error(f"Error checking database for user authorization: {e}")
                
                if not is_authorized:
                    logger.warning(f"Unauthorized login attempt from: {email}")
                    return jsonify({'error': 'Unauthorized email address'}), 403
                
                # Create or update user in database
                if DATABASE_AVAILABLE:
                    try:
                        db_manager = get_database_manager()
                        user_in_db = db_manager.get_user(email)
                        
                        if not user_in_db:
                            # Create new user - if they're in authorized_emails, make them admin
                            is_admin = email in self.authorized_emails
                            # Make fredrik.svantes@ethereum.org an owner who can't be deleted
                            is_owner = email == 'fredrik.svantes@ethereum.org'
                            success = db_manager.create_user(
                                email=email,
                                name=id_info.get('name', ''),
                                is_admin=is_admin,
                                repository_access=None,  # Admin users get all access
                                created_by='system',
                                is_owner=is_owner
                            )
                            if success:
                                logger.info(f"Created new user in database: {email} (admin: {is_admin}, owner: {is_owner})")
                        else:
                            # Update last login
                            db_manager.update_last_login(email)
                            logger.info(f"Updated last login for user: {email}")
                            
                    except Exception as e:
                        logger.error(f"Failed to create/update user in database: {e}")
                        # Continue with login even if database operation fails
                
                # Store user info in session
                session['user'] = {
                    'email': email,
                    'name': id_info.get('name', ''),
                    'picture': id_info.get('picture', ''),
                    'authenticated': True,
                    'login_time': datetime.now(timezone.utc).isoformat()
                }
                
                # Determine redirect URL - use provided redirect_url if it's safe, otherwise default to index
                final_redirect = url_for('index')  # Default fallback
                
                if redirect_url:
                    # Basic security check - ensure redirect URL is for this app
                    # Allow relative URLs and URLs for the same host
                    from urllib.parse import urlparse
                    parsed_redirect = urlparse(redirect_url)
                    request_host = request.headers.get('Host', '')
                    
                    # Allow relative URLs (no scheme/netloc) or URLs to the same host
                    if not parsed_redirect.netloc or parsed_redirect.netloc == request_host:
                        final_redirect = redirect_url
                    else:
                        logger.warning(f"Rejected redirect to external host: {redirect_url}")
                
                logger.info(f"User authenticated: {email}, redirecting to: {final_redirect}")
                return jsonify({'success': True, 'redirect': final_redirect})
                
            except GoogleAuthError as e:
                logger.error(f"Google authentication error: {e}")
                return jsonify({'error': 'Invalid Google token'}), 401
            except Exception as e:
                logger.error(f"Authentication error: {e}")
                return jsonify({'error': 'Authentication failed'}), 500
        
        @self.app.route('/logout')
        def logout():
            """Logout user."""
            if 'user' in session:
                logger.info(f"User logged out: {session['user']['email']}")
                session.pop('user', None)
            return redirect(url_for('index'))
        
        @self.app.route('/findings')
        def findings():
            """Show findings list (authenticated users only)."""
            if not self.is_authenticated():
                return redirect(url_for('login'))
            
            # Get pagination parameters
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 10, type=int)
            
            # Get filter parameters
            vulnerability_filter = request.args.get('vulnerability_filter', 'vulnerable')
            repository_filter = request.args.get('repository_filter', '')
            status_filter = request.args.get('status_filter', 'unassigned')
            classification_filter = request.args.get('classification_filter', '')
            
            # Validate per_page values
            if per_page not in [10, 25, 50, 75, 100]:
                per_page = 10
            
            return self.show_findings_list(
                page=page, 
                per_page=per_page,
                vulnerability_filter=vulnerability_filter,
                repository_filter=repository_filter,
                status_filter=status_filter,
                classification_filter=classification_filter
            )
        
        @self.app.route('/finding/<finding_id>')
        def view_finding(finding_id):
            """Redirect to triage view."""
            return redirect(url_for('triage_finding', finding_uuid=finding_id))
        
        @self.app.route('/api/findings')
        def api_findings():
            """API endpoint for findings list (authenticated users only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                findings = self.get_all_findings()
                return jsonify({
                    'success': True,
                    'findings': findings,
                    'total': len(findings)
                })
            except Exception as e:
                logger.error(f"Error fetching findings: {e}")
                return jsonify({'error': 'Failed to fetch findings'}), 500
        
        @self.app.route('/health')
        def health():
            """Health check endpoint."""
            status = {
                'status': 'healthy',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'database': False
            }
            
            # Check database
            if DATABASE_AVAILABLE:
                try:
                    db_manager = get_database_manager()
                    status['database'] = db_manager.health_check()
                except Exception:
                    pass
            
            return jsonify(status)
        
        @self.app.route('/report/<finding_uuid>')
        def public_finding(finding_uuid):
            """Public access to findings via UUID (for backwards compatibility)."""
            # This route allows public access to findings via UUID links
            # No authentication required - this maintains backwards compatibility
            
            # Handle example report
            if finding_uuid == 'example-report':
                finding_data = self._generate_example_report()
                return self._render_finding_page(finding_data, finding_uuid)
            
            # Get finding from database
            finding_data = None
            if DATABASE_AVAILABLE:
                try:
                    db_manager = get_database_manager()
                    finding_data = db_manager.get_finding(finding_uuid)
                except Exception as e:
                    logger.error(f"Error retrieving finding {finding_uuid}: {e}")
            
            if not finding_data:
                return self._render_error_page("Finding not found or has expired", 404)
            
            return self._render_finding_page(finding_data, finding_uuid)
        
        @self.app.route('/triage/<finding_uuid>')
        def triage_finding(finding_uuid):
            """View finding with optional triage controls (public access with limited data for unauthenticated users)."""
            
            if not DATABASE_AVAILABLE:
                return self._render_error_page("Database not available", 503)
            
            try:
                db_manager = get_database_manager()
                finding = db_manager.get_finding_full(finding_uuid)
                
                if not finding:
                    return self._render_error_page("Finding not found", 404)
                
                is_authenticated = self.is_authenticated()
                user = self.get_current_user() if is_authenticated else None
                
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
                                     google_client_id=self.google_client_id)
                
            except Exception as e:
                logger.error(f"Error retrieving finding for triage {finding_uuid}: {e}")
                return self._render_error_page("Error loading finding", 500)
        
        @self.app.route('/api/triage/<finding_uuid>', methods=['POST'])
        def update_triage(finding_uuid):
            """Update triage status of a finding (authenticated users only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
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
                
                user_email = self.get_current_user()['email']
                
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
        
        @self.app.route('/api/notes/<finding_uuid>', methods=['POST'])
        def add_note(finding_uuid):
            """Add a note to a finding (authenticated users only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            if not DATABASE_AVAILABLE:
                return jsonify({'error': 'Database not available'}), 503
            
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'No data provided'}), 400
                
                note_text = data.get('note')
                if not note_text or not note_text.strip():
                    return jsonify({'error': 'Note text is required'}), 400
                
                user_email = self.get_current_user()['email']
                
                db_manager = get_database_manager()
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
                logger.error(f"Error adding note to {finding_uuid}: {e}")
                return jsonify({'error': 'Internal server error'}), 500
        
        @self.app.route('/api/notes/<finding_uuid>', methods=['GET'])
        def get_notes(finding_uuid):
            """Get notes for a finding (authenticated users only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            if not DATABASE_AVAILABLE:
                return jsonify({'error': 'Database not available'}), 503
            
            try:
                db_manager = get_database_manager()
                notes = db_manager.get_notes(finding_uuid)
                return jsonify({'success': True, 'notes': notes})
                
            except Exception as e:
                logger.error(f"Error fetching notes for {finding_uuid}: {e}")
                return jsonify({'error': 'Failed to fetch notes'}), 500
        
        @self.app.route('/api/notes/<finding_uuid>/<int:note_id>', methods=['DELETE'])
        def delete_note(finding_uuid, note_id):
            """Delete a note from a finding (authenticated users only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            if not DATABASE_AVAILABLE:
                return jsonify({'error': 'Database not available'}), 503
            
            try:
                user_email = self.get_current_user()['email']
                
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
        
        @self.app.route('/api/triage/statistics')
        def triage_statistics():
            """Get triage statistics (authenticated users only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            if not DATABASE_AVAILABLE:
                return jsonify({'error': 'Database not available'}), 503
            
            try:
                db_manager = get_database_manager()
                stats = db_manager.get_triage_statistics()
                return jsonify(stats)
                
            except Exception as e:
                logger.error(f"Error fetching triage statistics: {e}")
                return jsonify({'error': 'Failed to fetch statistics'}), 500
        
        # Admin routes
        @self.app.route('/admin')
        def admin_dashboard():
            """Admin dashboard (admin users only)."""
            if not self.is_authenticated():
                return redirect(url_for('login'))
            
            if not self.is_admin():
                flash('Access denied. Admin privileges required.', 'error')
                return redirect(url_for('index'))
            
            if not DATABASE_AVAILABLE:
                flash('Database not available', 'error')
                return redirect(url_for('index'))
            
            try:
                db_manager = get_database_manager()
                users = db_manager.get_all_users()
                repositories = self._load_repositories()
                
                return render_template('admin/dashboard.html', 
                                     users=users,
                                     repositories=repositories,
                                     user=self.get_current_user())
                
            except Exception as e:
                logger.error(f"Error loading admin dashboard: {e}")
                flash('Error loading admin dashboard', 'error')
                return redirect(url_for('index'))
        
        @self.app.route('/admin/users/create', methods=['GET', 'POST'])
        def admin_create_user():
            """Create a new user (admin only)."""
            if not self.is_authenticated():
                return redirect(url_for('login'))
            
            if not self.is_admin():
                flash('Access denied. Admin privileges required.', 'error')
                return redirect(url_for('index'))
            
            if not DATABASE_AVAILABLE:
                flash('Database not available', 'error')
                return redirect(url_for('admin_dashboard'))
            
            if request.method == 'GET':
                repositories = self._load_repositories()
                return render_template('admin/create_user.html', 
                                     repositories=repositories,
                                     user=self.get_current_user())
            
            try:
                # Get form data
                email = request.form.get('email', '').strip()
                name = request.form.get('name', '').strip()
                is_admin = request.form.get('is_admin') == 'on'
                
                # Only owners can create admin users
                if is_admin and not self.is_owner():
                    flash('Only owners can create admin users', 'error')
                    return redirect(url_for('admin_create_user'))
                
                # Get repository access
                repository_access = []
                access_type = request.form.get('access_type')
                if access_type == 'specific':
                    repository_access = request.form.getlist('repositories')
                elif access_type == 'all':
                    repository_access = None  # None means all repositories
                
                # Validate input
                if not email:
                    flash('Email is required', 'error')
                    return redirect(url_for('admin_create_user'))
                
                if not name:
                    flash('Name is required', 'error')
                    return redirect(url_for('admin_create_user'))
                
                # Create user
                db_manager = get_database_manager()
                current_user = self.get_current_user()
                
                success = db_manager.create_user(
                    email=email,
                    name=name,
                    is_admin=is_admin,
                    repository_access=repository_access,
                    created_by=current_user['email']
                )
                
                if success:
                    flash(f'User {email} created successfully', 'success')
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('Failed to create user. User may already exist.', 'error')
                    return redirect(url_for('admin_create_user'))
                
            except Exception as e:
                logger.error(f"Error creating user: {e}")
                flash('Error creating user', 'error')
                return redirect(url_for('admin_create_user'))
        
        @self.app.route('/admin/users/<email>/edit', methods=['GET', 'POST'])
        def admin_edit_user(email):
            """Edit a user (admin only)."""
            if not self.is_authenticated():
                return redirect(url_for('login'))
            
            if not self.is_admin():
                flash('Access denied. Admin privileges required.', 'error')
                return redirect(url_for('index'))
            
            if not DATABASE_AVAILABLE:
                flash('Database not available', 'error')
                return redirect(url_for('admin_dashboard'))
            
            try:
                db_manager = get_database_manager()
                user_data = db_manager.get_user(email)
                
                if not user_data:
                    flash('User not found', 'error')
                    return redirect(url_for('admin_dashboard'))
                
                if request.method == 'GET':
                    repositories = self._load_repositories()
                    return render_template('admin/edit_user.html', 
                                         user_data=user_data.to_dict(),
                                         repositories=repositories,
                                         user=self.get_current_user())
                
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
                    repository_access = None  # None means all repositories
                
                # Validate input
                if not name:
                    flash('Name is required', 'error')
                    return redirect(url_for('admin_edit_user', email=email))
                
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
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('Failed to update user', 'error')
                    return redirect(url_for('admin_edit_user', email=email))
                
            except Exception as e:
                logger.error(f"Error editing user {email}: {e}")
                flash('Error editing user', 'error')
                return redirect(url_for('admin_dashboard'))
        
        @self.app.route('/admin/users/<email>/delete', methods=['POST'])
        def admin_delete_user(email):
            """Delete a user (admin only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            if not self.is_admin():
                return jsonify({'error': 'Access denied'}), 403
            
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
        
        @self.app.route('/api/admin/users')
        def admin_api_users():
            """Get all users (admin only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            if not self.is_admin():
                return jsonify({'error': 'Access denied'}), 403
            
            if not DATABASE_AVAILABLE:
                return jsonify({'error': 'Database not available'}), 503
            
            try:
                db_manager = get_database_manager()
                users = db_manager.get_all_users()
                return jsonify({'success': True, 'users': users})
                
            except Exception as e:
                logger.error(f"Error fetching users: {e}")
                return jsonify({'error': 'Failed to fetch users'}), 500
        
        @self.app.route('/settings', methods=['GET', 'POST'])
        def user_settings():
            """User settings page (authenticated users only)."""
            if not self.is_authenticated():
                return redirect(url_for('login'))
            
            if not DATABASE_AVAILABLE:
                flash('Database not available', 'error')
                return redirect(url_for('index'))
            
            try:
                db_manager = get_database_manager()
                current_user = self.get_current_user()
                user_data = db_manager.get_user(current_user['email'])
                
                if not user_data:
                    flash('User data not found', 'error')
                    return redirect(url_for('index'))
                
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
                
                return redirect(url_for('user_settings'))
                
            except Exception as e:
                logger.error(f"Error in user settings for {current_user['email']}: {e}")
                flash('Error loading settings', 'error')
                return redirect(url_for('index'))
        
        # Repository management routes (admin only)
        @self.app.route('/admin/repositories/create', methods=['GET', 'POST'])
        def admin_create_repository():
            """Create a new repository (admin only)."""
            if not self.is_authenticated():
                return redirect(url_for('login'))
            
            if not self.is_admin():
                flash('Access denied. Admin privileges required.', 'error')
                return redirect(url_for('index'))
            
            if not DATABASE_AVAILABLE:
                flash('Database not available', 'error')
                return redirect(url_for('admin_dashboard'))
            
            if request.method == 'GET':
                return render_template('admin/create_repository.html', 
                                     user=self.get_current_user())
            
            try:
                # Get form data
                url = request.form.get('url', '').strip()
                branches_str = request.form.get('branches', '').strip()
                telegram_channel_id = request.form.get('telegram_channel_id', '').strip()
                notify_default_channel = request.form.get('notify_default_channel') == 'on'
                
                # Validate input
                if not url:
                    flash('Repository URL is required', 'error')
                    return redirect(url_for('admin_create_repository'))
                
                if not branches_str:
                    flash('At least one branch is required', 'error')
                    return redirect(url_for('admin_create_repository'))
                
                # Parse branches (comma-separated)
                branches = [branch.strip() for branch in branches_str.split(',') if branch.strip()]
                
                if not branches:
                    flash('At least one valid branch is required', 'error')
                    return redirect(url_for('admin_create_repository'))
                
                # Extract repository name from URL
                from .database import Repository
                repo_name = Repository.extract_repo_name_from_url(url)
                
                # Create repository
                db_manager = get_database_manager()
                current_user = self.get_current_user()
                
                success = db_manager.create_repository(
                    name=repo_name,
                    url=url,
                    branches=branches,
                    telegram_channel_id=telegram_channel_id if telegram_channel_id else None,
                    notify_default_channel=notify_default_channel,
                    created_by=current_user['email']
                )
                
                if success:
                    # Send audit email notification to owner
                    try:
                        from .email_notifications import get_email_service
                        email_service = get_email_service()
                        repository_data = {
                            'name': repo_name,
                            'url': url,
                            'branches': branches,
                            'telegram_channel_id': telegram_channel_id,
                            'notify_default_channel': notify_default_channel,
                            'is_active': True  # New repositories are active by default
                        }
                        email_service.send_repository_creation_notification(
                            db_manager=db_manager,
                            repository_data=repository_data,
                            created_by=current_user['email']
                        )
                        logger.info(f"Audit email sent for repository creation: {repo_name}")
                    except Exception as email_error:
                        # Log email error but don't fail the creation
                        logger.error(f"Failed to send repository creation audit email: {email_error}")
                    
                    flash(f'Repository {repo_name} created successfully', 'success')
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('Failed to create repository. Repository may already exist.', 'error')
                    return redirect(url_for('admin_create_repository'))
                
            except Exception as e:
                logger.error(f"Error creating repository: {e}")
                flash('Error creating repository', 'error')
                return redirect(url_for('admin_create_repository'))
        
        @self.app.route('/admin/repositories/<path:repo_name>/edit', methods=['GET', 'POST'])
        def admin_edit_repository(repo_name):
            """Edit a repository (admin only)."""
            if not self.is_authenticated():
                return redirect(url_for('login'))
            
            if not self.is_admin():
                flash('Access denied. Admin privileges required.', 'error')
                return redirect(url_for('index'))
            
            if not DATABASE_AVAILABLE:
                flash('Database not available', 'error')
                return redirect(url_for('admin_dashboard'))
            
            try:
                db_manager = get_database_manager()
                repository = db_manager.get_repository(repo_name)
                
                if not repository:
                    flash('Repository not found', 'error')
                    return redirect(url_for('admin_dashboard'))
                
                if request.method == 'GET':
                    return render_template('admin/edit_repository.html', 
                                         repository=repository.to_dict(),
                                         user=self.get_current_user())
                
                # Handle POST request
                url = request.form.get('url', '').strip()
                branches_str = request.form.get('branches', '').strip()
                telegram_channel_id = request.form.get('telegram_channel_id', '').strip()
                notify_default_channel = request.form.get('notify_default_channel') == 'on'
                is_active = request.form.get('is_active') == 'on'
                
                # Validate input
                if not url:
                    flash('Repository URL is required', 'error')
                    return redirect(url_for('admin_edit_repository', repo_name=repo_name))
                
                if not branches_str:
                    flash('At least one branch is required', 'error')
                    return redirect(url_for('admin_edit_repository', repo_name=repo_name))
                
                # Parse branches (comma-separated)
                branches = [branch.strip() for branch in branches_str.split(',') if branch.strip()]
                
                if not branches:
                    flash('At least one valid branch is required', 'error')
                    return redirect(url_for('admin_edit_repository', repo_name=repo_name))
                
                # Get old repository data for comparison
                old_repository_data = repository.to_dict()
                
                # Update repository
                current_user = self.get_current_user()
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
                    # Send audit email notification to owner
                    try:
                        from .email_notifications import get_email_service
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
                        # Log email error but don't fail the update
                        logger.error(f"Failed to send repository modification audit email: {email_error}")
                    
                    flash(f'Repository {repo_name} updated successfully', 'success')
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('Failed to update repository', 'error')
                    return redirect(url_for('admin_edit_repository', repo_name=repo_name))
                
            except Exception as e:
                logger.error(f"Error editing repository {repo_name}: {e}")
                flash('Error editing repository', 'error')
                return redirect(url_for('admin_dashboard'))
        
        @self.app.route('/admin/repositories/<path:repo_name>/delete', methods=['POST'])
        def admin_delete_repository(repo_name):
            """Delete a repository (admin only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            if not self.is_admin():
                return jsonify({'error': 'Access denied'}), 403
            
            if not DATABASE_AVAILABLE:
                return jsonify({'error': 'Database not available'}), 503
            
            try:
                db_manager = get_database_manager()
                current_user = self.get_current_user()
                
                # Get repository data before deletion for audit email
                repository = db_manager.get_repository(repo_name)
                if not repository:
                    return jsonify({'error': 'Repository not found'}), 404
                
                # Convert repository object to dictionary for email
                repository_data = repository.to_dict()
                
                # Delete the repository
                success = db_manager.delete_repository(repo_name)
                
                if success:
                    # Send audit email notification to owner
                    try:
                        from .email_notifications import get_email_service
                        email_service = get_email_service()
                        email_service.send_repository_deletion_notification(
                            db_manager=db_manager,
                            repository_data=repository_data,
                            deleted_by=current_user['email']
                        )
                        logger.info(f"Audit email sent for repository deletion: {repo_name}")
                    except Exception as email_error:
                        # Log email error but don't fail the deletion
                        logger.error(f"Failed to send repository deletion audit email: {email_error}")
                    
                    return jsonify({'success': True, 'message': f'Repository {repo_name} deleted successfully'})
                else:
                    return jsonify({'error': 'Failed to delete repository or repository not found'}), 500
                
            except Exception as e:
                logger.error(f"Error deleting repository {repo_name}: {e}")
                return jsonify({'error': 'Internal server error'}), 500
        
        # Repository document management routes (admin only)
        @self.app.route('/admin/repositories/<path:repo_name>/documents')
        def admin_repository_documents(repo_name):
            """View and manage documents for a repository (admin only)."""
            if not self.is_authenticated():
                return redirect(url_for('login'))
            
            if not self.is_admin():
                flash('Access denied. Admin privileges required.', 'error')
                return redirect(url_for('index'))
            
            if not DATABASE_AVAILABLE:
                flash('Database not available', 'error')
                return redirect(url_for('admin_dashboard'))
            
            try:
                db_manager = get_database_manager()
                
                # Verify repository exists
                repository = db_manager.get_repository(repo_name)
                if not repository:
                    flash('Repository not found', 'error')
                    return redirect(url_for('admin_dashboard'))
                
                # Get all documents for this repository
                documents = db_manager.get_repository_documents(repo_name)
                
                return render_template('admin/repository_documents.html',
                                     repository=repository.to_dict(),
                                     documents=documents,
                                     user=self.get_current_user())
                
            except Exception as e:
                logger.error(f"Error loading documents for repository {repo_name}: {e}")
                flash('Error loading documents', 'error')
                return redirect(url_for('admin_dashboard'))
        
        @self.app.route('/admin/repositories/<path:repo_name>/documents/upload', methods=['POST'])
        def admin_upload_document(repo_name):
            """Upload a document for a repository (admin only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            if not self.is_admin():
                return jsonify({'error': 'Access denied'}), 403
            
            if not DATABASE_AVAILABLE:
                return jsonify({'error': 'Database not available'}), 503
            
            try:
                # Check if file was uploaded
                if 'file' not in request.files:
                    return jsonify({'error': 'No file provided'}), 400
                
                file = request.files['file']
                if file.filename == '':
                    return jsonify({'error': 'No file selected'}), 400
                
                # Validate file extension
                allowed_extensions = {'.pdf', '.txt', '.md', '.markdown'}
                file_ext = os.path.splitext(file.filename)[1].lower()
                if file_ext not in allowed_extensions:
                    return jsonify({'error': f'Invalid file type. Allowed: {", ".join(allowed_extensions)}'}), 400
                
                # Save file temporarily
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as temp_file:
                    file.save(temp_file.name)
                    temp_path = temp_file.name
                
                try:
                    # Read file content and generate embedding
                    from .voyage_vector_store import get_voyage_vector_store
                    
                    voyage_store = get_voyage_vector_store()
                    if not voyage_store:
                        return jsonify({'error': 'Voyage AI not configured. Set VOYAGE_API_KEY environment variable.'}), 500
                    
                    # Read file content
                    content = voyage_store.read_file_content(temp_path)
                    
                    # Generate embedding
                    embedding = voyage_store.generate_embedding(content)
                    
                    # Get file size
                    file_size = os.path.getsize(temp_path)
                    
                    # Store in database
                    db_manager = get_database_manager()
                    current_user = self.get_current_user()
                    
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
                    # Clean up temp file
                    try:
                        os.unlink(temp_path)
                    except Exception:
                        pass
                
            except Exception as e:
                logger.error(f"Error uploading document for repository {repo_name}: {e}")
                return jsonify({'error': f'Internal server error: {str(e)}'}), 500
        
        @self.app.route('/admin/repositories/<path:repo_name>/documents/<int:doc_id>/delete', methods=['POST'])
        def admin_delete_document(repo_name, doc_id):
            """Delete a document (admin only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            if not self.is_admin():
                return jsonify({'error': 'Access denied'}), 403
            
            if not DATABASE_AVAILABLE:
                return jsonify({'error': 'Database not available'}), 503
            
            try:
                db_manager = get_database_manager()
                
                # Verify document exists and belongs to this repository
                document = db_manager.get_repository_document(doc_id)
                if not document:
                    return jsonify({'error': 'Document not found'}), 404
                
                if document.repository_name != repo_name:
                    return jsonify({'error': 'Document does not belong to this repository'}), 400
                
                # Delete the document
                success = db_manager.delete_repository_document(doc_id)
                
                if success:
                    return jsonify({'success': True, 'message': 'Document deleted successfully'})
                else:
                    return jsonify({'error': 'Failed to delete document'}), 500
                
            except Exception as e:
                logger.error(f"Error deleting document {doc_id}: {e}")
                return jsonify({'error': 'Internal server error'}), 500
        
        @self.app.route('/admin/repositories/<path:repo_name>/toggle-status', methods=['POST'])
        def admin_toggle_repository_status(repo_name):
            """Toggle repository active status (admin only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            if not self.is_admin():
                return jsonify({'error': 'Access denied'}), 403
            
            if not DATABASE_AVAILABLE:
                return jsonify({'error': 'Database not available'}), 503
            
            try:
                db_manager = get_database_manager()
                current_user = self.get_current_user()
                
                # Get current repository status
                repository = db_manager.get_repository(repo_name)
                if not repository:
                    return jsonify({'error': 'Repository not found'}), 404
                
                # Toggle the status
                new_status = not repository.is_active
                
                # Update repository
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
        
        @self.app.route('/api/admin/repositories')
        def admin_api_repositories():
            """Get all repositories (admin only)."""
            if not self.is_authenticated():
                return jsonify({'error': 'Unauthorized'}), 401
            
            if not self.is_admin():
                return jsonify({'error': 'Access denied'}), 403
            
            if not DATABASE_AVAILABLE:
                return jsonify({'error': 'Database not available'}), 503
            
            try:
                db_manager = get_database_manager()
                repositories = db_manager.get_all_repositories(include_inactive=True)
                return jsonify({'success': True, 'repositories': repositories})
                
            except Exception as e:
                logger.error(f"Error fetching repositories: {e}")
                return jsonify({'error': 'Failed to fetch repositories'}), 500
    
    def _generate_example_report(self) -> Dict:
        """Generate an example security report for demonstration purposes."""
        import os
        
        # Load example report from external file
        example_path = os.path.join(os.path.dirname(__file__), 'example_report.html')
        try:
            with open(example_path, 'r') as f:
                example_html = f.read()
        except FileNotFoundError:
            # Fallback if file not found
            example_html = """
    <div class="main-card">
        <div class="card-header">
            <h2><i class="fas fa-code-branch"></i> Repository: ethereum/example-contract</h2>
        </div>
        <div class="card-content">
            <p>Example report file not found. Please ensure example_report.html exists in the pr_security_review directory.</p>
        </div>
    </div>
"""
        
        return {
            'html_content': example_html,
            'created_at': datetime.now(timezone.utc),
            'metadata': {
                'is_example': True,
                'repo_name': 'ethereum/example-contract'
            }
        }
    
    def _render_finding_page(self, finding_data: Dict, finding_uuid: str) -> str:
        """Render a finding page with full styling."""
        
        # Check if user is authenticated to show navigation
        is_authenticated = self.is_authenticated()
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Finding Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1a202c;
            background: #f8fafc;
            min-height: 100vh;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem 0;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        
        .header-content {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .header h1 {{
            font-size: 1.75rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .header h1 i {{
            font-size: 1.5rem;
        }}
        
        .header-actions {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        
        .dashboard-btn {{
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            text-decoration: none;
            font-size: 0.875rem;
            font-weight: 500;
            transition: background 0.2s;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .dashboard-btn:hover {{
            background: rgba(255, 255, 255, 0.3);
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        .footer {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 2rem 0;
            margin-top: 4rem;
        }}
        
        .footer-content {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
            text-align: center;
        }}
        
        .metadata {{
            font-size: 0.875rem;
            color: #a0aec0;
        }}
        
        .metadata p {{
            margin: 0.25rem 0;
        }}
        
        /* Include all the existing styles from findings_server.py */
        .main-card {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
            overflow: hidden;
            margin-bottom: 2rem;
        }}
        
        .card-header {{
            background: #f7fafc;
            padding: 1.5rem 2rem;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        .card-content {{
            padding: 2rem;
        }}
        
        .multi-judge {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
            padding: 2rem;
            margin: 2rem 0;
        }}
        
        .multi-judge h3 {{
            color: #2d3748;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .judge-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: #f7fafc;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }}
        
        .stat-value {{
            font-size: 1.5rem;
            font-weight: 700;
            color: #2d3748;
        }}
        
        .stat-label {{
            font-size: 0.75rem;
            color: #718096;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        
        th {{
            background: #f7fafc;
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
            color: #4a5568;
            border-bottom: 2px solid #e2e8f0;
        }}
        
        td {{
            padding: 0.75rem;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        tr:hover {{
            background: #f7fafc;
        }}
        
        .repo-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .info-item {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            overflow: hidden;
        }}
        
        .info-item i {{
            color: #667eea;
            width: 20px;
            text-align: center;
            flex-shrink: 0;
        }}
        
        .info-label {{
            font-weight: 500;
            color: #4a5568;
            min-width: 80px;
            flex-shrink: 0;
        }}
        
        .info-value {{
            color: #1a202c;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            flex: 1;
        }}
        
        .info-value a {{
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }}
        
        .info-value a:hover {{
            text-decoration: underline;
        }}
        
        .commit-message {{
            background: #f7fafc;
            border-left: 4px solid #667eea;
            padding: 1rem 1.5rem;
            border-radius: 0 8px 8px 0;
            margin: 1.5rem 0;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9rem;
        }}
        
        .score-section {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }}
        
        .score-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        
        .score-card.safe {{
            background: linear-gradient(135deg, #d4fc79 0%, #96e6a1 100%);
        }}
        
        .score-card.vulnerable {{
            background: linear-gradient(135deg, #fc466b 0%, #3f5efb 100%);
            color: white;
        }}
        
        .score-value {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }}
        
        .score-label {{
            font-size: 0.875rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .summary-section {{
            background: #edf2f7;
            padding: 1.5rem;
            border-radius: 8px;
            margin: 2rem 0;
        }}
        
        .findings-section {{
            margin-top: 2rem;
        }}
        
        .finding-card {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
            margin-bottom: 1.5rem;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .finding-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }}
        
        .finding-header {{
            padding: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        
        .finding-header.high {{
            background: #fff5f5;
            border-left: 4px solid #fc8181;
        }}
        
        .finding-header.medium {{
            background: #fffaf0;
            border-left: 4px solid #f6ad55;
        }}
        
        .finding-header.low {{
            background: #fffff0;
            border-left: 4px solid #f6e05e;
        }}
        
        .severity-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .severity-badge.high {{
            background: #fc8181;
            color: white;
        }}
        
        .severity-badge.medium {{
            background: #f6ad55;
            color: white;
        }}
        
        .severity-badge.low {{
            background: #f6e05e;
            color: #744210;
        }}
        
        .confidence-badge {{
            background: #e2e8f0;
            color: #4a5568;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
        }}
        
        .finding-content {{
            padding: 1.5rem;
        }}
        
        .finding-content h4 {{
            color: #2d3748;
            margin-bottom: 0.75rem;
            font-size: 1.125rem;
        }}
        
        .finding-content p {{
            color: #4a5568;
            margin-bottom: 1rem;
        }}
        
        .recommendation {{
            background: #e6fffa;
            border-left: 4px solid #4fd1c5;
            padding: 1rem;
            border-radius: 0 8px 8px 0;
            margin: 1rem 0;
        }}
        
        .details-box {{
            margin-top: 1.5rem;
        }}
        
        .details-toggle {{
            background: #667eea;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            transition: background 0.2s;
        }}
        
        .details-toggle:hover {{
            background: #5a67d8;
        }}
        
        .details-content {{
            display: none;
            margin-top: 1rem;
            padding: 1.5rem;
            background: #f7fafc;
            border-radius: 8px;
        }}
        
        .details-content.show {{
            display: block;
        }}
        
        .details-content h4 {{
            color: #2d3748;
            margin-top: 1.5rem;
            margin-bottom: 0.75rem;
            font-size: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .details-content h4:first-child {{
            margin-top: 0;
        }}
        
        .details-content h4 i {{
            color: #667eea;
            font-size: 0.875rem;
        }}
        
        pre {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.875rem;
            line-height: 1.5;
            margin: 1rem 0;
        }}
        
        code {{
            background: #edf2f7;
            color: #e53e3e;
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
            font-size: 0.875rem;
        }}
        
        pre code {{
            background: transparent;
            color: inherit;
            padding: 0;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 1.5rem;
            }}
            
            .container {{
                padding: 1rem;
            }}
            
            .card-content {{
                padding: 1rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>
                <i class="fas fa-shield-alt"></i>
                Security Finding Report
            </h1>
            
            {'<div class="header-actions"><a href="/" class="dashboard-btn"><i class="fas fa-home"></i>Back to Dashboard</a></div>' if is_authenticated else ''}
        </div>
    </div>
    
    <div class="container">
        {finding_data['html_content']}
    </div>
    
    <div class="footer">
        <div class="footer-content">
            <div class="metadata">
                <p><i class="far fa-clock"></i> Generated on: {finding_data['created_at'].strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
        </div>
    </div>
    
    <script>
        // Toggle details sections
        document.querySelectorAll('.details-toggle').forEach(button => {{
            button.addEventListener('click', function() {{
                const content = this.nextElementSibling;
                content.classList.toggle('show');
                const icon = this.querySelector('i');
                if (content.classList.contains('show')) {{
                    icon.classList.remove('fa-chevron-down');
                    icon.classList.add('fa-chevron-up');
                }} else {{
                    icon.classList.remove('fa-chevron-up');
                    icon.classList.add('fa-chevron-down');
                }}
            }});
        }});
    </script>
</body>
</html>"""
        
        return html_content
    
    def _render_error_page(self, message: str, status_code: int = 404) -> str:
        """Render an error page."""
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Security Findings</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1a202c;
            background: #f8fafc;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }}
        
        .error-container {{
            text-align: center;
            padding: 2rem;
            max-width: 600px;
        }}
        
        .error-icon {{
            font-size: 4rem;
            color: #fc8181;
            margin-bottom: 1rem;
        }}
        
        .error-title {{
            font-size: 2rem;
            font-weight: 700;
            color: #2d3748;
            margin-bottom: 1rem;
        }}
        
        .error-message {{
            font-size: 1.125rem;
            color: #4a5568;
            margin-bottom: 2rem;
        }}
        
        .back-link {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 500;
            transition: background 0.2s;
        }}
        
        .back-link:hover {{
            background: #5a67d8;
        }}
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">
            <i class="fas fa-exclamation-triangle"></i>
        </div>
        <h1 class="error-title">Error {status_code}</h1>
        <p class="error-message">{message}</p>
        <a href="/" class="back-link">
            <i class="fas fa-home"></i>
            Back to Home
        </a>
    </div>
</body>
</html>"""
        
        return html_content, status_code
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        if not ('user' in session and session['user'].get('authenticated', False)):
            return False
        
        email = session['user'].get('email')
        if not email:
            return False
        
        # Check if user is in authorized_emails
        if email in self.authorized_emails:
            return True
        
        # Check if user exists in database and is active
        if DATABASE_AVAILABLE:
            try:
                db_manager = get_database_manager()
                user_in_db = db_manager.get_user(email)
                if user_in_db and user_in_db.is_active:
                    return True
            except Exception as e:
                logger.error(f"Error checking database for user authentication: {e}")
        
        return False
    
    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """Get current authenticated user."""
        if self.is_authenticated():
            return session['user']
        return None
    
    def is_admin(self) -> bool:
        """Check if current user is an admin."""
        if not self.is_authenticated():
            return False
        
        # Check if user is admin in the database
        if DATABASE_AVAILABLE:
            try:
                db_manager = get_database_manager()
                user_email = self.get_current_user()['email']
                return db_manager.is_admin(user_email)
            except Exception as e:
                logger.error(f"Error checking admin status: {e}")
                return False
        
        # Fallback to environmental variable check
        return self.get_current_user()['email'] in self.authorized_emails
    
    def is_owner(self) -> bool:
        """Check if current user is an owner."""
        if not self.is_authenticated():
            return False
        
        # Check if user is owner in the database
        if DATABASE_AVAILABLE:
            try:
                db_manager = get_database_manager()
                user_email = self.get_current_user()['email']
                return db_manager.is_owner(user_email)
            except Exception as e:
                logger.error(f"Error checking owner status: {e}")
                return False
        
        # Fallback to environmental variable check for owner
        return self.get_current_user()['email'] == 'fredrik.svantes@ethereum.org'
    
    def _get_pagination_range(self, page: int, total_pages: int, window: int = 5) -> List[int]:
        """Generate pagination range for template."""
        if total_pages <= window:
            return list(range(1, total_pages + 1))
        
        # Calculate start and end of the window
        start = max(1, page - window // 2)
        end = min(total_pages, start + window - 1)
        
        # Adjust start if we're near the end
        if end - start < window - 1:
            start = max(1, end - window + 1)
        
        return list(range(start, end + 1))
    
    def show_findings_list(self, page: int = 1, per_page: int = 10, vulnerability_filter: str = 'vulnerable', 
                          repository_filter: str = '', status_filter: str = 'unassigned', 
                          classification_filter: str = '', user_filter: str = '') -> str:
        """Show the findings list page with pagination and filtering."""
        try:
            # Get all findings for statistics (unfiltered)
            all_findings = self.get_all_findings()
            
            # Apply filters to get filtered dataset
            filtered_findings = self._apply_filters(
                all_findings, 
                vulnerability_filter, 
                repository_filter, 
                status_filter, 
                classification_filter,
                user_filter
            )
            
            user = self.get_current_user()
            repositories = self._load_repositories()
            
            # Get user's repository access for filtering
            user_accessible_repos = None
            if self.is_authenticated() and DATABASE_AVAILABLE:
                try:
                    db_manager = get_database_manager()
                    user_accessible_repos = db_manager.get_user_repository_access(user['email'])
                except Exception as e:
                    logger.error(f"Error getting user repository access: {e}")
            
            # Filter unique users based on user's repository access
            unique_users = self._get_unique_users(user_accessible_repos)
            
            # Filter repositories based on user access (for repository dropdown)
            if user_accessible_repos:
                # User has specific repository access, filter repositories
                accessible_repositories = [repo for repo in repositories if repo['name'] in user_accessible_repos]
            else:
                # User has access to all repositories or is admin
                accessible_repositories = repositories
            
            # Calculate pagination on filtered results
            total_filtered = len(filtered_findings)
            total_pages = (total_filtered + per_page - 1) // per_page  # Ceiling division
            
            # Get findings for current page
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            paginated_findings = filtered_findings[start_idx:end_idx]
            
            # Create pagination info
            pagination = {
                'page': page,
                'per_page': per_page,
                'total': total_filtered,
                'pages': total_pages,
                'has_prev': page > 1,
                'prev_num': page - 1 if page > 1 else None,
                'has_next': page < total_pages,
                'next_num': page + 1 if page < total_pages else None,
                'iter_pages': list(self._get_pagination_range(page, total_pages))
            }
            
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
                                 all_findings=all_findings,  # Pass all findings for unfiltered reference
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
                                 all_findings=[],  # Pass empty all_findings for statistics
                                 user=self.get_current_user(),
                                 total_findings=0,
                                 repositories=[],
                                 pagination={'page': 1, 'per_page': per_page, 'total': 0, 'pages': 0, 'has_prev': False, 'has_next': False, 'iter_pages': []},
                                 current_filters={'vulnerability_filter': 'vulnerable', 'repository_filter': '', 'status_filter': 'unassigned', 'classification_filter': ''},
                                 filtered_stats={'total': 0, 'vulnerable': 0, 'safe': 0})
    
    def _apply_filters(self, findings: List[Dict[str, Any]], vulnerability_filter: str, 
                      repository_filter: str, status_filter: str, classification_filter: str,
                      user_filter: str = '') -> List[Dict[str, Any]]:
        """Apply filters to the findings list."""
        filtered_findings = findings.copy()
        
        # Apply vulnerability filter
        if vulnerability_filter == 'vulnerable':
            filtered_findings = [f for f in filtered_findings if f.get('has_vulnerabilities')]
        elif vulnerability_filter == 'safe':
            filtered_findings = [f for f in filtered_findings if not f.get('has_vulnerabilities')]
        # 'all' means no filtering
        
        # Apply repository filter
        if repository_filter:
            filtered_findings = [f for f in filtered_findings if f.get('repo_name', '').lower() == repository_filter.lower()]
        
        # Apply status filter
        if status_filter:
            filtered_findings = [f for f in filtered_findings if (f.get('triage_status') or 'unassigned') == status_filter]
        
        # Apply classification filter (only when status is completed)
        if status_filter == 'completed' and classification_filter:
            filtered_findings = [f for f in filtered_findings if f.get('completion_classification') == classification_filter]
        
        # Apply user filter
        if user_filter:
            filtered_findings = [f for f in filtered_findings if 
                               f.get('assigned_to') == user_filter or 
                               f.get('completed_by') == user_filter]
        
        return filtered_findings
    
    def get_all_findings(self, triage_status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all security findings from database with optional triage filtering."""
        if not DATABASE_AVAILABLE:
            return []
        
        try:
            db_manager = get_database_manager()
            
            if triage_status:
                # Use the new filtered method
                findings = db_manager.get_findings_by_status(triage_status=triage_status)
            else:
                # Get all findings
                session_db = db_manager.get_session()
                
                # Get all findings (no expiration filtering since findings never expire)
                findings_query = session_db.query(SecurityFinding).order_by(SecurityFinding.created_at.desc()).all()
                
                result = []
                for finding in findings_query:
                    result.append({
                        'uuid': str(finding.uuid),
                        'repo_name': finding.repo_name,
                        'commit_sha': finding.commit_sha,
                        'commit_url': finding.commit_url,
                        'branch': finding.branch,
                        'author': finding.author,
                        'commit_date': finding.commit_date.isoformat() if finding.commit_date else None,
                        'commit_message': finding.commit_message,
                        'has_vulnerabilities': finding.has_vulnerabilities,
                        'confidence_score': finding.confidence_score,
                        'summary': finding.summary,
                        'findings_count': finding.findings_count,
                        'created_at': finding.created_at.isoformat() if finding.created_at else None,
                        'expires_at': finding.expires_at.isoformat() if finding.expires_at else None,
                        # Add triage fields
                        'triage_status': finding.triage_status,
                        'assigned_to': finding.assigned_to,
                        'completion_classification': finding.completion_classification,
                        'completed_at': finding.completed_at.isoformat() if finding.completed_at else None,
                        'completed_by': finding.completed_by,
                        'priority': finding.priority,
                        'severity': finding.severity,
                    })
                
                session_db.close()
                findings = result
            
            # Apply repository access filtering based on current user
            if self.is_authenticated():
                user_email = self.get_current_user()['email']
                findings = db_manager.filter_findings_by_user_access(findings, user_email)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error fetching findings: {e}")
            return []
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run the Flask application."""
        logger.info(f"Starting Security Finder web app on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app_instance = SecurityFinderApp()
    return app_instance.app


if __name__ == '__main__':
    app = SecurityFinderApp()
    port = int(os.getenv('WEB_APP_PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(port=port, debug=debug)
